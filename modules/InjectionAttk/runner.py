"""
runner.py — InjectionScanner
Testa SQLi (error + time-based), Command Injection, SSTI e XXE
em formulários, endpoints e APIs extraídos do attack_surface.json.
"""

from __future__ import annotations

import json
import os
import ssl
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from . import payloads as P

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; Buggy/1.0)",
    "Accept": "*/*",
}
JSON_HEADERS = {**HEADERS, "Content-Type": "application/json"}
XML_HEADERS  = {**HEADERS, "Content-Type": "application/xml"}

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode    = ssl.CERT_NONE

TIMEOUT = 12  # segundos por request normal
TIME_THRESHOLD = 3.2  # segundos — threshold para time-based SQLi


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _get(url: str, timeout: int = TIMEOUT) -> tuple[int, str, float]:
    """GET → (status, body, elapsed_s)."""
    t0 = time.time()
    try:
        req = Request(url, headers=HEADERS)
        resp = urlopen(req, timeout=timeout, context=SSL_CTX)
        body = resp.read(512 * 1024).decode("utf-8", errors="ignore")
        return resp.status, body, time.time() - t0
    except HTTPError as e:
        body = e.read(32 * 1024).decode("utf-8", errors="ignore") if e.fp else ""
        return e.code, body, time.time() - t0
    except Exception:
        return 0, "", time.time() - t0


def _post_form(url: str, data: dict, timeout: int = TIMEOUT) -> tuple[int, str, float]:
    """POST form-urlencoded → (status, body, elapsed_s)."""
    t0 = time.time()
    try:
        encoded = urllib.parse.urlencode(data).encode()
        req = Request(url, data=encoded, headers={
            **HEADERS, "Content-Type": "application/x-www-form-urlencoded"
        })
        resp = urlopen(req, timeout=timeout, context=SSL_CTX)
        body = resp.read(512 * 1024).decode("utf-8", errors="ignore")
        return resp.status, body, time.time() - t0
    except HTTPError as e:
        body = e.read(32 * 1024).decode("utf-8", errors="ignore") if e.fp else ""
        return e.code, body, time.time() - t0
    except Exception:
        return 0, "", time.time() - t0


def _post_xml(url: str, xml: str, timeout: int = TIMEOUT) -> tuple[int, str, float]:
    t0 = time.time()
    try:
        req = Request(url, data=xml.encode(), headers=XML_HEADERS)
        resp = urlopen(req, timeout=timeout, context=SSL_CTX)
        body = resp.read(512 * 1024).decode("utf-8", errors="ignore")
        return resp.status, body, time.time() - t0
    except HTTPError as e:
        body = e.read(32 * 1024).decode("utf-8", errors="ignore") if e.fp else ""
        return e.code, body, time.time() - t0
    except Exception:
        return 0, "", time.time() - t0


def _inject_get_param(url: str, param: str, value: str) -> str:
    """Substitui ou adiciona `param=value` na query string."""
    parsed = urllib.parse.urlparse(url)
    qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_qs = urllib.parse.urlencode(qs, doseq=True)
    return parsed._replace(query=new_qs).geturl()


def _contains_any(text: str, markers: list[str]) -> str | None:
    tl = text.lower()
    for m in markers:
        if m.lower() in tl:
            return m
    return None


# ── SQLi ──────────────────────────────────────────────────────────────────────

def _test_sqli_error(url: str, param: str, via: str = "GET") -> dict | None:
    for payload in P.SQLI_ERROR[:10]:   # limite de payloads por param
        injected_url = _inject_get_param(url, param, payload)
        _, body, _   = _get(injected_url, timeout=TIMEOUT)
        hit = _contains_any(body, P.SQLI_ERROR_PATTERNS)
        if hit:
            return {
                "type":       "sqli",
                "url":        injected_url,
                "parameter":  param,
                "payload":    payload,
                "evidence":   hit,
                "confidence": "high",
                "via":        via,
            }
    return None


def _test_sqli_time(url: str, param: str) -> dict | None:
    # Baseline
    _, _, baseline = _get(url, timeout=TIMEOUT)

    for payload in P.SQLI_TIME[:6]:
        injected_url  = _inject_get_param(url, param, payload)
        _, _, elapsed = _get(injected_url, timeout=20)
        if elapsed >= TIME_THRESHOLD and elapsed >= baseline + 2.5:
            return {
                "type":       "sqli_blind",
                "url":        injected_url,
                "parameter":  param,
                "payload":    payload,
                "evidence":   f"Response delayed {elapsed:.1f}s (baseline {baseline:.1f}s)",
                "confidence": "medium",
            }
    return None


# ── Command Injection ─────────────────────────────────────────────────────────

def _test_cmdi(url: str, param: str) -> dict | None:
    for payload in P.CMD_PAYLOADS[:8]:
        injected_url = _inject_get_param(url, param, payload)
        _, body, _   = _get(injected_url, timeout=TIMEOUT)
        if P.CANARY in body:
            return {
                "type":       "command_injection",
                "url":        injected_url,
                "parameter":  param,
                "payload":    payload,
                "evidence":   P.CANARY,
                "confidence": "high",
            }
    return None


# ── SSTI ──────────────────────────────────────────────────────────────────────

def _test_ssti(url: str, param: str) -> dict | None:
    for payload in P.SSTI_PAYLOADS[:6]:
        injected_url = _inject_get_param(url, param, payload)
        _, body, _   = _get(injected_url, timeout=TIMEOUT)
        hit = _contains_any(body, P.SSTI_MARKERS)
        if hit:
            return {
                "type":       "ssti",
                "url":        injected_url,
                "parameter":  param,
                "payload":    payload,
                "evidence":   hit,
                "confidence": "high",
            }
    return None


# ── XXE ───────────────────────────────────────────────────────────────────────

def _test_xxe(url: str) -> dict | None:
    for xml_payload in P.XXE_PAYLOADS[:3]:
        _, body, _ = _post_xml(url, xml_payload, timeout=TIMEOUT)
        hit = _contains_any(body, P.XXE_MARKERS)
        if hit:
            return {
                "type":       "xxe",
                "url":        url,
                "parameter":  "xml_body",
                "payload":    xml_payload[:200],
                "evidence":   hit,
                "confidence": "high",
            }
    return None


# ── Form-based injection ──────────────────────────────────────────────────────

def _test_form(form: dict) -> list[dict]:
    """Testa SQLi + SSTI em todos os campos de um form."""
    url    = form.get("action", "") or form.get("url", "")
    method = (form.get("method", "GET") or "GET").upper()
    fields = form.get("fields", []) or form.get("inputs", [])
    findings = []

    if not url:
        return findings

    for field in fields:
        name = field if isinstance(field, str) else field.get("name", "")
        if not name:
            continue

        # SQLi error
        payload = "'"
        data    = {name: payload}
        if method == "POST":
            _, body, _ = _post_form(url, data)
        else:
            _, body, _ = _get(_inject_get_param(url, name, payload))

        if _contains_any(body, P.SQLI_ERROR_PATTERNS):
            findings.append({
                "type": "sqli", "url": url, "parameter": name,
                "payload": payload, "evidence": "sql error in response",
                "confidence": "high", "via": method,
            })
            continue   # já confirmado, pula outros payloads

        # SSTI
        for pl in P.SSTI_PAYLOADS[:3]:
            if method == "POST":
                _, body, _ = _post_form(url, {name: pl})
            else:
                _, body, _ = _get(_inject_get_param(url, name, pl))
            hit = _contains_any(body, P.SSTI_MARKERS)
            if hit:
                findings.append({
                    "type": "ssti", "url": url, "parameter": name,
                    "payload": pl, "evidence": hit,
                    "confidence": "high", "via": method,
                })
                break

    return findings


# ── Scanner principal ─────────────────────────────────────────────────────────

class InjectionScanner:
    def __init__(self, target: str, output_dir: str):
        self.target     = target
        self.output_dir = Path(output_dir)
        self.attack_dir = self.output_dir / "attacks" / "injection"
        self.attack_dir.mkdir(parents=True, exist_ok=True)
        self.findings: list[dict] = []

    def _load_surface(self) -> dict:
        p = self.output_dir / "surface" / "attack_surface.json"
        if p.exists():
            with open(p) as f:
                return json.load(f)
        return {}

    def _save(self):
        from modules.Report import score_bulk
        if self.findings:
            self.findings = score_bulk(self.findings)
        out = self.attack_dir / "findings.json"
        with open(out, "w") as f:
            json.dump(self.findings, f, indent=2)
        # Append findings into attack_surface.json
        surface_file = self.output_dir / "surface" / "attack_surface.json"
        if surface_file.exists():
            with open(surface_file) as f:
                surface = json.load(f)
            surface.setdefault("injection_findings", []).extend(self.findings)
            with open(surface_file, "w") as f:
                json.dump(surface, f, indent=2)

    def _collect_targets(self, surface: dict) -> list[tuple[str, str]]:
        """Retorna lista de (url, param) para testar."""
        targets: list[tuple[str, str]] = []

        # Endpoints com parâmetros GET
        for ep in surface.get("injection_targets", {}).get("search_endpoints", []):
            url = str(ep)
            parsed = urllib.parse.urlparse(url)
            qs     = urllib.parse.parse_qs(parsed.query)
            for param in qs:
                targets.append((url, param))

        # Admin / login pages — testa parâmetros comuns
        for ep in surface.get("injection_targets", {}).get("login_pages", []):
            url = str(ep)
            for param in ["user", "username", "email", "id", "q", "search", "name"]:
                targets.append((url, param))

        return targets[:60]   # cap de segurança

    def exec(self, threads: int = 20, timeout: float = 10.0):
        print(f"\n{'='*60}")
        print(f"  InjectionScanner — {self.target}")
        print(f"{'='*60}\n")

        surface = self._load_surface()
        if not surface:
            print("  ⚠️  attack_surface.json não encontrado — rode surface primeiro")
            return

        tasks: list[tuple] = []   # (type, *args)

        # Coleta alvos de parâmetros GET
        targets = self._collect_targets(surface)
        print(f"  [+] {len(targets)} parâmetros GET para testar")

        for url, param in targets:
            tasks.append(("sqli_error", url, param))
            tasks.append(("sqli_time",  url, param))
            tasks.append(("cmdi",       url, param))
            tasks.append(("ssti",       url, param))

        # Forms
        forms = surface.get("injection_targets", {}).get("forms", [])
        print(f"  [+] {len(forms)} formulários para testar")
        for form in forms[:30]:
            tasks.append(("form", form))

        # APIs — XXE nos endpoints que aceitam XML
        for api in surface.get("api_endpoints", [])[:10]:
            url = api.get("url", "") if isinstance(api, dict) else str(api)
            if url:
                tasks.append(("xxe", url))

        print(f"  [+] {len(tasks)} tarefas totais\n")

        def _run_task(task: tuple) -> list[dict]:
            kind = task[0]
            try:
                if kind == "sqli_error":
                    r = _test_sqli_error(task[1], task[2])
                    return [r] if r else []
                elif kind == "sqli_time":
                    r = _test_sqli_time(task[1], task[2])
                    return [r] if r else []
                elif kind == "cmdi":
                    r = _test_cmdi(task[1], task[2])
                    return [r] if r else []
                elif kind == "ssti":
                    r = _test_ssti(task[1], task[2])
                    return [r] if r else []
                elif kind == "form":
                    return _test_form(task[1])
                elif kind == "xxe":
                    r = _test_xxe(task[1])
                    return [r] if r else []
            except Exception:
                pass
            return []

        with ThreadPoolExecutor(max_workers=min(threads, 30)) as ex:
            futures = [ex.submit(_run_task, t) for t in tasks]
            done = 0
            for fut in as_completed(futures):
                results = fut.result()
                self.findings.extend(results)
                done += 1
                if done % 20 == 0:
                    print(f"  ... {done}/{len(tasks)} tasks, {len(self.findings)} findings")

        self._save()

        print(f"\n{'='*60}")
        print(f"  ✅ Injection scan complete — {len(self.findings)} findings")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = sum(1 for f in self.findings if f.get("cvss_severity") == sev)
            if count:
                print(f"     {sev}: {count}")
        print(f"  📁 {self.attack_dir}/findings.json")
        print(f"{'='*60}")

        return self.findings
