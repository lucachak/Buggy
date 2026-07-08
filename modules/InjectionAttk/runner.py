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

from . import payloads as P
from modules.utils.http_client import HttpClient
from modules.utils.logger import buggy_logger

TIMEOUT = 12  # segundos por request normal
TIME_THRESHOLD = 3.2  # segundos — threshold para time-based SQLi

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

def _test_sqli_error(client: HttpClient, url: str, param: str, via: str = "GET") -> dict | None:
    for payload in P.SQLI_ERROR[:10]:   # limite de payloads por param
        injected_url = _inject_get_param(url, param, payload)
        resp = client.get(injected_url)
        hit = _contains_any(resp.body, P.SQLI_ERROR_PATTERNS)
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


def _test_sqli_time(client: HttpClient, url: str, param: str) -> dict | None:
    # Baseline
    baseline = client.get(url)

    for payload in P.SQLI_TIME[:6]:
        injected_url  = _inject_get_param(url, param, payload)
        # Using a specialized client config for this if we wanted, but the global handles timeouts
        resp = client.get(injected_url)
        if resp.elapsed >= TIME_THRESHOLD and resp.elapsed >= baseline.elapsed + 2.5:
            return {
                "type":       "sqli_blind",
                "url":        injected_url,
                "parameter":  param,
                "payload":    payload,
                "evidence":   f"Response delayed {resp.elapsed:.1f}s (baseline {baseline.elapsed:.1f}s)",
                "confidence": "medium",
            }
    return None


# ── Command Injection ─────────────────────────────────────────────────────────

def _test_cmdi(client: HttpClient, url: str, param: str) -> dict | None:
    for payload in P.CMD_PAYLOADS[:8]:
        injected_url = _inject_get_param(url, param, payload)
        resp = client.get(injected_url)
        if P.CANARY in resp.body:
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

def _test_ssti(client: HttpClient, url: str, param: str) -> dict | None:
    for payload in P.SSTI_PAYLOADS[:6]:
        injected_url = _inject_get_param(url, param, payload)
        resp = client.get(injected_url)
        hit = _contains_any(resp.body, P.SSTI_MARKERS)
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

def _test_xxe(client: HttpClient, url: str) -> dict | None:
    for xml_payload in P.XXE_PAYLOADS[:3]:
        resp = client.post_xml(url, xml_payload)
        hit = _contains_any(resp.body, P.XXE_MARKERS)
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

def _test_form(client: HttpClient, form: dict) -> list[dict]:
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
            resp = client.post_form(url, data)
        else:
            resp = client.get(_inject_get_param(url, name, payload))

        if _contains_any(resp.body, P.SQLI_ERROR_PATTERNS):
            findings.append({
                "type": "sqli", "url": url, "parameter": name,
                "payload": payload, "evidence": "sql error in response",
                "confidence": "high", "via": method,
            })
            continue   # já confirmado, pula outros payloads

        # SSTI
        for pl in P.SSTI_PAYLOADS[:3]:
            if method == "POST":
                resp = client.post_form(url, {name: pl})
            else:
                resp = client.get(_inject_get_param(url, name, pl))
            hit = _contains_any(resp.body, P.SSTI_MARKERS)
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
        buggy_logger.info(f"\n{'='*60}")
        buggy_logger.info(f"  InjectionScanner — {self.target}")
        buggy_logger.info(f"{'='*60}\n")

        surface = self._load_surface()
        if not surface:
            buggy_logger.warning("  ⚠️  attack_surface.json não encontrado — rode surface primeiro")
            return

        client = HttpClient(timeout=timeout)
        tasks: list[tuple] = []   # (type, *args)

        # Coleta alvos de parâmetros GET
        targets = self._collect_targets(surface)
        buggy_logger.info(f"  [+] {len(targets)} parâmetros GET para testar")

        for url, param in targets:
            tasks.append(("sqli_error", url, param))
            tasks.append(("sqli_time",  url, param))
            tasks.append(("cmdi",       url, param))
            tasks.append(("ssti",       url, param))

        # Forms
        forms = surface.get("injection_targets", {}).get("forms", [])
        buggy_logger.info(f"  [+] {len(forms)} formulários para testar")
        for form in forms[:30]:
            tasks.append(("form", form))

        # APIs — XXE nos endpoints que aceitam XML
        for api in surface.get("api_endpoints", [])[:10]:
            url = api.get("url", "") if isinstance(api, dict) else str(api)
            if url:
                tasks.append(("xxe", url))

        buggy_logger.info(f"  [+] {len(tasks)} tarefas totais\n")

        def _run_task(task: tuple) -> list[dict]:
            kind = task[0]
            try:
                if kind == "sqli_error":
                    r = _test_sqli_error(client, task[1], task[2])
                    return [r] if r else []
                elif kind == "sqli_time":
                    r = _test_sqli_time(client, task[1], task[2])
                    return [r] if r else []
                elif kind == "cmdi":
                    r = _test_cmdi(client, task[1], task[2])
                    return [r] if r else []
                elif kind == "ssti":
                    r = _test_ssti(client, task[1], task[2])
                    return [r] if r else []
                elif kind == "form":
                    return _test_form(client, task[1])
                elif kind == "xxe":
                    r = _test_xxe(client, task[1])
                    return [r] if r else []
            except Exception as e:
                buggy_logger.debug(f"Error in Injection task {kind} for {task[1]}: {e}")
            return []

        with ThreadPoolExecutor(max_workers=min(threads, 30)) as ex:
            futures = [ex.submit(_run_task, t) for t in tasks]
            done = 0
            for fut in as_completed(futures):
                results = fut.result()
                self.findings.extend(results)
                done += 1
                if done % 20 == 0:
                    buggy_logger.info(f"  ... {done}/{len(tasks)} tasks, {len(self.findings)} findings")

        self._save()

        buggy_logger.info(f"\n{'='*60}")
        buggy_logger.info(f"  ✅ Injection scan complete — {len(self.findings)} findings")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = sum(1 for f in self.findings if f.get("cvss_severity") == sev)
            if count:
                buggy_logger.info(f"     {sev}: {count}")
        buggy_logger.info(f"  📁 {self.attack_dir}/findings.json")
        buggy_logger.info(f"{'='*60}")

        return self.findings
