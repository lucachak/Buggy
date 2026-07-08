"""
runner.py — XSSScanner
Testa Reflected XSS, Stored XSS (probe), DOM XSS (heurística),
CSRF (ausência de token), e Open Redirect.
"""

from __future__ import annotations

import json
import ssl
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode

from . import payloads as P
from modules.utils.http_client import HttpClient
from modules.utils.logger import buggy_logger

# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _inject_get_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_qs = urlencode(qs, doseq=True)
    return parsed._replace(query=new_qs).geturl()


# ── Reflected XSS ─────────────────────────────────────────────────────────────

def _test_xss_get(client: HttpClient, url: str, param: str) -> dict | None:
    for payload in P.XSS_REFLECTED[:8]:
        injected_url = _inject_get_param(url, param, payload)
        resp = client.get(injected_url)
        
        # Verifica se o canary aparece sem encoding na resposta
        if P.XSS_CANARY in resp.body and (
            "<script>" in resp.body.lower() or "onerror=" in resp.body.lower()
            or "onload=" in resp.body.lower() or "svg" in resp.body.lower()
        ):
            return {
                "type":       "xss_reflected",
                "url":        injected_url,
                "parameter":  param,
                "payload":    payload,
                "evidence":   f"Payload reflected unencoded in response",
                "confidence": "high",
            }
        # Fallback: só canary (possível)
        if P.XSS_CANARY in resp.body:
            return {
                "type":       "xss_reflected",
                "url":        injected_url,
                "parameter":  param,
                "payload":    payload,
                "evidence":   f"Canary '{P.XSS_CANARY}' reflected in response",
                "confidence": "medium",
            }
    return None


# ── Stored XSS probe ──────────────────────────────────────────────────────────

def _test_stored_xss(client: HttpClient, form: dict) -> dict | None:
    url    = form.get("action", "") or form.get("url", "")
    method = (form.get("method", "GET") or "GET").upper()
    fields = form.get("fields", []) or form.get("inputs", [])

    if not url or not fields:
        return None

    data = {}
    for f in fields:
        name = f if isinstance(f, str) else f.get("name", "")
        ftype = "" if isinstance(f, str) else f.get("type", "text")
        if name and ftype not in ("hidden", "submit", "button", "file"):
            data[name] = P.XSS_STORED_PROBE[0]
        elif name:
            data[name] = "buggy_test"

    if not data:
        return None

    if method == "POST":
        resp = client.post(url, data=data)
        body = resp.body
    else:
        probe_url = url
        for k, v in data.items():
            probe_url = _inject_get_param(probe_url, k, v)
        resp = client.get(probe_url)
        body = resp.body

    # Re-lê a mesma URL para ver se o payload persiste
    resp2 = client.get(url)
    body2 = resp2.body

    for probe_url_str in [body, body2]:
        if P.XSS_CANARY in probe_url_str:
            return {
                "type":       "xss_stored",
                "url":        url,
                "parameter":  list(data.keys())[0],
                "payload":    P.XSS_STORED_PROBE[0],
                "evidence":   f"Payload persisted on re-read of {url}",
                "confidence": "high",
            }
    return None


# ── DOM XSS heuristic ─────────────────────────────────────────────────────────

def _check_dom_xss(url: str, js_content: str) -> dict | None:
    found_sources = [s for s in P.DOM_SOURCES if s in js_content]
    found_sinks   = [s for s in P.DOM_SINKS   if s in js_content]

    if found_sources and found_sinks:
        return {
            "type":       "xss_dom",
            "url":        url,
            "parameter":  "dom",
            "payload":    "N/A (static analysis)",
            "evidence":   f"Sources: {found_sources[:3]} → Sinks: {found_sinks[:3]}",
            "confidence": "low",
        }
    return None


# ── CSRF ──────────────────────────────────────────────────────────────────────

def _check_csrf(form: dict, page_body: str) -> dict | None:
    url    = form.get("action", "") or form.get("url", "")
    method = (form.get("method", "GET") or "GET").upper()
    fields = form.get("fields", []) or form.get("inputs", [])

    if method != "POST" or not url:
        return None

    field_names = set()
    for f in fields:
        name = f if isinstance(f, str) else f.get("name", "")
        if name:
            field_names.add(name.lower())

    has_token = any(t in field_names for t in P.CSRF_TOKEN_NAMES)

    if has_token:
        return None

    return {
        "type":       "csrf",
        "url":        url,
        "parameter":  "form",
        "payload":    "N/A (missing CSRF token)",
        "evidence":   f"POST form has no CSRF token field. Fields: {list(field_names)[:5]}",
        "confidence": "medium",
    }


# ── Open Redirect ─────────────────────────────────────────────────────────────

def _test_open_redirect(client: HttpClient, url: str, param: str) -> dict | None:
    for payload in P.REDIRECT_PAYLOADS[:5]:
        injected = _inject_get_param(url, param, payload)
        try:
            resp = client.get(injected)
            if "evil.com" in resp.url or payload.lstrip("/") in resp.url:
                return {
                    "type":       "open_redirect",
                    "url":        injected,
                    "parameter":  param,
                    "payload":    payload,
                    "evidence":   f"Redirected to {resp.url}",
                    "confidence": "high",
                }
        except Exception:
            pass
    return None


def _probe_redirect_params(client: HttpClient, url: str) -> list[dict]:
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs     = urllib.parse.parse_qs(parsed.query)
    for param in qs:
        if param.lower() in P.REDIRECT_PARAMS:
            r = _test_open_redirect(client, url, param)
            if r:
                findings.append(r)
    return findings


# ── Scanner principal ─────────────────────────────────────────────────────────

class XSSScanner:
    def __init__(self, target: str, output_dir: str):
        self.target     = target
        self.output_dir = Path(output_dir)
        self.attack_dir = self.output_dir / "attacks" / "xss"
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
        surface_file = self.output_dir / "surface" / "attack_surface.json"
        if surface_file.exists():
            with open(surface_file) as f:
                surface = json.load(f)
            surface.setdefault("xss_findings", []).extend(self.findings)
            with open(surface_file, "w") as f:
                json.dump(surface, f, indent=2)

    def exec(self, threads: int = 20, timeout: float = 10.0):
        buggy_logger.info(f"\n{'='*60}")
        buggy_logger.info(f"  XSSScanner — {self.target}")
        buggy_logger.info(f"{'='*60}\n")

        surface = self._load_surface()
        if not surface:
            buggy_logger.warning("attack_surface.json não encontrado — rode surface primeiro")
            return

        client = HttpClient(timeout=timeout)
        tasks = []

        search_eps = surface.get("injection_targets", {}).get("search_endpoints", [])
        for ep in search_eps[:40]:
            url    = str(ep)
            parsed = urllib.parse.urlparse(url)
            qs     = urllib.parse.parse_qs(parsed.query)
            for param in list(qs.keys())[:5]:
                tasks.append(("reflected", url, param))
            for param in list(qs.keys())[:5]:
                if param.lower() in P.REDIRECT_PARAMS:
                    tasks.append(("redirect", url, param))

        for ep in surface.get("injection_targets", {}).get("login_pages", [])[:20]:
            tasks.append(("redirect_probe", str(ep)))

        forms = surface.get("injection_targets", {}).get("forms", [])
        buggy_logger.info(f"  [+] {len(forms)} forms | {len(search_eps)} search endpoints")
        for form in forms[:30]:
            tasks.append(("stored",  form))
            tasks.append(("csrf",    form, ""))

        buggy_logger.info(f"  [+] {len(tasks)} tarefas totais\n")

        def _run_task(task: tuple) -> list[dict]:
            kind = task[0]
            try:
                if kind == "reflected":
                    r = _test_xss_get(client, task[1], task[2])
                    return [r] if r else []
                elif kind == "stored":
                    r = _test_stored_xss(client, task[1])
                    return [r] if r else []
                elif kind == "csrf":
                    resp = client.get(task[1].get("action", "") or task[1].get("url", ""))
                    r = _check_csrf(task[1], resp.body)
                    return [r] if r else []
                elif kind == "redirect":
                    r = _test_open_redirect(client, task[1], task[2])
                    return [r] if r else []
                elif kind == "redirect_probe":
                    return _probe_redirect_params(client, task[1])
            except Exception as e:
                buggy_logger.debug(f"Error in XSS task {kind}: {e}")
            return []

        with ThreadPoolExecutor(max_workers=min(threads, 25)) as ex:
            futures = [ex.submit(_run_task, t) for t in tasks]
            done = 0
            for fut in as_completed(futures):
                self.findings.extend(fut.result())
                done += 1
                if done % 10 == 0:
                    buggy_logger.info(f"  ... {done}/{len(tasks)} tasks, {len(self.findings)} findings")

        self._save()

        buggy_logger.info(f"\n{'='*60}")
        buggy_logger.info(f"  ✅ XSS scan complete — {len(self.findings)} findings")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = sum(1 for f in self.findings if f.get("cvss_severity") == sev)
            if count:
                buggy_logger.info(f"     {sev}: {count}")
        buggy_logger.info(f"  📁 {self.attack_dir}/findings.json")
        buggy_logger.info(f"{'='*60}")

        return self.findings
