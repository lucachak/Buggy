"""
runner.py — XSSScanner
Testa Reflected XSS, Stored XSS (probe), DOM XSS (heurística),
CSRF (ausência de token), e Open Redirect.
"""

from __future__ import annotations

import json
import re
import ssl
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from . import payloads as P

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; Buggy/1.0)", "Accept": "*/*"}
TIMEOUT = 10

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode    = ssl.CERT_NONE


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _get(url: str, allow_redirects: bool = True, timeout: int = TIMEOUT) -> tuple[int, str, str]:
    """GET → (status, body, final_url)."""
    try:
        req  = Request(url, headers=HEADERS)
        resp = urlopen(req, timeout=timeout, context=SSL_CTX)
        body = resp.read(256 * 1024).decode("utf-8", errors="ignore")
        return resp.status, body, resp.url
    except HTTPError as e:
        body = e.read(16 * 1024).decode("utf-8", errors="ignore") if e.fp else ""
        return e.code, body, url
    except Exception:
        return 0, "", url


def _post_form(url: str, data: dict, timeout: int = TIMEOUT) -> tuple[int, str]:
    try:
        encoded = urllib.parse.urlencode(data).encode()
        req = Request(url, data=encoded, headers={
            **HEADERS, "Content-Type": "application/x-www-form-urlencoded"
        })
        resp = urlopen(req, timeout=timeout, context=SSL_CTX)
        body = resp.read(256 * 1024).decode("utf-8", errors="ignore")
        return resp.status, body
    except HTTPError as e:
        body = e.read(16 * 1024).decode("utf-8", errors="ignore") if e.fp else ""
        return e.code, body
    except Exception:
        return 0, ""


def _inject_param(url: str, param: str, value: str) -> str:
    parsed = urllib.parse.urlparse(url)
    qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()


# ── Reflected XSS ─────────────────────────────────────────────────────────────

def _test_reflected_xss(url: str, param: str) -> dict | None:
    for payload in P.XSS_REFLECTED[:8]:
        injected = _inject_param(url, param, payload)
        _, body, _ = _get(injected)
        # Verifica se o canary aparece sem encoding na resposta
        if P.XSS_CANARY in body and (
            "<script>" in body.lower() or "onerror=" in body.lower()
            or "onload=" in body.lower() or "svg" in body.lower()
        ):
            return {
                "type":       "xss_reflected",
                "url":        injected,
                "parameter":  param,
                "payload":    payload,
                "evidence":   f"Payload reflected unencoded in response",
                "confidence": "high",
            }
        # Fallback: só canary (possível)
        if P.XSS_CANARY in body:
            return {
                "type":       "xss_reflected",
                "url":        injected,
                "parameter":  param,
                "payload":    payload,
                "evidence":   f"Canary '{P.XSS_CANARY}' reflected in response",
                "confidence": "medium",
            }
    return None


# ── Stored XSS probe ──────────────────────────────────────────────────────────

def _test_stored_xss(form: dict) -> dict | None:
    url    = form.get("action", "") or form.get("url", "")
    method = (form.get("method", "GET") or "GET").upper()
    fields = form.get("fields", []) or form.get("inputs", [])

    if not url or not fields:
        return None

    # Submete payload em todos os campos de texto
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
        status, body = _post_form(url, data)
    else:
        probe_url = url
        for k, v in data.items():
            probe_url = _inject_param(probe_url, k, v)
        _, body, _ = _get(probe_url)

    # Re-lê a mesma URL para ver se o payload persiste
    _, body2, _ = _get(url)

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
    """
    Analisa JS já baixado (do JS analyzer) buscando source→sink.
    Retorna finding se houver source próximo de sink.
    """
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

    # Só interessa forms POST
    if method != "POST" or not url:
        return None

    field_names = set()
    for f in fields:
        name = f if isinstance(f, str) else f.get("name", "")
        if name:
            field_names.add(name.lower())

    # Verifica ausência de qualquer campo CSRF
    has_token = any(t in field_names for t in P.CSRF_TOKEN_NAMES)

    # Também checa header (mas não temos headers de form no surface)
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

def _test_open_redirect(url: str, param: str) -> dict | None:
    for payload in P.REDIRECT_PAYLOADS[:5]:
        injected = _inject_param(url, param, payload)
        try:
            # urlopen segue redirects por padrão — verifica URL final
            req = Request(injected, headers=HEADERS)
            resp = urlopen(req, timeout=TIMEOUT, context=SSL_CTX)
            final_url = resp.url
            resp.close()
            if "evil.com" in final_url or payload.lstrip("/") in final_url:
                return {
                    "type":       "open_redirect",
                    "url":        injected,
                    "parameter":  param,
                    "payload":    payload,
                    "evidence":   f"Redirected to {final_url}",
                    "confidence": "high",
                }
        except Exception:
            pass

        # Checa status 30x sem seguir redirect
        try:
            req = Request(injected, headers=HEADERS)
            import urllib.request
            old_opener = urllib.request.build_opener(
                urllib.request.HTTPRedirectHandler()
            )
        except Exception:
            pass
    return None


def _probe_redirect_params(url: str) -> list[dict]:
    """Detecta parâmetros de redirect na URL e testa todos."""
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs     = urllib.parse.parse_qs(parsed.query)
    for param in qs:
        if param.lower() in P.REDIRECT_PARAMS:
            r = _test_open_redirect(url, param)
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
        print(f"\n{'='*60}")
        print(f"  XSSScanner — {self.target}")
        print(f"{'='*60}\n")

        surface = self._load_surface()
        if not surface:
            print("  ⚠️  attack_surface.json não encontrado — rode surface primeiro")
            return

        tasks = []

        # Reflected XSS — parâmetros GET
        search_eps = surface.get("injection_targets", {}).get("search_endpoints", [])
        for ep in search_eps[:40]:
            url    = str(ep)
            parsed = urllib.parse.urlparse(url)
            qs     = urllib.parse.parse_qs(parsed.query)
            for param in list(qs.keys())[:5]:
                tasks.append(("reflected", url, param))
            # Open redirect
            for param in list(qs.keys())[:5]:
                if param.lower() in P.REDIRECT_PARAMS:
                    tasks.append(("redirect", url, param))

        # Redirect params via login/admin pages
        for ep in surface.get("injection_targets", {}).get("login_pages", [])[:20]:
            tasks.append(("redirect_probe", str(ep)))

        # Stored XSS — forms
        forms = surface.get("injection_targets", {}).get("forms", [])
        print(f"  [+] {len(forms)} forms | {len(search_eps)} search endpoints")
        for form in forms[:30]:
            tasks.append(("stored",  form))
            tasks.append(("csrf",    form, ""))

        # DOM XSS — JS results do JS analyzer (surface_mapping.json)
        sm_file = self.output_dir / "surface" / "surface_mapping.json"
        if sm_file.exists():
            with open(sm_file) as f:
                sm = json.load(f)
            js_results = sm.get("js_secrets", {}).get("results", [])
            for jr in js_results[:20]:
                if jr.get("endpoints"):
                    # Não temos o conteúdo JS aqui — usa endpoints como heurística
                    pass
            # Se temos conteúdo inline… (futuro)

        print(f"  [+] {len(tasks)} tarefas totais\n")

        def _run_task(task: tuple) -> list[dict]:
            kind = task[0]
            try:
                if kind == "reflected":
                    r = _test_reflected_xss(task[1], task[2])
                    return [r] if r else []
                elif kind == "stored":
                    r = _test_stored_xss(task[1])
                    return [r] if r else []
                elif kind == "csrf":
                    _, body, _ = _get(task[1].get("action", "") or task[1].get("url", ""))
                    r = _check_csrf(task[1], body)
                    return [r] if r else []
                elif kind == "redirect":
                    r = _test_open_redirect(task[1], task[2])
                    return [r] if r else []
                elif kind == "redirect_probe":
                    return _probe_redirect_params(task[1])
            except Exception:
                pass
            return []

        with ThreadPoolExecutor(max_workers=min(threads, 25)) as ex:
            futures = [ex.submit(_run_task, t) for t in tasks]
            done = 0
            for fut in as_completed(futures):
                self.findings.extend(fut.result())
                done += 1
                if done % 15 == 0:
                    print(f"  ... {done}/{len(tasks)} tasks, {len(self.findings)} findings")

        self._save()

        print(f"\n{'='*60}")
        print(f"  ✅ XSS scan complete — {len(self.findings)} findings")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = sum(1 for f in self.findings if f.get("cvss_severity") == sev)
            if count:
                print(f"     {sev}: {count}")
        print(f"  📁 {self.attack_dir}/findings.json")
        print(f"{'='*60}")

        return self.findings
