"""
runner.py — AuthScanner
Testa cookies inseguros, falta de rate limit em logins e IDOR simples 
em parâmetros extraídos.
"""

from __future__ import annotations

import json
import ssl
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from . import payloads as P
from modules.utils.http_client import HttpClient
from modules.utils.logger import buggy_logger

def _test_idor(client: HttpClient, url: str, param: str, orig_val: str) -> dict | None:
    # Baseline
    baseline = client.get(url)
    
    # Inject
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [P.IDOR_TEST_VALUE]
    injected_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
    
    test = client.get(injected_url)
    
    if test.status == 200 and baseline.status == 200:
        if abs(len(test.body) - len(baseline.body)) > 100:
            return {
                "type": "potential_idor",
                "url": injected_url,
                "parameter": param,
                "payload": P.IDOR_TEST_VALUE,
                "evidence": f"Status 200. Response length changed from {len(baseline.body)} to {len(test.body)}",
                "confidence": "low",
            }
    return None


def _check_cookies_and_ratelimit(client: HttpClient, url: str, is_login: bool = False) -> list[dict]:
    findings = []
    resp = client.get(url)
    
    if resp.status == 0:
        return findings

    set_cookie = resp.headers.get("set-cookie", "").lower()
    if set_cookie:
        if "httponly" not in set_cookie:
            findings.append({
                "type": "insecure_cookie",
                "url": url,
                "parameter": "headers",
                "payload": "N/A",
                "evidence": "Set-Cookie header missing HttpOnly flag",
                "confidence": "medium",
            })
        if url.startswith("https") and "secure" not in set_cookie:
            findings.append({
                "type": "insecure_cookie",
                "url": url,
                "parameter": "headers",
                "payload": "N/A",
                "evidence": "Set-Cookie header missing Secure flag over HTTPS",
                "confidence": "medium",
            })

    # Check rate limit on login
    if is_login:
        has_rl = any(rl in headers for rl in P.RATE_LIMIT_HEADERS)
        if not has_rl:
            findings.append({
                "type": "missing_rate_limit",
                "url": url,
                "parameter": "headers",
                "payload": "N/A",
                "evidence": f"Login page missing rate limit headers: {P.RATE_LIMIT_HEADERS}",
                "confidence": "low",
            })
            
    return findings


class AuthScanner:
    def __init__(self, target: str, output_dir: str):
        self.target     = target
        self.output_dir = Path(output_dir)
        self.attack_dir = self.output_dir / "attacks" / "auth"
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
            surface.setdefault("auth_findings", []).extend(self.findings)
            with open(surface_file, "w") as f:
                json.dump(surface, f, indent=2)

    def exec(self, threads: int = 20, timeout: float = 10.0):
        buggy_logger.info(f"\n{'='*60}")
        buggy_logger.info(f"  AuthScanner — {self.target}")
        buggy_logger.info(f"{'='*60}\n")

        surface = self._load_surface()
        if not surface:
            buggy_logger.warning("attack_surface.json não encontrado — rode surface primeiro")
            return

        client = HttpClient(timeout=timeout)
        tasks = []
        
        # IDOR (busca params como id, user_id, etc em search_endpoints)
        search_endpoints = surface.get("injection_targets", {}).get("search_endpoints", [])
        for ep in search_endpoints[:30]:
            url = str(ep)
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            for param, vals in qs.items():
                if param.lower() in P.IDOR_PARAMS and vals:
                    tasks.append(("idor", url, param, vals[0]))

        # Configurações de cookies e rate limit
        # Testa em todos os login pages
        login_pages = surface.get("injection_targets", {}).get("login_pages", [])
        for ep in login_pages[:10]:
            tasks.append(("cookies", str(ep), True))

        # Testa cookies em alguns endpoints aleatórios também
        for ep in surface.get("api_endpoints", [])[:5]:
            url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
            if url:
                tasks.append(("cookies", url, False))

        buggy_logger.info(f"  [+] {len(tasks)} tarefas totais\n")

        def _run_task(task: tuple) -> list[dict]:
            kind = task[0]
            try:
                if kind == "idor":
                    r = _test_idor(client, task[1], task[2], task[3])
                    return [r] if r else []
                elif kind == "cookies":
                    return _check_cookies_and_ratelimit(client, task[1], task[2])
            except Exception as e:
                buggy_logger.debug(f"Error in Auth task {kind} for {task[1]}: {e}")
            return []

        with ThreadPoolExecutor(max_workers=min(threads, 20)) as ex:
            futures = [ex.submit(_run_task, t) for t in tasks]
            done = 0
            for fut in as_completed(futures):
                self.findings.extend(fut.result())
                done += 1
                if done % 10 == 0:
                    buggy_logger.info(f"  ... {done}/{len(tasks)} tasks, {len(self.findings)} findings")

        self._save()

        buggy_logger.info(f"\n{'='*60}")
        buggy_logger.info(f"  ✅ Auth scan complete — {len(self.findings)} findings")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = sum(1 for f in self.findings if f.get("cvss_severity") == sev)
            if count:
                buggy_logger.info(f"     {sev}: {count}")
        buggy_logger.info(f"  📁 {self.attack_dir}/findings.json")
        buggy_logger.info(f"{'='*60}")

        return self.findings
