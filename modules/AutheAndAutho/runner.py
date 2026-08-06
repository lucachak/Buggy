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

def _test_idor(client: HttpClient, url: str, param: str, orig_val: str) -> list[dict]:
    findings = []
    # Baseline
    baseline = client.get(url)
    if baseline.status != 200:
        return findings
    
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    
    # 1. Standard Replacement
    qs_standard = qs.copy()
    qs_standard[param] = [P.IDOR_TEST_VALUE]
    url_standard = parsed._replace(query=urllib.parse.urlencode(qs_standard, doseq=True)).geturl()
    test_standard = client.get(url_standard)
    
    if test_standard.status == 200 and abs(len(test_standard.body) - len(baseline.body)) > 100:
        findings.append({
            "type": "potential_idor",
            "url": url_standard,
            "parameter": param,
            "payload": P.IDOR_TEST_VALUE,
            "evidence": f"Status 200. Response length changed from {len(baseline.body)} to {len(test_standard.body)}",
            "confidence": "low",
        })
        
    # 2. Array Bypass (HPP)
    qs_array = qs.copy()
    qs_array[param] = [orig_val, P.IDOR_ARRAY_BYPASS_VALUE]
    url_array = parsed._replace(query=urllib.parse.urlencode(qs_array, doseq=True)).geturl()
    test_array = client.get(url_array)
    
    if test_array.status == 200 and abs(len(test_array.body) - len(baseline.body)) > 100:
        findings.append({
            "type": "potential_idor_array_bypass",
            "url": url_array,
            "parameter": param,
            "payload": f"{orig_val}&{param}={P.IDOR_ARRAY_BYPASS_VALUE}",
            "evidence": f"Status 200. Response length changed from {len(baseline.body)} to {len(test_array.body)} via HPP",
            "confidence": "low",
        })
        
    return findings


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
        has_rl = any(rl in resp.headers for rl in P.RATE_LIMIT_HEADERS)
        if not has_rl:
            findings.append({
                "type": "missing_rate_limit",
                "url": url,
                "parameter": "headers",
                "payload": "N/A",
                "evidence": f"Login page missing rate limit headers: {P.RATE_LIMIT_HEADERS}",
                "confidence": "low",
            })
            
    # Check for JWT exposure in headers or cookies and inspect for sensitive info
    import base64
    def _inspect_jwt(token: str, source: str):
        if token.startswith("eyJ") and token.count(".") == 2:
            try:
                payload = token.split(".")[1]
                # Pad payload for base64 decoding
                payload += "=" * ((4 - len(payload) % 4) % 4)
                decoded = base64.b64decode(payload).decode("utf-8")
                
                # Check for sensitive claims
                sensitive_claims = ["admin", "role", "email", "password", "secret", "uid"]
                exposed = [c for c in sensitive_claims if f'"{c}"' in decoded.lower()]
                if exposed:
                    findings.append({
                        "type": "jwt_sensitive_data_exposure",
                        "url": url,
                        "parameter": source,
                        "payload": "N/A",
                        "evidence": f"JWT payload exposes sensitive claims: {exposed}",
                        "confidence": "medium",
                    })
            except Exception:
                pass

    _inspect_jwt(set_cookie, "Set-Cookie")
    for k, v in resp.headers.items():
        if "authorization" in k.lower():
            _inspect_jwt(v, "Authorization Header")

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
                    return _test_idor(client, task[1], task[2], task[3])
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

        # ── SSO Brute Scan ────────────────────────────────────────────────
        try:
            from .sso_scanner import SSOScanner
            buggy_logger.info(f"\n  [+] Running SSO brute scanner...")
            sso = SSOScanner(target=self.target, client=client)
            sso_findings = sso.exec(threads=min(threads, 10))
            self.findings.extend(sso_findings)
        except Exception as e:
            buggy_logger.warning(f"SSO scan error: {e}")
        # ──────────────────────────────────────────────────────────────────

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

