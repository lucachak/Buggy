"""
runner.py — InfraScanner
Testa configurações CORS, headers de segurança e exposição de arquivos em endpoints
extraídos do attack_surface.json.
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

def _test_cors(client: HttpClient, url: str) -> dict | None:
    # Origem maliciosa
    malicious_origin = "https://evil-cors.com"
    resp = client.get(url, extra_headers={"Origin": malicious_origin})
    
    if not resp.is_success and resp.status == 0:
        return None # Connection error, skip evaluation
        
    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get("access-control-allow-credentials", "")
    
    if acao == "*" or malicious_origin in acao:
        confidence = "high" if acac.lower() == "true" else "medium"
        evidence = f"ACAO: {acao}" + (f" | ACAC: {acac}" if acac else "")
        return {
            "type": "cors_misconfig",
            "url": url,
            "parameter": "headers",
            "payload": malicious_origin,
            "evidence": evidence,
            "confidence": confidence,
        }
    return None


def _check_security_headers(url: str, headers: dict) -> list[dict]:
    findings = []
    # Só testar HTTPS para certas configs, mas assumimos URL como base
    is_https = url.startswith("https")
    
    if is_https and "strict-transport-security" not in headers:
        findings.append({
            "type": "missing_hsts",
            "url": url,
            "parameter": "headers",
            "payload": "N/A",
            "evidence": "Strict-Transport-Security header is missing",
            "confidence": "high",
        })
        
    if "x-frame-options" not in headers and "content-security-policy" not in headers:
        findings.append({
            "type": "missing_clickjacking_protection",
            "url": url,
            "parameter": "headers",
            "payload": "N/A",
            "evidence": "X-Frame-Options and CSP frame-ancestors are missing",
            "confidence": "medium",
        })
        
    return findings


def _test_sensitive_files(client: HttpClient, base_url: str) -> list[dict]:
    findings = []
    base = base_url.rstrip("/")
    
    for path in P.SENSITIVE_FILES:
        target_url = base + path
        resp = client.get(target_url)
        if resp.status == 200 and len(resp.body) > 0 and "404" not in resp.body and "Not Found" not in resp.body:
            findings.append({
                "type": "exposed_sensitive_file",
                "url": target_url,
                "parameter": "path",
                "payload": path,
                "evidence": f"File returned HTTP 200 with {len(resp.body)} bytes",
                "confidence": "medium",
            })
    return findings


class InfraScanner:
    def __init__(self, target: str, output_dir: str):
        self.target     = target
        self.output_dir = Path(output_dir)
        self.attack_dir = self.output_dir / "attacks" / "infra"
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
            surface.setdefault("infra_findings", []).extend(self.findings)
            with open(surface_file, "w") as f:
                json.dump(surface, f, indent=2)

    def exec(self, threads: int = 20, timeout: float = 10.0):
        buggy_logger.info(f"\n{'='*60}")
        buggy_logger.info(f"  InfraScanner — {self.target}")
        buggy_logger.info(f"{'='*60}\n")

        surface = self._load_surface()
        if not surface:
            buggy_logger.warning("attack_surface.json não encontrado — rode surface primeiro")
            return

        client = HttpClient(timeout=timeout)
        tasks = []
        
        # Coleta bases para testar sensitive files e security headers
        endpoints = []
        if (self.output_dir / "surface" / "surface_mapping.json").exists():
            with open(self.output_dir / "surface" / "surface_mapping.json") as f:
                sm = json.load(f)
                endpoints = sm.get("endpoints", {}).get("endpoints", [])
        
        # Pega bases únicas (hostnames com schema)
        bases = set()
        for ep in endpoints:
            parsed = urllib.parse.urlparse(ep)
            base = f"{parsed.scheme}://{parsed.netloc}"
            if base:
                bases.add(base)
                
        # Se não tiver, adiciona o target
        if not bases:
            bases.add(f"http://{self.target}")
            bases.add(f"https://{self.target}")
            
        buggy_logger.info(f"  [+] {len(bases)} hosts identificados para infra scan")
        
        for base in list(bases)[:10]:
            tasks.append(("headers", base))
            tasks.append(("sensitive", base))
            
        # APIs e endpoints normais para CORS
        for ep in surface.get("api_endpoints", [])[:10]:
            url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
            if url:
                tasks.append(("cors", url))

        buggy_logger.info(f"  [+] {len(tasks)} tarefas totais\n")

        def _run_task(task: tuple) -> list[dict]:
            kind = task[0]
            try:
                if kind == "headers":
                    resp = client.get(task[1])
                    if resp.status != 0:
                        return _check_security_headers(task[1], resp.headers)
                elif kind == "sensitive":
                    return _test_sensitive_files(client, task[1])
                elif kind == "cors":
                    r = _test_cors(client, task[1])
                    return [r] if r else []
            except Exception as e:
                buggy_logger.debug(f"Error in Infra task {kind} for {task[1]}: {e}")
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
        buggy_logger.info(f"  ✅ Infra scan complete — {len(self.findings)} findings")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = sum(1 for f in self.findings if f.get("cvss_severity") == sev)
            if count:
                buggy_logger.info(f"     {sev}: {count}")
        buggy_logger.info(f"  📁 {self.attack_dir}/findings.json")
        buggy_logger.info(f"{'='*60}")

        return self.findings
