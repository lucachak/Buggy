"""
runner.py — BusinessLogicScanner
Testa falhas de lógica de negócios usando heurísticas: 
- HTTP Parameter Pollution (HPP)
- Mass Assignment em forms e APIs
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

def _test_hpp_get(client: HttpClient, url: str, param: str) -> dict | None:
    # URL injetando o mesmo parâmetro duas vezes
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    
    # Substitui/Adiciona pra forçar duas ocorrencias
    qs[param] = [P.HPP_TEST_VALUE_1, P.HPP_TEST_VALUE_2]
    
    injected_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
    
    resp = client.get(injected_url)
    
    if resp.status == 200:
        # Verifica se ambos refletiram, ou como o servidor tratou
        if P.HPP_TEST_VALUE_1 in resp.body and P.HPP_TEST_VALUE_2 in resp.body:
            evidence = f"Both values reflected (array/concatenation behavior)"
        elif P.HPP_TEST_VALUE_1 in resp.body:
            evidence = f"First value took precedence"
        elif P.HPP_TEST_VALUE_2 in resp.body:
            evidence = f"Second value took precedence"
        else:
            evidence = None
            
        if evidence:
            return {
                "type": "http_parameter_pollution",
                "url": injected_url,
                "parameter": param,
                "payload": f"?{param}={P.HPP_TEST_VALUE_1}&{param}={P.HPP_TEST_VALUE_2}",
                "evidence": evidence,
                "confidence": "low", # Precisa de review manual para ver se quebra lógica
            }
    return None


def _test_mass_assignment(client: HttpClient, form: dict) -> list[dict]:
    findings = []
    url = form.get("action", "") or form.get("url", "")
    method = (form.get("method", "GET") or "GET").upper()
    fields = form.get("fields", []) or form.get("inputs", [])
    
    if not url or method != "POST":
        return findings
        
    field_names = [f if isinstance(f, str) else f.get("name", "") for f in fields]
    field_names = [f for f in field_names if f]
    
    # Se já tiver admin, ignora
    if any("admin" in f.lower() for f in field_names):
        return findings

    # Constrói o corpo original falso com values 'buggy_test'
    data = {f: "buggy_test" for f in field_names}
    
    # Envia sem mass assignment (form and json)
    base_resp_form = client.post_form(url, data)
    base_resp_json = client.post_json(url, data)
    
    # Testa cada parâmetro de mass assignment
    for m_param in P.MASS_ASSIGNMENT_PARAMS:
        for m_val in P.MASS_ASSIGNMENT_VALUES:
            test_data = data.copy()
            test_data[m_param] = m_val
            
            # Test Form-urlencoded
            resp_form = client.post_form(url, test_data)
            if resp_form.status == 200 and base_resp_form.status == 200:
                if abs(len(resp_form.body) - len(base_resp_form.body)) > 150:
                    findings.append({
                        "type": "potential_mass_assignment",
                        "url": url,
                        "parameter": m_param,
                        "payload": m_val,
                        "evidence": f"Response length changed significantly when injecting {m_param}={m_val} (Form URL-Encoded)",
                        "confidence": "low",
                    })
                    break
                    
            # Test JSON (API)
            resp_json = client.post_json(url, test_data)
            if resp_json.status == 200 and base_resp_json.status == 200:
                if abs(len(resp_json.body) - len(base_resp_json.body)) > 150:
                    findings.append({
                        "type": "potential_mass_assignment_api",
                        "url": url,
                        "parameter": m_param,
                        "payload": m_val,
                        "evidence": f"Response length changed significantly when injecting {m_param}={m_val} (JSON)",
                        "confidence": "low",
                    })
                    break
    
    return findings


class BusinessLogicScanner:
    def __init__(self, target: str, output_dir: str):
        self.target     = target
        self.output_dir = Path(output_dir)
        self.attack_dir = self.output_dir / "attacks" / "business"
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
            surface.setdefault("business_findings", []).extend(self.findings)
            with open(surface_file, "w") as f:
                json.dump(surface, f, indent=2)

    def exec(self, threads: int = 20, timeout: float = 10.0):
        buggy_logger.info(f"\n{'='*60}")
        buggy_logger.info(f"  BusinessLogicScanner — {self.target}")
        buggy_logger.info(f"{'='*60}\n")

        surface = self._load_surface()
        if not surface:
            buggy_logger.warning("attack_surface.json não encontrado — rode surface primeiro")
            return

        client = HttpClient(timeout=timeout)
        tasks = []
        
        # HPP: Busca parâmetros GET extraídos do search_endpoints
        search_endpoints = surface.get("injection_targets", {}).get("search_endpoints", [])
        for ep in search_endpoints[:30]:
            url = str(ep)
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            for param in qs.keys():
                tasks.append(("hpp", url, param))

        # Mass Assignment: Busca formulários
        forms = surface.get("injection_targets", {}).get("forms", [])
        for form in forms[:20]:
            tasks.append(("mass", form))

        buggy_logger.info(f"  [+] {len(tasks)} tarefas totais\n")

        def _run_task(task: tuple) -> list[dict]:
            kind = task[0]
            try:
                if kind == "hpp":
                    r = _test_hpp_get(client, task[1], task[2])
                    return [r] if r else []
                elif kind == "mass":
                    return _test_mass_assignment(client, task[1])
            except Exception as e:
                buggy_logger.debug(f"Error in Business task {kind} for {task[1]}: {e}")
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
        buggy_logger.info(f"  ✅ Business Logic scan complete — {len(self.findings)} findings")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = sum(1 for f in self.findings if f.get("cvss_severity") == sev)
            if count:
                buggy_logger.info(f"     {sev}: {count}")
        buggy_logger.info(f"  📁 {self.attack_dir}/findings.json")
        buggy_logger.info(f"{'='*60}")

        return self.findings
