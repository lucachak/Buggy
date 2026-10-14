"""Deterministic, network-free onboarding data for the local Web UI."""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path

from modules.Validation.planner import save_registry_and_plan


DEMO_TARGET = "http://buggy-demo.invalid"


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def create_demo_output(output_root: Path) -> Path:
    """Create realistic scan artifacts without starting a process or making requests."""
    created_at = time.time()
    root = output_root / f"ui_demo_{int(created_at * 1000)}_{uuid.uuid4().hex[:8]}"
    root.mkdir(parents=True, exist_ok=False)

    _write_json(root / "demo.json", {
        "schema_version": 1,
        "is_demo": True,
        "title": "Primeiro scan guiado",
        "description": "Dados locais de exemplo; nenhuma requisição de rede foi enviada.",
        "created_at": created_at,
    })
    _write_json(root / "surface" / "summary.json", {
        "schema_version": 1,
        "target": DEMO_TARGET,
        "summary": {
            "technologies": {
                "software": [
                    {"product": "apache", "version": "2.4.49", "source": "server-header"},
                    {"product": "tomcat", "version": "7.0.79", "source": "server-header"},
                ],
                "frameworks": ["Java"],
            },
            "attack_surface": {"total_endpoints": 6, "total_forms": 1, "total_apis": 2},
            "risk_indicators": {"waf_present": False, "exposed_admin": True},
        },
    })
    _write_json(root / "intelligence" / "cves.json", {
        "schema_version": 1,
        "target": DEMO_TARGET,
        "summary": {"total": 2, "critical": 1, "high": 1, "kev": 1},
        "cves": [
            {
                "cve_id": "CVE-2021-41773", "priority": "CRITICAL", "priority_score": 92,
                "cvss_score": 9.8, "epss": 0.94, "kev": True,
                "component": {"product": "apache", "version": "2.4.49"},
                "applicability": "possible",
            },
            {
                "cve_id": "CVE-2017-12615", "priority": "HIGH", "priority_score": 76,
                "cvss_score": 8.1, "epss": 0.71, "kev": False,
                "component": {"product": "tomcat", "version": "7.0.79"},
                "applicability": "possible",
            },
        ],
    })
    plan = save_registry_and_plan(str(root), DEMO_TARGET)
    results = []
    summaries = {
        "CVE-2021-41773": "A versão Apache exposta coincide; confirmação exigiria teste adicional autorizado.",
        "CVE-2017-12615": "A versão Tomcat e suporte a PUT foram simulados; nenhum upload foi realizado.",
    }
    for item in plan["items"]:
        results.append({
            "status": "completed",
            "item_id": item["item_id"],
            "validator_id": item["validator_id"],
            "result": {
                "cve_id": item["cve_id"], "applicability": "possible", "confirmed": False,
                "summary": summaries[item["cve_id"]],
                "safety": "Demonstração local: nenhum payload ou request foi enviado.",
            },
        })
    _write_json(root / "validation" / "execution.json", {
        "schema_version": 1, "plan_id": plan["plan_id"], "results": results,
    })
    (root / "webui-process.log").write_text(
        "[demo] Inventário carregado\n"
        "[demo] 2 CVEs correlacionadas\n"
        "[demo] 2 validators safe planejados\n"
        "[demo] Resultados sintéticos concluídos sem acesso à rede\n",
        encoding="utf-8",
    )
    return root
