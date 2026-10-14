"""Translate scanner log markers into a stable UI step timeline."""
from __future__ import annotations


STEP_DEFINITIONS = {
    "recon": [
        ("[1/4]", "Subdomínios"),
        ("[2/4]", "DNS e resolução"),
        ("[3/4]", "Origem e CDN"),
        ("[4/4]", "Diretórios e rotas"),
    ],
    "surface": [
        ("[1/6]", "Tecnologias"),
        ("[2/6]", "Endpoints"),
        ("[3/6]", "JavaScript"),
        ("[4/6]", "Formulários"),
        ("[5/6]", "APIs"),
        ("[6/6]", "Portas e serviços"),
    ],
    "all": [
        ("PHASE 1/9", "Reconhecimento"),
        ("PHASE 2/9", "Superfície"),
        ("PHASE 3/9", "CVEs e validação"),
        ("PHASE 4/9", "Infraestrutura"),
        ("PHASE 5/9", "Autenticação"),
        ("PHASE 6/9", "Lógica de negócio"),
        ("PHASE 7/9", "Injeções"),
        ("PHASE 8/9", "XSS e cliente"),
        ("PHASE 9/9", "SSRF e servidor"),
    ],
}

MODULE_LABELS = {
    "cve": "Inteligência de CVEs", "plan": "Plano de validação",
    "infra": "Infraestrutura", "auth": "Autenticação e autorização",
    "business": "Lógica de negócio", "injection": "Injeções",
    "xss": "XSS e cliente", "ssrf": "SSRF e servidor", "demo": "Demonstração",
}


def scan_progress(module: str, log: str, status: str) -> dict:
    definitions = STEP_DEFINITIONS.get(
        module, [("", MODULE_LABELS.get(module, module.title() or "Scan"))]
    )
    seen = [bool(marker and marker in log) for marker, _ in definitions]
    current = max((index for index, value in enumerate(seen) if value), default=0)
    terminal = status in {"completed", "failed", "cancelled"}
    steps = []
    for index, (_, label) in enumerate(definitions):
        if status == "completed":
            state = "completed"
        elif index < current:
            state = "completed"
        elif index == current:
            state = status if terminal else "running"
        else:
            state = "pending"
        steps.append({"number": index + 1, "label": label, "state": state})
    completed = sum(step["state"] == "completed" for step in steps)
    percent = 100 if status == "completed" else round(completed / len(steps) * 100)
    return {"steps": steps, "percent": percent, "current": current + 1, "total": len(steps)}
