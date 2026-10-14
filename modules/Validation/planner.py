from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from .registry import ValidatorRegistry, builtin_registry


def build_plan(target: str, intelligence: dict, registry: ValidatorRegistry) -> dict:
    registry_snapshot = registry.snapshot()
    items = []
    for candidate in intelligence.get("cves", []):
        cve_id = candidate.get("cve_id", "")
        for spec in registry.for_cve(cve_id):
            items.append({
                "item_id": f"{spec.validator_id}:{cve_id}",
                "validator_id": spec.validator_id,
                "cve_id": cve_id,
                "risk": spec.risk,
                "executor": spec.executor,
                "target": target,
                "status": "proposed",
                "approved": spec.risk == "safe",
                "priority": candidate.get("priority", "LOW"),
            })
    seed = json.dumps({"target": target, "registry": registry_snapshot["digest"],
                       "items": items}, sort_keys=True, separators=(",", ":"))
    return {
        "schema_version": 1,
        "plan_id": hashlib.sha256(seed.encode()).hexdigest()[:24],
        "created_at": time.time(),
        "target": target,
        "registry_digest": registry_snapshot["digest"],
        "items": items,
        "summary": {
            "total": len(items),
            "auto_approved_safe": sum(item["approved"] for item in items),
            "requires_approval": sum(not item["approved"] for item in items),
        },
    }


def save_registry_and_plan(output_dir: str, target: str,
                           registry: ValidatorRegistry | None = None) -> dict:
    registry = registry or builtin_registry()
    root = Path(output_dir)
    intelligence_path = root / "intelligence" / "cves.json"
    intelligence = json.loads(intelligence_path.read_text()) if intelligence_path.exists() else {"cves": []}
    validation_dir = root / "validation"
    validation_dir.mkdir(parents=True, exist_ok=True)
    plan = build_plan(target, intelligence, registry)
    (validation_dir / "registry.json").write_text(
        json.dumps(registry.snapshot(), indent=2), encoding="utf-8"
    )
    (validation_dir / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    return plan
