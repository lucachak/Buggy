from __future__ import annotations

import ipaddress
import json
import math
import os
import subprocess
import sys
import urllib.parse
from pathlib import Path

from .approval import verify_approval
from .registry import ValidatorSpec


def _private_target(target: str) -> bool:
    host = urllib.parse.urlparse(target).hostname or ""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def _limits(timeout: float):
    def apply():
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CPU, (math.ceil(timeout) + 1, math.ceil(timeout) + 2))
            resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
            if hasattr(resource, "RLIMIT_NPROC"):
                resource.setrlimit(resource.RLIMIT_NPROC, (16, 16))
        except (ImportError, OSError, ValueError):
            pass
    return apply


def run_python_validator(spec: ValidatorSpec, target: str, output_dir: str,
                         cve_id: str = "") -> dict:
    validation_dir = Path(output_dir) / "validation" / "runs"
    validation_dir.mkdir(parents=True, exist_ok=True)
    run_id = f"{spec.validator_id}.{cve_id.lower()}" if cve_id else spec.validator_id
    request_path = validation_dir / f"{run_id}.request.json"
    result_path = validation_dir / f"{run_id}.result.json"
    request_path.write_text(json.dumps({
        "spec": spec.to_dict(), "target": target, "cve_id": cve_id,
        "output_dir": str(Path(output_dir).resolve()),
    }), encoding="utf-8")
    os.chmod(request_path, 0o600)
    project_root = Path(__file__).resolve().parents[2]
    command = [sys.executable, "-m", "modules.Validation.worker",
               "--request", str(request_path), "--result", str(result_path)]
    completed = subprocess.run(
        command, capture_output=True, text=True, timeout=spec.timeout + 3,
        cwd=project_root, preexec_fn=_limits(spec.timeout) if os.name == "posix" else None,
        env={"PATH": os.environ.get("PATH", ""), "LANG": os.environ.get("LANG", "C.UTF-8"),
             "PYTHONPATH": str(project_root)},
    )
    if result_path.exists():
        return json.loads(result_path.read_text(encoding="utf-8"))
    return {"status": "failed", "validator_id": spec.validator_id,
            "error": completed.stderr[-1000:] or f"worker exited {completed.returncode}"}


def execute_plan(output_dir: str, *, lab_mode: bool = False) -> dict:
    root = Path(output_dir)
    plan = json.loads((root / "validation" / "plan.json").read_text(encoding="utf-8"))
    snapshot = json.loads((root / "validation" / "registry.json").read_text(encoding="utf-8"))
    approval = verify_approval(output_dir, plan)
    approved_ids = set(approval.get("item_ids", [])) if approval else set()
    specs = {item["validator_id"]: ValidatorSpec(
        validator_id=item["validator_id"], name=item["name"], cves=tuple(item["cves"]),
        risk=item["risk"], description=item["description"], executor=item["executor"],
        implementation=item["implementation"], methods=tuple(item["methods"]),
        timeout=item["timeout"], reversible=item["reversible"],
        requires_auth=item["requires_auth"], enabled=item["enabled"], source=item["source"],
    ) for item in snapshot.get("validators", [])}
    results = []
    for item in plan.get("items", []):
        spec = specs.get(item["validator_id"])
        if not spec:
            results.append({"status": "blocked", "item_id": item["item_id"], "reason": "missing spec"})
            continue
        if spec.risk != "safe" and item["item_id"] not in approved_ids:
            results.append({"status": "blocked", "item_id": item["item_id"], "reason": "approval required"})
            continue
        if spec.risk == "lab-exploit" and (not lab_mode or not _private_target(plan["target"])):
            results.append({"status": "blocked", "item_id": item["item_id"], "reason": "private lab target required"})
            continue
        if spec.executor != "python":
            results.append({"status": "delegated", "item_id": item["item_id"], "executor": spec.executor})
            continue
        result = run_python_validator(spec, plan["target"], output_dir, item["cve_id"])
        result["item_id"] = item["item_id"]
        results.append(result)
    execution = {"schema_version": 1, "plan_id": plan["plan_id"], "results": results}
    (root / "validation" / "execution.json").write_text(json.dumps(execution, indent=2), encoding="utf-8")
    return execution
