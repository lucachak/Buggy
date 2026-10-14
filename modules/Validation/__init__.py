from .planner import build_plan, save_registry_and_plan
from .registry import ValidatorRegistry, ValidatorSpec, builtin_registry
from .nuclei import NucleiAdapter
from .approval import approve_plan, verify_approval
from .sandbox import execute_plan


def run_validation_plan(target: str, args, output_dir: str):
    plan = save_registry_and_plan(output_dir, target)
    print(f"\n  Validation plan: {plan['summary']['total']} validators")
    print(f"  Output: {output_dir}/validation/plan.json")
    return plan


def run_nuclei_adapter(target: str, args, output_dir: str):
    template_root = getattr(args, "nuclei_templates", "")
    manifest = getattr(args, "nuclei_manifest", "")
    adapter = NucleiAdapter(
        target, output_dir, template_root, manifest,
        rate=getattr(args, "rate", 10), threads=getattr(args, "threads", 10),
        timeout=getattr(args, "timeout", 10),
    )
    result = adapter.exec()
    print(f"\n  Nuclei: {result['status']} — {len(result['findings'])} findings")
    if result.get("reason"):
        print(f"  Reason: {result['reason']}")
    return result


def run_approval(target: str, args, output_dir: str):
    record = approve_plan(
        output_dir, getattr(args, "approve_item", []),
        getattr(args, "approved_by", ""), getattr(args, "approval_ttl", 3600),
    )
    print(f"\n  Approved {len(record['item_ids'])} item(s) until {record['expires_at']}")
    return record


def run_execution(target: str, args, output_dir: str):
    execution = execute_plan(output_dir, lab_mode=getattr(args, "lab_mode", False))
    print(f"\n  Validation execution: {len(execution['results'])} result(s)")
    return execution


__all__ = [
    "ValidatorRegistry", "ValidatorSpec", "builtin_registry",
    "build_plan", "save_registry_and_plan", "run_validation_plan",
    "NucleiAdapter", "run_nuclei_adapter",
    "approve_plan", "verify_approval", "execute_plan", "run_approval", "run_execution",
]
