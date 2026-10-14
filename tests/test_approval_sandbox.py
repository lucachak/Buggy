import json
import os
import time

from modules.Validation.approval import approve_plan, verify_approval
from modules.Validation.planner import save_registry_and_plan
from modules.Validation.registry import ValidatorRegistry, ValidatorSpec
from modules.Validation.sandbox import execute_plan


def prepare(tmp_path, risk="standard", target="https://example.com"):
    intel = tmp_path / "intelligence"
    intel.mkdir()
    (intel / "cves.json").write_text(json.dumps({
        "cves": [{"cve_id": "CVE-2099-0001", "priority": "HIGH"}]
    }))
    registry = ValidatorRegistry()
    registry.register(ValidatorSpec(
        f"fixture.{risk}", "Fixture", ("CVE-2099-0001",), risk, "fixture",
        implementation="modules.Validators.fixture.validate",
    ))
    plan = save_registry_and_plan(str(tmp_path), target, registry)
    return plan


def test_approval_is_bound_to_plan_and_detects_tampering(tmp_path):
    plan = prepare(tmp_path)
    item = plan["items"][0]["item_id"]
    approval = approve_plan(str(tmp_path), [item], "tester", ttl=600)
    assert verify_approval(str(tmp_path), plan)["approved_by"] == "tester"
    approval["item_ids"] = ["tampered"]
    (tmp_path / "validation" / "approval.json").write_text(json.dumps(approval))
    assert verify_approval(str(tmp_path), plan) is None


def test_approval_files_are_owner_only(tmp_path):
    plan = prepare(tmp_path)
    approve_plan(str(tmp_path), [plan["items"][0]["item_id"]], "tester")
    assert os.stat(tmp_path / "validation" / ".approval-key").st_mode & 0o777 == 0o600
    assert os.stat(tmp_path / "validation" / "approval.json").st_mode & 0o777 == 0o600


def test_standard_validator_is_blocked_without_approval(tmp_path):
    prepare(tmp_path)
    execution = execute_plan(str(tmp_path))
    assert execution["results"][0]["status"] == "blocked"
    assert execution["results"][0]["reason"] == "approval required"


def test_lab_exploit_requires_private_target_even_when_approved(tmp_path):
    plan = prepare(tmp_path, risk="lab-exploit")
    approve_plan(str(tmp_path), [plan["items"][0]["item_id"]], "tester")
    execution = execute_plan(str(tmp_path), lab_mode=True)
    assert execution["results"][0]["reason"] == "private lab target required"


def test_empty_plan_executes_safely(tmp_path):
    validation = tmp_path / "validation"
    validation.mkdir()
    plan = {"plan_id": "empty", "registry_digest": "digest", "target": "http://localhost", "items": []}
    (validation / "plan.json").write_text(json.dumps(plan))
    (validation / "registry.json").write_text(json.dumps({"validators": []}))
    assert execute_plan(str(tmp_path))["results"] == []
