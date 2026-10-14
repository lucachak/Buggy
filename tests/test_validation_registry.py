import json

import pytest

from modules.Validation.planner import build_plan, save_registry_and_plan
from modules.Validation.registry import ValidatorRegistry, ValidatorSpec, builtin_registry


def spec(risk="safe"):
    return ValidatorSpec(
        validator_id=f"fixture.{risk}", name="Fixture", cves=("CVE-2099-0001",),
        risk=risk, description="test", implementation="modules.Validators.fixture.validate",
        methods=("GET",),
    )


def test_registry_rejects_duplicates_and_untrusted_imports():
    registry = ValidatorRegistry()
    registry.register(spec())
    with pytest.raises(ValueError, match="duplicate"):
        registry.register(spec())
    with pytest.raises(ValueError, match="modules.Validators"):
        ValidatorSpec(
            "bad.validator", "Bad", ("CVE-2099-0001",), "safe", "bad",
            implementation="os.system",
        ).validate()


def test_registry_snapshot_is_deterministic():
    first, second = ValidatorRegistry(), ValidatorRegistry()
    first.register(spec())
    second.register(spec())
    assert first.snapshot()["digest"] == second.snapshot()["digest"]


def test_plan_only_auto_approves_safe_validators():
    registry = ValidatorRegistry()
    registry.register(spec("safe"))
    registry.register(spec("intrusive"))
    intelligence = {"cves": [{"cve_id": "CVE-2099-0001", "priority": "CRITICAL"}]}
    plan = build_plan("https://example.com", intelligence, registry)
    assert plan["summary"] == {
        "total": 2, "auto_approved_safe": 1, "requires_approval": 1,
    }
    assert {item["approved"] for item in plan["items"]} == {True, False}


def test_plan_persistence_integrates_intelligence(tmp_path):
    intel = tmp_path / "intelligence"
    intel.mkdir()
    (intel / "cves.json").write_text(json.dumps({
        "cves": [{"cve_id": "CVE-2099-0001", "priority": "HIGH"}]
    }))
    registry = ValidatorRegistry()
    registry.register(spec())
    plan = save_registry_and_plan(str(tmp_path), "https://example.com", registry)
    assert plan["summary"]["total"] == 1
    assert (tmp_path / "validation" / "registry.json").exists()
    assert (tmp_path / "validation" / "plan.json").exists()


def test_builtin_registry_connects_selected_cves_to_safe_validators():
    registry = builtin_registry()
    apache = registry.for_cve("CVE-2021-41773")[0]
    tomcat = registry.for_cve("CVE-2017-12615")[0]
    assert apache.risk == tomcat.risk == "safe"
    assert apache.methods == ("GET",)
    assert tomcat.methods == ("GET", "OPTIONS")
