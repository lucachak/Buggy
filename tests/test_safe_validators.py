from types import SimpleNamespace

from modules.Validation.registry import builtin_registry
from modules.Validation.planner import save_registry_and_plan
from modules.Validation.sandbox import execute_plan, run_python_validator
from modules.Validators import apache, tomcat


def response(status=200, server="", allow=""):
    headers = {"server": server}
    if allow:
        headers["allow"] = allow
    return SimpleNamespace(status=status, headers=headers)


def context(cve_id):
    return {"cve_id": cve_id, "target": "https://example.test/app", "timeout": 2}


def test_apache_validator_reports_possible_without_exploit(monkeypatch):
    class Client:
        def __init__(self, **kwargs): pass
        def get(self, url, allow_redirects=False):
            assert url == "https://example.test/"
            return response(server="Apache/2.4.49 (Unix)")

    monkeypatch.setattr(apache, "HttpClient", Client)
    value = apache.validate_path_traversal(context("CVE-2021-41773"))
    assert value["applicability"] == "possible"
    assert value["confirmed"] is False
    assert "payload" in value["safety"]


def test_apache_validator_rejects_non_matching_exposed_version(monkeypatch):
    class Client:
        def __init__(self, **kwargs): pass
        def get(self, *args, **kwargs): return response(server="Apache/2.4.58")

    monkeypatch.setattr(apache, "HttpClient", Client)
    value = apache.validate_path_traversal(context("CVE-2021-42013"))
    assert value["applicability"] == "not_vulnerable"


def test_tomcat_validator_uses_get_and_options_only(monkeypatch):
    calls = []

    class Client:
        def __init__(self, **kwargs): pass
        def get(self, *args, **kwargs):
            calls.append("GET")
            return response(server="Apache-Coyote/1.1 Tomcat/7.0.79")
        def options(self, *args, **kwargs):
            calls.append("OPTIONS")
            return response(server="Apache-Coyote/1.1 Tomcat/7.0.79", allow="GET, HEAD, PUT")

    monkeypatch.setattr(tomcat, "HttpClient", Client)
    value = tomcat.validate_put(context("CVE-2017-12615"))
    assert calls == ["GET", "OPTIONS"]
    assert value["applicability"] == "possible"
    assert value["confirmed"] is False


def test_validator_runs_in_worker_and_keeps_cve_specific_artifacts(tmp_path):
    spec = builtin_registry().for_cve("CVE-2021-41773")[0]
    value = run_python_validator(spec, "http://localhost:9", str(tmp_path), "CVE-2021-41773")
    assert value["status"] == "completed"
    assert value["result"]["applicability"] == "inconclusive"
    runs = tmp_path / "validation" / "runs"
    assert (runs / "apache.path-traversal-applicability.cve-2021-41773.request.json").exists()
    assert (runs / "apache.path-traversal-applicability.cve-2021-41773.result.json").exists()


def test_intelligence_to_plan_to_automatic_safe_execution(tmp_path):
    intelligence = tmp_path / "intelligence"
    intelligence.mkdir()
    (intelligence / "cves.json").write_text(
        '{"cves":[{"cve_id":"CVE-2021-41773","priority":"HIGH"}]}',
        encoding="utf-8",
    )
    plan = save_registry_and_plan(str(tmp_path), "http://localhost:9")
    assert plan["summary"] == {
        "total": 1, "auto_approved_safe": 1, "requires_approval": 0,
    }
    execution = execute_plan(str(tmp_path))
    assert execution["results"][0]["status"] == "completed"
    assert execution["results"][0]["result"]["confirmed"] is False
