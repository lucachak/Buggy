import json

from modules.Report.report import _all_scored_findings, _list_items, _table, generate


def test_report_escapes_scan_controlled_html():
    payload = '<img src=x onerror="alert(1)">'
    rendered = _table([payload], [[payload]]) + _list_items([payload])
    assert payload not in rendered
    assert "&lt;img" in rendered


def test_report_includes_safe_validator_result(tmp_path):
    validation = tmp_path / "validation"
    validation.mkdir()
    (validation / "execution.json").write_text(json.dumps({"results": [{
        "status": "completed", "validator_id": "apache.path-traversal-applicability",
        "result": {"cve_id": "CVE-2021-41773", "applicability": "possible",
                   "confirmed": False, "summary": "Version match only"},
    }]}), encoding="utf-8")
    report = generate(str(tmp_path))
    rendered = open(report, encoding="utf-8").read()
    assert "CVE Validation" in rendered
    assert "CVE-2021-41773" in rendered
    assert "possible" in rendered


def test_report_merges_module_findings_and_reports_inconclusive_coverage(tmp_path):
    surface = tmp_path / "surface"
    surface.mkdir()
    finding = {
        "type": "missing_security_header", "url": "http://lab.test",
        "cvss_score": 4.3, "cvss_severity": "MEDIUM", "cvss_desc": "CSP missing",
    }
    (surface / "attack_surface.json").write_text(json.dumps({
        "infra_findings": [finding],
        "injection_targets": {"forms": [], "login_pages": [], "search_endpoints": []},
        "api_endpoints": [],
    }), encoding="utf-8")
    (surface / "surface_mapping.json").write_text(json.dumps({
        "summary": {"attack_surface": {"total_endpoints": 1, "total_forms": 0,
                                         "total_apis": 0, "js_secrets_found": 0},
                    "technologies": {}, "risk_indicators": {}, "high_value_targets": {}},
        "js_secrets": {"summary": {"total_files": 0}},
        "endpoints": {"interesting": [{"severity": "high", "type": "robots_disallow",
                                           "url": "http://lab.test/ftp",
                                           "description": "Hidden path"}]},
    }), encoding="utf-8")

    assert _all_scored_findings({"infra_findings": [finding]}) == [finding]
    rendered = open(generate(str(tmp_path)), encoding="utf-8").read()
    assert "missing_security_header" in rendered
    assert "Observações de superfície" in rendered
    assert "http://lab.test/ftp" in rendered
    assert "Resultado inconclusivo" in rendered
    assert "módulos dinâmicos não receberam alvos suficientes" in rendered
