import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from modules.Validation.nuclei import NucleiAdapter
from modules.utils.http_client import configure_http


@pytest.fixture(autouse=True)
def scope():
    configure_http("https://example.com")


def make_manifest(tmp_path, content, **overrides):
    root = tmp_path / "templates"
    root.mkdir()
    template = root / "check.yaml"
    template.write_text(content)
    item = {
        "template_id": "fixture-cve", "path": "check.yaml",
        "sha256": hashlib.sha256(template.read_bytes()).hexdigest(),
        "cves": ["CVE-2099-0001"], "risk": "safe",
        "signed_required": True,
    }
    item.update(overrides)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"templates": [item]}))
    return root, manifest


def test_trusted_signed_template_and_safe_command(tmp_path):
    root, manifest = make_manifest(tmp_path, "id: fixture\nhttp:\n  - method: GET\n# digest: abc\n")
    with patch("modules.Validation.nuclei.shutil.which", return_value="/usr/bin/nuclei"):
        adapter = NucleiAdapter("https://example.com", str(tmp_path), str(root), str(manifest))
    templates = adapter.load_templates()
    command = adapter.build_command(templates, tmp_path / "out.jsonl")
    assert command[0] == "/usr/bin/nuclei"
    assert "-dut" in command and "-ept" in command and "-dr" in command
    assert "-code" not in command and "-headless" not in command


@pytest.mark.parametrize("body", [
    "id: bad\ncode:\n  - engine: bash\n# digest: abc\n",
    "id: bad\nheadless:\n  - steps: []\n# digest: abc\n",
])
def test_forbidden_protocol_is_rejected(tmp_path, body):
    root, manifest = make_manifest(tmp_path, body)
    adapter = NucleiAdapter("https://example.com", str(tmp_path), str(root), str(manifest))
    with pytest.raises(ValueError, match="unsafe protocol"):
        adapter.load_templates()


def test_checksum_and_signature_are_enforced(tmp_path):
    root, manifest = make_manifest(tmp_path, "id: unsigned\nhttp: []\n")
    adapter = NucleiAdapter("https://example.com", str(tmp_path), str(root), str(manifest))
    with pytest.raises(ValueError, match="signed template"):
        adapter.load_templates()
    data = json.loads(manifest.read_text())
    data["templates"][0]["sha256"] = "0" * 64
    manifest.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="checksum"):
        adapter.load_templates()


def test_jsonl_import_drops_out_of_scope_findings(tmp_path):
    adapter = NucleiAdapter("https://example.com", str(tmp_path), "", "")
    path = tmp_path / "results.jsonl"
    path.write_text("\n".join([
        json.dumps({"template-id": "ok", "matched-at": "https://example.com/a", "info": {}}),
        json.dumps({"template-id": "bad", "matched-at": "https://evil.example/a", "info": {}}),
    ]))
    findings = adapter._import_jsonl(path)
    assert [finding["template_id"] for finding in findings] == ["ok"]


def test_missing_manifest_is_safe_skip(tmp_path):
    adapter = NucleiAdapter("https://example.com", str(tmp_path), "", "")
    result = adapter.exec()
    assert result["status"] == "skipped"
    assert result["findings"] == []
