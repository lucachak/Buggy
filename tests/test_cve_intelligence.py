import json
from pathlib import Path

from modules.CVEIntelligence.models import CVECandidate, SoftwareComponent
from modules.CVEIntelligence.prioritizer import prioritize
from modules.CVEIntelligence.providers import JsonCache
from modules.CVEIntelligence.runner import CVEIntelligence, _component_from_text


class FakeProvider:
    def cves_for_cpe(self, cpe):
        assert "nginx:1.24.0" in cpe
        return [{
            "cve_id": "CVE-2099-0001", "description": "fixture",
            "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L",
            "references": ["https://vendor.example/advisory"],
        }]

    def kev_catalog(self):
        return {"CVE-2099-0001": {
            "dueDate": "2099-02-01", "knownRansomwareCampaignUse": "Known",
        }}

    def epss_scores(self, cve_ids):
        return {"CVE-2099-0001": {"epss": "0.91", "percentile": "0.99"}}


def test_component_normalization_generates_versioned_cpe():
    component = _component_from_text("nginx/1.24.0")
    assert component.vendor == "f5"
    assert component.version == "1.24.0"
    assert component.cpe.startswith("cpe:2.3:a:f5:nginx:1.24.0:")


def test_prioritizer_is_transparent_and_bounded():
    candidate = CVECandidate(
        "CVE-2099-0001", SoftwareComponent("v", "p", "1"),
        cvss_score=9.8, epss=0.91, kev=True,
    )
    prioritize(candidate, exposure=1.0)
    assert candidate.priority == "CRITICAL"
    assert candidate.priority_score <= 100
    assert "CISA KEV" in candidate.reasons


def test_cache_roundtrip_and_stale_offline(tmp_path):
    cache = JsonCache(tmp_path, ttl=-1)
    cache.put("nvd", "key", {"ok": True})
    assert cache.get("nvd", "key") is None
    assert cache.get("nvd", "key", allow_stale=True) == {"ok": True}


def test_cve_pipeline_integrates_surface_inventory(tmp_path):
    surface = tmp_path / "surface"
    surface.mkdir()
    (surface / "summary.json").write_text(json.dumps({
        "technologies": {"software": ["nginx/1.24.0"]}
    }))
    result = CVEIntelligence(
        "https://example.com", str(tmp_path), provider=FakeProvider()
    ).exec()
    assert result["summary"] == {
        "components": 1, "versioned_components": 1,
        "cves": 1, "kev": 1, "critical": 1,
    }
    assert result["cves"][0]["cve_id"] == "CVE-2099-0001"
    assert (tmp_path / "intelligence" / "cves.json").exists()


def test_offline_empty_inventory_is_valid(tmp_path):
    result = CVEIntelligence(
        "http://localhost", str(tmp_path), provider=FakeProvider()
    ).exec()
    assert result["summary"]["cves"] == 0
