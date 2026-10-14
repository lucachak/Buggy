from __future__ import annotations

import ipaddress
import json
import re
import time
import urllib.parse
from pathlib import Path

from .models import CVECandidate, SoftwareComponent
from .prioritizer import prioritize
from .providers import IntelligenceProvider


CPE_PRODUCTS = {
    "nginx": ("f5", "nginx"), "apache": ("apache", "http_server"),
    "tomcat": ("apache", "tomcat"), "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"), "joomla": ("joomla", "joomla!"),
    "php": ("php", "php"), "kibana": ("elastic", "kibana"),
    "elasticsearch": ("elastic", "elasticsearch"),
}


def _component_from_text(value: str) -> SoftwareComponent:
    text = value.strip()
    match = re.match(r"(?P<name>[A-Za-z][A-Za-z0-9_.+-]*)(?:[/ ]v?(?P<version>\d[^ ]*))?$", text)
    name = (match.group("name") if match else text).lower()
    version = match.group("version") if match and match.group("version") else ""
    vendor, product = CPE_PRODUCTS.get(name, (name, name))
    cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*" if version else ""
    return SoftwareComponent(vendor, product, version, cpe, evidence=text)


class CVEIntelligence:
    def __init__(self, target: str, output_dir: str, *, provider=None,
                 offline: bool = False, refresh: bool = False):
        self.target = target
        self.output_dir = Path(output_dir)
        self.intel_dir = self.output_dir / "intelligence"
        self.intel_dir.mkdir(parents=True, exist_ok=True)
        self.provider = provider or IntelligenceProvider(
            self.intel_dir / "cache", offline=offline, refresh=refresh
        )

    def _inventory(self) -> list[SoftwareComponent]:
        explicit = self.output_dir / "surface" / "software_inventory.json"
        components: list[SoftwareComponent] = []
        if explicit.exists():
            data = json.loads(explicit.read_text(encoding="utf-8"))
            items = data if isinstance(data, list) else data.get("components", [])
            for item in items:
                components.append(SoftwareComponent(**item))

        summary = self.output_dir / "surface" / "summary.json"
        if summary.exists():
            data = json.loads(summary.read_text(encoding="utf-8"))
            tech = data.get("technologies", {})
            for key in ("cms", "frameworks", "servers", "software"):
                components.extend(_component_from_text(str(v)) for v in tech.get(key, []))

        unique = {(c.vendor, c.product, c.version, c.cpe): c for c in components}
        return list(unique.values())

    def _exposure(self) -> float:
        host = urllib.parse.urlparse(self.target).hostname or self.target
        if host == "localhost":
            return 0.1
        try:
            return 0.1 if ipaddress.ip_address(host).is_private else 1.0
        except ValueError:
            return 1.0

    def exec(self) -> dict:
        components = self._inventory()
        raw: list[tuple[SoftwareComponent, dict]] = []
        for component in components:
            if component.cpe and component.version:
                raw.extend((component, item) for item in self.provider.cves_for_cpe(component.cpe))

        cve_ids = [item.get("cve_id", "") for _, item in raw if item.get("cve_id")]
        kev = self.provider.kev_catalog() if cve_ids else {}
        epss = self.provider.epss_scores(cve_ids) if cve_ids else {}
        candidates = []
        for component, item in raw:
            cve_id = item.get("cve_id", "")
            kev_item, epss_item = kev.get(cve_id, {}), epss.get(cve_id, {})
            candidate = CVECandidate(
                cve_id=cve_id, component=component,
                description=item.get("description", ""), cvss_score=item.get("cvss_score", 0.0),
                cvss_vector=item.get("cvss_vector", ""), references=item.get("references", []),
                epss=float(epss_item.get("epss", 0.0) or 0.0),
                epss_percentile=float(epss_item.get("percentile", 0.0) or 0.0),
                kev=bool(kev_item), kev_due_date=kev_item.get("dueDate", ""),
                known_ransomware_use=kev_item.get("knownRansomwareCampaignUse", "Unknown"),
                applicability="likely" if component.cpe else "possible",
            )
            candidates.append(prioritize(candidate, self._exposure()))

        candidates.sort(key=lambda c: c.priority_score, reverse=True)
        result = {
            "schema_version": 1, "generated_at": time.time(), "target": self.target,
            "inventory": [c.to_dict() for c in components],
            "cves": [c.to_dict() for c in candidates],
            "summary": {
                "components": len(components), "versioned_components": sum(bool(c.version) for c in components),
                "cves": len(candidates), "kev": sum(c.kev for c in candidates),
                "critical": sum(c.priority == "CRITICAL" for c in candidates),
            },
        }
        (self.intel_dir / "cves.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result
