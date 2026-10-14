from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.parse
import urllib.request
from pathlib import Path


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


class JsonCache:
    def __init__(self, directory: Path, ttl: int = 86400):
        self.directory = directory
        self.ttl = ttl
        directory.mkdir(parents=True, exist_ok=True)

    def _path(self, namespace: str, key: str) -> Path:
        digest = hashlib.sha256(key.encode()).hexdigest()
        return self.directory / f"{namespace}-{digest}.json"

    def get(self, namespace: str, key: str, allow_stale: bool = False):
        path = self._path(namespace, key)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            fresh = time.time() - data["cached_at"] <= self.ttl
            return data["value"] if fresh or allow_stale else None
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def put(self, namespace: str, key: str, value) -> None:
        path = self._path(namespace, key)
        temp = path.with_suffix(".tmp")
        temp.write_text(json.dumps({"cached_at": time.time(), "value": value}), encoding="utf-8")
        temp.replace(path)


class IntelligenceProvider:
    def __init__(self, cache_dir: Path, *, offline: bool = False,
                 refresh: bool = False, timeout: float = 15.0):
        self.cache = JsonCache(cache_dir)
        self.offline = offline
        self.refresh = refresh
        self.timeout = timeout

    def _json(self, namespace: str, key: str, url: str, headers: dict | None = None):
        if not self.refresh:
            cached = self.cache.get(namespace, key, allow_stale=self.offline)
            if cached is not None:
                return cached
        if self.offline:
            return None
        request = urllib.request.Request(
            url, headers={"User-Agent": "Buggy-CVEIntelligence/0.4", **(headers or {})}
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                value = json.loads(response.read(4 * 1024 * 1024))
            self.cache.put(namespace, key, value)
            return value
        except Exception:
            return self.cache.get(namespace, key, allow_stale=True)

    def cves_for_cpe(self, cpe: str) -> list[dict]:
        params = urllib.parse.urlencode({"cpeName": cpe, "noRejected": ""})
        headers = {}
        api_key = os.environ.get("NVD_API_KEY", "").strip()
        if api_key:
            headers["apiKey"] = api_key
        data = self._json("nvd", cpe, f"{NVD_URL}?{params}", headers) or {}
        return [self._parse_nvd(item.get("cve", {})) for item in data.get("vulnerabilities", [])]

    @staticmethod
    def _parse_nvd(cve: dict) -> dict:
        descriptions = cve.get("descriptions", [])
        description = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        metric = {}
        for name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(name):
                metric = metrics[name][0].get("cvssData", {})
                break
        return {
            "cve_id": cve.get("id", ""), "description": description,
            "cvss_score": float(metric.get("baseScore", 0.0) or 0.0),
            "cvss_vector": metric.get("vectorString", ""),
            "references": [r.get("url", "") for r in cve.get("references", [])[:10]],
        }

    def kev_catalog(self) -> dict[str, dict]:
        data = self._json("cisa-kev", "catalog", KEV_URL) or {}
        return {item.get("cveID", ""): item for item in data.get("vulnerabilities", [])}

    def epss_scores(self, cve_ids: list[str]) -> dict[str, dict]:
        scores: dict[str, dict] = {}
        for start in range(0, len(cve_ids), 50):
            batch = sorted(set(cve_ids[start:start + 50]))
            if not batch:
                continue
            key = ",".join(batch)
            url = EPSS_URL + "?" + urllib.parse.urlencode({"cve": key})
            data = self._json("epss", key, url) or {}
            for item in data.get("data", []):
                scores[item.get("cve", "")] = item
        return scores
