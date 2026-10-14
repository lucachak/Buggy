from modules.SurfaceMapping.detectors.js_analyzer import (
    _fetch_js, _scan_content, discover_script_urls,
)
from modules.SurfaceMapping.detectors.api import discover
from modules.SurfaceMapping.detectors.tech import SIGNATURES, _match
from modules.SurfaceMapping.endpoint_mapper.mapper import EndpointMapper
from modules.SurfaceMapping.surface import SurfaceMapper


def test_standalone_surface_preserves_authorized_scheme_and_port(tmp_path):
    mapper = SurfaceMapper("http://127.0.0.1:3000", str(tmp_path))
    mapper._load_recon_data()
    assert mapper.base_urls == ["http://127.0.0.1:3000"]


def test_recon_target_port_is_preserved_without_portless_duplicates(tmp_path):
    mapper = SurfaceMapper("http://127.0.0.1:3000", str(tmp_path))
    urls = mapper._extract_base_urls({
        "meta": {"target": "http://127.0.0.1:3000"},
        "subdomains": ["127.0.0.1"],
        "live_ips": ["127.0.0.1"],
    })
    assert urls == ["http://127.0.0.1:3000"]


def test_observed_recon_paths_seed_endpoint_and_js_analysis(tmp_path, monkeypatch):
    js_url = "http://127.0.0.1:3000/main.js"
    endpoint_mapper = EndpointMapper(["http://127.0.0.1:3000"], [js_url])
    assert js_url in endpoint_mapper.endpoints

    surface = SurfaceMapper("http://127.0.0.1:3000", str(tmp_path))
    surface.base_urls = ["http://127.0.0.1:3000"]
    surface.paths = [js_url]
    surface.results["endpoints"] = {"endpoints": []}
    observed = {}

    def fake_analyze(urls, **kwargs):
        observed["urls"] = urls
        return {"results": [], "summary": {"total_files": 0, "total_secrets": 0}}

    monkeypatch.setattr("modules.SurfaceMapping.surface.analyze_js", fake_analyze)
    surface._run_js_analyzer(threads=2, timeout=2)
    assert js_url in observed["urls"]


def test_angular_shell_is_fingerprinted():
    assert _match({"body": "<app-root></app-root><script src=main.js>"},
                  SIGNATURES["framework"]) == ["Angular"]


class _Response:
    def __init__(self, body: str, content_type: str):
        self.body = body.encode()
        self.headers = {"Content-Type": content_type}
    def read(self, limit=-1):
        return self.body[:limit] if limit >= 0 else self.body


def test_discovers_hashed_spa_bundles_from_html(monkeypatch):
    markup = """<html><head><base href="/"><link rel="modulepreload" href="chunk-A1.js">
    </head><body><script src="runtime.123.js"></script><script src="main.abc.js"></script></body></html>"""
    monkeypatch.setattr(
        "modules.SurfaceMapping.detectors.js_analyzer.scoped_urlopen",
        lambda request, timeout: _Response(markup, "text/html"),
    )
    urls = discover_script_urls(["http://lab.test/app"], timeout=2)
    assert urls == [
        "http://lab.test/chunk-A1.js",
        "http://lab.test/runtime.123.js",
        "http://lab.test/main.abc.js",
    ]


def test_rejects_html_soft404_returned_for_fake_js(monkeypatch):
    monkeypatch.setattr(
        "modules.SurfaceMapping.detectors.js_analyzer.scoped_urlopen",
        lambda request, timeout: _Response("<!doctype html><html>SPA</html>", "text/html"),
    )
    assert _fetch_js("http://lab.test/static/js/main.js", timeout=2) is None


def test_extracts_api_routes_and_http_method_from_minified_bundle():
    result = _scan_content(
        "http://lab.test/main.abc.js",
        'x.post("/rest/user/login",body);fetch("/api/Products");'
        'x.patch(this.host+`/api/BasketItems`,body);const u="/rest/products/search?q=test";',
    )
    details = {item["path"]: item for item in result["endpoint_details"]}
    assert details["/rest/user/login"]["method"] == "POST"
    assert details["/api/Products"]["method"] == "GET"
    assert details["/api/BasketItems"]["method"] == "PATCH"
    assert details["/rest/products/search?q=test"]["method"] == "UNKNOWN"


def test_js_routes_feed_surface_and_api_inventory(tmp_path):
    mapper = SurfaceMapper("http://lab.test", str(tmp_path))
    mapper.results["endpoints"] = {"endpoints": [], "categorized": {}}
    mapper.results["js_secrets"] = {"results": [{
        "url": "http://lab.test/assets/main.abc.js",
        "endpoint_details": [
            {"path": "/rest/user/login", "method": "POST"},
            {"path": "/rest/products/search?q=juice", "method": "GET"},
            {"path": "https://outside.test/api/private", "method": "GET"},
        ],
    }]}
    mapper._merge_js_routes()
    endpoints = mapper.results["endpoints"]["endpoints"]
    assert "http://lab.test/rest/user/login" in endpoints
    assert "http://lab.test/rest/products/search?q=juice" in endpoints
    assert all("outside.test" not in endpoint for endpoint in endpoints)
    assert mapper._filter_login_endpoints() == ["http://lab.test/rest/user/login"]
    assert mapper._filter_search_endpoints() == ["http://lab.test/rest/products/search?q=juice"]

    inventory = discover([], candidates=mapper._js_route_details())
    assert inventory["total_apis"] == 2
    methods = {item["url"]: item["method"] for item in inventory["results"]}
    assert methods["http://lab.test/rest/user/login"] == "POST"
