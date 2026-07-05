"""
api.py — Descobre APIs REST, GraphQL e specs OpenAPI/Swagger.
Substitui o binário Go api_discoverer.
"""

import json
import re
import ssl
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; Buggy/1.0)"}

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

# Paths a tentar em cada base URL
SWAGGER_PATHS = [
    "/swagger.json", "/swagger.yaml", "/swagger/v1/swagger.json",
    "/api-docs", "/api-docs.json", "/openapi.json", "/openapi.yaml",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/api/swagger.json", "/api/openapi.json",
]

GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/api/graphql", "/query",
    "/gql", "/graph",
]

REST_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/rest/v1", "/v1", "/v2",
    "/_api", "/.api",
]


def _get(url: str, timeout: int = 6) -> tuple[int, str, dict]:
    """Retorna (status, body, headers)."""
    try:
        req = Request(url, headers=HEADERS)
        resp = urlopen(req, timeout=timeout, context=SSL_CTX)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.read(512 * 1024).decode("utf-8", errors="ignore")
        return resp.status, body, headers
    except HTTPError as e:
        return e.code, "", {}
    except Exception:
        return 0, "", {}


def _probe_swagger(base_url: str) -> list[dict]:
    found = []
    for path in SWAGGER_PATHS:
        url = base_url.rstrip("/") + path
        status, body, headers = _get(url)
        if status == 200 and ('"swagger"' in body or '"openapi"' in body
                               or "swagger" in headers.get("content-type", "")):
            try:
                spec = json.loads(body)
                version   = spec.get("openapi") or spec.get("swagger", "?")
                endpoints = list(spec.get("paths", {}).keys())
                found.append({"url": url, "type": "OpenAPI",
                               "version": version, "endpoints": endpoints[:50]})
            except json.JSONDecodeError:
                found.append({"url": url, "type": "OpenAPI/YAML (unparsed)"})
    return found


def _probe_graphql(base_url: str) -> list[dict]:
    found = []
    for path in GRAPHQL_PATHS:
        url = base_url.rstrip("/") + path
        status, body, _ = _get(url)
        if status in (200, 400) and "data" in body and "__schema" in body:
            found.append({"url": url, "type": "GraphQL (introspection enabled)"})
        elif status == 200 and "graphql" in body.lower():
            found.append({"url": url, "type": "GraphQL (possible)"})
    return found


def _probe_rest(base_url: str) -> list[dict]:
    found = []
    for path in REST_PATHS:
        url = base_url.rstrip("/") + path
        status, body, headers = _get(url)
        if status in (200, 201) and "application/json" in headers.get("content-type", ""):
            found.append({"url": url, "type": "REST API"})
    return found


def discover(base_urls: list[str], threads: int = 10, timeout: float = 6.0) -> dict:
    """Descobre APIs em todas as base_urls."""
    openapi_specs = []
    graphqls      = []
    rest_apis     = []

    def _probe_all(base_url: str):
        return {
            "swagger": _probe_swagger(base_url),
            "graphql": _probe_graphql(base_url),
            "rest":    _probe_rest(base_url),
        }

    with ThreadPoolExecutor(max_workers=min(threads, len(base_urls) or 1, 10)) as ex:
        futures = {ex.submit(_probe_all, url): url for url in base_urls[:10]}
        for fut in as_completed(futures):
            res = fut.result()
            openapi_specs.extend(res["swagger"])
            graphqls.extend(res["graphql"])
            rest_apis.extend(res["rest"])

    total = len(openapi_specs) + len(graphqls) + len(rest_apis)

    return {
        "results":       openapi_specs + graphqls + rest_apis,
        "openapi_specs": openapi_specs,
        "graphqls":      graphqls,
        "rest_apis":     rest_apis,
        "total_apis":    total,
    }
