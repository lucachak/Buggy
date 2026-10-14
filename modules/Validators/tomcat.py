from __future__ import annotations

from modules.utils.http_client import HttpClient

from .common import parse_version, result, target_root


def validate_put(context: dict) -> dict:
    cve_id = context.get("cve_id", "")
    if cve_id != "CVE-2017-12615":
        raise ValueError(f"unsupported CVE for this validator: {cve_id}")

    client = HttpClient(timeout=min(float(context["timeout"]) / 2, 4), max_retries=0)
    root = target_root(context["target"])
    get_response = client.get(root, allow_redirects=False)
    options_response = client.options(root, allow_redirects=False)
    server = get_response.headers.get("server", options_response.headers.get("server", ""))
    version = parse_version(server) if "tomcat" in server.lower() else None
    allowed = {method.strip().upper() for method in options_response.headers.get("allow", "").split(",")}
    evidence = {
        "get_status": get_response.status,
        "options_status": options_response.status,
        "server_header": server[:160],
        "put_advertised": "PUT" in allowed,
    }
    if version is None:
        return result(cve_id, "inconclusive", "Tomcat version was not exposed.", **evidence)
    if not ((7, 0, 0) <= version <= (7, 0, 79)):
        return result(cve_id, "not_vulnerable", "Exposed Tomcat version is outside the affected range.",
                      **evidence)
    if "PUT" in allowed:
        return result(cve_id, "possible", "Affected Tomcat range and advertised PUT were observed.",
                      **evidence)
    return result(cve_id, "possible", "Affected Tomcat range observed, but PUT was not advertised.",
                  **evidence)
