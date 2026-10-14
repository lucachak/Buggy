from __future__ import annotations

from modules.utils.http_client import HttpClient

from .common import parse_version, result, target_root


AFFECTED = {
    "CVE-2021-41773": (2, 4, 49),
    "CVE-2021-42013": (2, 4, 50),
}


def validate_path_traversal(context: dict) -> dict:
    cve_id = context.get("cve_id", "")
    expected = AFFECTED.get(cve_id)
    if expected is None:
        raise ValueError(f"unsupported CVE for this validator: {cve_id}")

    response = HttpClient(timeout=min(float(context["timeout"]), 5), max_retries=0).get(
        target_root(context["target"]), allow_redirects=False
    )
    server = response.headers.get("server", "")
    version = parse_version(server) if "apache" in server.lower() else None
    evidence = {"http_status": response.status, "server_header": server[:160]}
    if version is None:
        return result(cve_id, "inconclusive", "Apache version was not exposed.", **evidence)
    if version == expected:
        return result(cve_id, "possible", f"Exposed Apache version matches {'.'.join(map(str, expected))}.",
                      **evidence)
    return result(cve_id, "not_vulnerable", "Exposed Apache version does not match this CVE.",
                  **evidence)
