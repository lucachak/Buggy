from __future__ import annotations

import re
import urllib.parse


VERSION_RE = re.compile(r"(?<!\d)(\d+)\.(\d+)\.(\d+)(?!\d)")


def target_root(target: str) -> str:
    """Return the authorized origin root, excluding credentials and fragments."""
    parsed = urllib.parse.urlsplit(target)
    host = parsed.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    port = f":{parsed.port}" if parsed.port else ""
    return urllib.parse.urlunsplit((parsed.scheme, f"{host}{port}", "/", "", ""))


def parse_version(value: str) -> tuple[int, int, int] | None:
    match = VERSION_RE.search(value or "")
    return tuple(map(int, match.groups())) if match else None


def result(cve_id: str, applicability: str, summary: str, **evidence) -> dict:
    return {
        "cve_id": cve_id,
        "applicability": applicability,
        "confirmed": False,
        "summary": summary,
        "evidence": evidence,
        "safety": "No exploit payload or state-changing request was sent.",
    }
