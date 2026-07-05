"""
js_analyzer.py — Extrai segredos e endpoints de arquivos JavaScript.
Substitui o binário Go js_analyzer.
"""

import re
import ssl
from urllib.request import Request, urlopen
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; Buggy/1.0)"}

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

# (label, regex, severity)
SECRET_PATTERNS = [
    ("AWS Access Key",     r"AKIA[0-9A-Z]{16}",                                     "critical"),
    ("AWS Secret Key",     r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "critical"),
    ("GCP API Key",        r"AIza[0-9A-Za-z\\-_]{35}",                              "critical"),
    ("GitHub Token",       r"ghp_[0-9a-zA-Z]{36}",                                  "critical"),
    ("Slack Token",        r"xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}",      "high"),
    ("Generic API Key",    r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{20,}['\"]", "high"),
    ("Bearer Token",       r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}",                  "high"),
    ("JWT",                r"ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "medium"),
    ("Password in code",   r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]", "medium"),
    ("Private IP",         r"(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}", "low"),
    ("Internal URL",       r"https?://(?:localhost|127\.0\.0\.1|internal|corp)[^\s'\"]+", "low"),
]

ENDPOINT_PATTERN = re.compile(
    r"""(?:fetch|axios|XMLHttpRequest|\.get|\.post|\.put|\.delete)\s*\(\s*['"`]"""
    r"""(/[a-zA-Z0-9_/\-?=&.%]{2,}|https?://[^\s'"`]+)""",
    re.I,
)


def _fetch_js(url: str, timeout: int = 10) -> str | None:
    try:
        req = Request(url, headers=HEADERS)
        resp = urlopen(req, timeout=timeout, context=SSL_CTX)
        ct = resp.headers.get("Content-Type", "")
        if "javascript" not in ct and not url.endswith(".js"):
            return None
        return resp.read(2 * 1024 * 1024).decode("utf-8", errors="ignore")
    except Exception:
        return None


def _scan_content(url: str, content: str) -> dict:
    secrets   = []
    endpoints = list({m.group(1) for m in ENDPOINT_PATTERN.finditer(content)})

    for label, pattern, severity in SECRET_PATTERNS:
        for match in re.finditer(pattern, content):
            secrets.append({
                "type":     label,
                "severity": severity,
                "match":    match.group(0)[:120],   # trunca para não vazar
                "url":      url,
            })

    return {"url": url, "secrets": secrets, "endpoints": endpoints,
            "secret_count": len(secrets)}


def analyze(js_urls: list[str], threads: int = 10, timeout: float = 10.0) -> dict:
    """Analisa lista de URLs JS e retorna segredos e endpoints encontrados."""
    all_results = []

    with ThreadPoolExecutor(max_workers=min(threads, len(js_urls) or 1, 15)) as ex:
        futures = {ex.submit(_fetch_js, url, int(timeout)): url
                   for url in js_urls[:30]}
        for fut in as_completed(futures):
            content = fut.result()
            url = futures[fut]
            if content:
                all_results.append(_scan_content(url, content))

    total_secrets = sum(r["secret_count"] for r in all_results)
    high_critical = sum(
        1 for r in all_results
        for s in r["secrets"]
        if s["severity"] in ("critical", "high")
    )

    return {
        "results": all_results,
        "summary": {
            "total_files":   len(all_results),
            "total_secrets": total_secrets,
            "high_severity": high_critical,
        },
    }
