"""
js_analyzer.py — Extrai segredos e endpoints de arquivos JavaScript.
Substitui o binário Go js_analyzer.
"""

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
from urllib.request import Request
from modules.utils.http_client import scoped_urlopen
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; Buggy/1.0)"}

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

CALL_ENDPOINT_PATTERN = re.compile(
    r"""(?:(?:\.\s*(get|post|put|delete|patch))|fetch)\s*\(\s*['"`]"""
    r"""((?:/(?:api|rest|graphql|v[0-9]+)[a-zA-Z0-9_/\-?=&.%:${}]*|https?://[^\s'"`]+))""",
    re.I,
)
ROUTE_LITERAL_PATTERN = re.compile(
    r"""['"`]((?:/(?:api|rest|graphql|v[0-9]+)[a-zA-Z0-9_/\-?=&.%:${}]*|https?://[^\s'"`]+))['"`]""",
    re.I,
)
SCRIPT_LITERAL_PATTERN = re.compile(r"""['"`]([^'"`\s]{1,180}\.js(?:\?[^'"`\s]*)?)['"`]""", re.I)
METHOD_CONTEXT_PATTERN = re.compile(
    r"\.\s*(get|post|put|delete|patch)\s*\([^)]{0,240}$", re.I,
)


class _AssetParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts: list[str] = []
        self.base_href = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        values = dict(attrs)
        if tag.lower() == "base" and values.get("href"):
            self.base_href = values["href"] or ""
        if tag.lower() == "script" and values.get("src"):
            self.scripts.append(values["src"] or "")
        if (tag.lower() == "link" and values.get("href")
                and str(values.get("rel", "")).lower() in {"modulepreload", "preload"}
                and (str(values.get("as", "")).lower() in {"", "script"})):
            self.scripts.append(values["href"] or "")


def discover_script_urls(page_urls: list[str], timeout: float = 10.0) -> list[str]:
    """Read actual script/modulepreload assets from authorized HTML pages."""
    discovered = []
    for page_url in list(dict.fromkeys(page_urls))[:10]:
        try:
            response = scoped_urlopen(Request(page_url, headers=HEADERS), timeout=timeout)
            content_type = response.headers.get("Content-Type", "").lower()
            if "html" not in content_type:
                continue
            markup = response.read(1024 * 1024).decode("utf-8", errors="ignore")
            parser = _AssetParser()
            parser.feed(markup)
            document_base = urljoin(page_url, parser.base_href or page_url)
            page_host = (urlparse(page_url).hostname or "").lower()
            for source in parser.scripts:
                candidate = urljoin(document_base, source)
                if (urlparse(candidate).hostname or "").lower() == page_host:
                    discovered.append(candidate)
        except Exception:
            continue
    return list(dict.fromkeys(discovered))


def _fetch_js(url: str, timeout: int = 10) -> str | None:
    try:
        req = Request(url, headers=HEADERS)
        resp = scoped_urlopen(req, timeout=timeout)
        ct = resp.headers.get("Content-Type", "")
        content = resp.read(2 * 1024 * 1024).decode("utf-8", errors="ignore")
        prefix = content.lstrip()[:500].lower()
        if "html" in ct.lower() or prefix.startswith("<!doctype html") or "<html" in prefix:
            return None
        if "javascript" not in ct.lower() and ".js" not in urlparse(url).path.lower():
            return None
        return content
    except Exception:
        return None


def _scan_content(url: str, content: str) -> dict:
    secrets   = []
    details = {}
    for match in CALL_ENDPOINT_PATTERN.finditer(content):
        endpoint = match.group(2)
        details[endpoint] = {
            "path": endpoint,
            "method": (match.group(1) or "GET").upper(),
            "source": url,
        }
    for match in ROUTE_LITERAL_PATTERN.finditer(content):
        endpoint = match.group(1)
        context = content[max(0, match.start() - 260):match.start()]
        inferred = METHOD_CONTEXT_PATTERN.search(context)
        method = inferred.group(1).upper() if inferred else "UNKNOWN"
        details.setdefault(endpoint, {"path": endpoint, "method": method, "source": url})
    script_refs = list(dict.fromkeys(match.group(1) for match in SCRIPT_LITERAL_PATTERN.finditer(content)))

    for label, pattern, severity in SECRET_PATTERNS:
        for match in re.finditer(pattern, content):
            secrets.append({
                "type":     label,
                "severity": severity,
                "match":    match.group(0)[:120],   # trunca para não vazar
                "url":      url,
            })

    return {"url": url, "secrets": secrets, "endpoints": list(details),
            "endpoint_details": list(details.values()), "script_refs": script_refs,
            "secret_count": len(secrets)}


def analyze(js_urls: list[str], threads: int = 10, timeout: float = 10.0,
            page_urls: list[str] | None = None) -> dict:
    """Analisa lista de URLs JS e retorna segredos e endpoints encontrados."""
    all_results = []
    queue = list(dict.fromkeys(js_urls + discover_script_urls(page_urls or [], timeout)))[:30]
    visited = set()

    # Two bounded rounds include direct bundle references without becoming a crawler.
    for _ in range(2):
        batch = [item for item in queue if item not in visited][:30 - len(visited)]
        if not batch:
            break
        with ThreadPoolExecutor(max_workers=min(threads, len(batch) or 1, 15)) as ex:
            futures = {ex.submit(_fetch_js, url, int(timeout)): url for url in batch}
            for fut in as_completed(futures):
                content = fut.result()
                source_url = futures[fut]
                visited.add(source_url)
                if content:
                    result = _scan_content(source_url, content)
                    all_results.append(result)
                    source_host = (urlparse(source_url).hostname or "").lower()
                    for reference in result.get("script_refs", []):
                        candidate = urljoin(source_url, reference)
                        if (urlparse(candidate).hostname or "").lower() == source_host:
                            queue.append(candidate)

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
            "attempted_files": len(visited),
            "total_secrets": total_secrets,
            "high_severity": high_critical,
        },
    }
