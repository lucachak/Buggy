"""HTTP primitives shared by Buggy's active scanners.

Defaults are conservative: verified TLS, explicit scope, scoped redirects,
bounded responses and no state-changing requests in the safe profile.
"""
from __future__ import annotations

import json
import random
import ssl
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from http.client import IncompleteRead
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from .logger import buggy_logger

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36",
]
WAF_BYPASS_HEADERS = {
    "X-Forwarded-For": "127.0.0.1", "X-Forwarded-Host": "127.0.0.1",
    "X-Client-IP": "127.0.0.1", "X-Remote-IP": "127.0.0.1",
    "X-Remote-Addr": "127.0.0.1", "X-Originating-IP": "127.0.0.1",
    "Client-IP": "127.0.0.1", "True-Client-IP": "127.0.0.1",
}


class ScopeViolation(ValueError):
    """A request or redirect tried to leave the authorized scope."""


class UnsafeMethodBlocked(PermissionError):
    """The safe profile blocked a state-changing request."""


@dataclass
class HttpRuntimeConfig:
    allowed_hosts: set[str] = field(default_factory=set)
    verify_tls: bool = True
    waf_bypass: bool = False
    active_tests: bool = False
    max_rate: float = 10.0


HTTP_CONFIG = HttpRuntimeConfig()
_GLOBAL_RATE_LOCK = threading.Lock()
_GLOBAL_LAST_REQUEST = 0.0


def configure_http(target: str, *, allowed_hosts: list[str] | None = None,
                   verify_tls: bool = True, waf_bypass: bool = False,
                   active_tests: bool = False, max_rate: float = 10.0) -> None:
    """Configure process-wide scanner defaults before modules are created."""
    host = (urllib.parse.urlparse(target).hostname or "").lower().rstrip(".")
    extras = {(h or "").lower().rstrip(".") for h in (allowed_hosts or [])}
    HTTP_CONFIG.allowed_hosts = {h for h in {host, *extras} if h}
    HTTP_CONFIG.verify_tls = verify_tls
    HTTP_CONFIG.waf_bypass = waf_bypass
    HTTP_CONFIG.active_tests = active_tests
    HTTP_CONFIG.max_rate = max_rate


def validate_scoped_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ScopeViolation(f"unsupported or incomplete URL: {url!r}")
    host = parsed.hostname.lower().rstrip(".")
    if HTTP_CONFIG.allowed_hosts and host not in HTTP_CONFIG.allowed_hosts:
        raise ScopeViolation(f"host {host!r} is outside the authorized scope")


def scoped_urlopen(req: Request, *, timeout: float = 10.0):
    """Compatibility helper for surface modules that need a raw response."""
    global _GLOBAL_LAST_REQUEST
    validate_scoped_url(req.full_url)
    if HTTP_CONFIG.max_rate > 0:
        with _GLOBAL_RATE_LOCK:
            wait = 1 / HTTP_CONFIG.max_rate - (time.monotonic() - _GLOBAL_LAST_REQUEST)
            if wait > 0:
                time.sleep(wait)
            _GLOBAL_LAST_REQUEST = time.monotonic()
    context = (ssl.create_default_context() if HTTP_CONFIG.verify_tls
               else ssl._create_unverified_context())  # noqa: SLF001
    opener = build_opener(HTTPSHandler(context=context), _ScopedRedirectHandler())
    return opener.open(req, timeout=timeout)


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _ScopedRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_scoped_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class HttpResponse:
    def __init__(self, status: int, headers: dict, body: str, url: str,
                 elapsed: float, error: Exception | None = None):
        self.status, self.headers, self.body = status, headers, body
        self.url, self.elapsed, self.error = url, elapsed, error

    @property
    def is_success(self) -> bool:
        return 200 <= self.status < 300


class HttpClient:
    """Bounded HTTP client with retries, scope control and rate limiting."""
    def __init__(self, timeout: float = 10.0, max_retries: int = 2,
                 waf_bypass: bool | None = None):
        self.timeout = timeout
        self.max_retries = max_retries
        self.waf_bypass = HTTP_CONFIG.waf_bypass if waf_bypass is None else waf_bypass
        self._rate_lock = threading.Lock()
        self._last_request = 0.0
        self._ssl_context = (ssl.create_default_context() if HTTP_CONFIG.verify_tls
                             else ssl._create_unverified_context())  # noqa: SLF001

    def _prepare_headers(self, extra_headers: dict | None = None) -> dict:
        headers = {"User-Agent": random.choice(USER_AGENTS), "Accept": "*/*"}
        if self.waf_bypass:
            headers.update(WAF_BYPASS_HEADERS)
        if extra_headers:
            headers.update(extra_headers)
        return headers

    def _throttle(self) -> None:
        if HTTP_CONFIG.max_rate <= 0:
            return
        with self._rate_lock:
            wait = 1 / HTTP_CONFIG.max_rate - (time.monotonic() - self._last_request)
            if wait > 0:
                time.sleep(wait)
            self._last_request = time.monotonic()

    def _execute(self, req: Request, *, allow_redirects: bool = True) -> HttpResponse:
        try:
            validate_scoped_url(req.full_url)
        except ScopeViolation as exc:
            buggy_logger.warning(str(exc))
            return HttpResponse(0, {}, "", req.full_url, 0, exc)

        redirects = _ScopedRedirectHandler() if allow_redirects else _NoRedirectHandler()
        opener = build_opener(HTTPSHandler(context=self._ssl_context), redirects)
        retries, backoff = 0, 0.5
        while retries <= self.max_retries:
            self._throttle()
            started = time.monotonic()
            try:
                resp = opener.open(req, timeout=self.timeout)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                try:
                    body = resp.read(512 * 1024).decode("utf-8", errors="replace")
                except IncompleteRead as exc:
                    body = exc.partial.decode("utf-8", errors="replace")
                return HttpResponse(resp.status, headers, body, resp.url,
                                    time.monotonic() - started)
            except HTTPError as exc:
                headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
                try:
                    body = exc.read(512 * 1024).decode("utf-8", errors="replace") if exc.fp else ""
                except IncompleteRead as incomplete:
                    body = incomplete.partial.decode("utf-8", errors="replace")
                if 500 <= exc.code < 600 and retries < self.max_retries:
                    time.sleep(backoff); retries += 1; backoff *= 2
                    continue
                return HttpResponse(exc.code, headers, body, req.full_url,
                                    time.monotonic() - started, exc)
            except (ScopeViolation, URLError, TimeoutError, ConnectionResetError) as exc:
                if isinstance(exc, ScopeViolation) or retries >= self.max_retries:
                    return HttpResponse(0, {}, "", req.full_url,
                                        time.monotonic() - started, exc)
                time.sleep(backoff); retries += 1; backoff *= 2
            except Exception as exc:
                buggy_logger.debug(f"Unexpected HTTP error for {req.full_url}: {exc}")
                return HttpResponse(0, {}, "", req.full_url,
                                    time.monotonic() - started, exc)
        return HttpResponse(0, {}, "", req.full_url, 0)

    def get(self, url: str, extra_headers: dict | None = None,
            allow_redirects: bool = True) -> HttpResponse:
        return self._execute(Request(url, headers=self._prepare_headers(extra_headers)),
                             allow_redirects=allow_redirects)

    def options(self, url: str, extra_headers: dict | None = None,
                allow_redirects: bool = False) -> HttpResponse:
        """Issue a read-only capability query without following redirects."""
        request = Request(url, headers=self._prepare_headers(extra_headers), method="OPTIONS")
        return self._execute(request, allow_redirects=allow_redirects)

    def _blocked_write(self, url: str) -> HttpResponse | None:
        if HTTP_CONFIG.active_tests:
            return None
        exc = UnsafeMethodBlocked("state-changing request blocked; use --profile standard")
        buggy_logger.debug(f"{exc}: {url}")
        return HttpResponse(0, {}, "", url, 0, exc)

    def post(self, url: str, data: dict | None = None,
             extra_headers: dict | None = None) -> HttpResponse:
        return self.post_form(url, data or {}, extra_headers)

    def post_form(self, url: str, data: dict,
                  extra_headers: dict | None = None) -> HttpResponse:
        blocked = self._blocked_write(url)
        if blocked:
            return blocked
        headers = self._prepare_headers(extra_headers)
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        encoded = urllib.parse.urlencode(data or {}, doseq=True).encode()
        return self._execute(Request(url, data=encoded, headers=headers))

    def post_json(self, url: str, data: dict,
                  extra_headers: dict | None = None) -> HttpResponse:
        blocked = self._blocked_write(url)
        if blocked:
            return blocked
        headers = self._prepare_headers(extra_headers); headers["Content-Type"] = "application/json"
        return self._execute(Request(url, data=json.dumps(data).encode(), headers=headers))

    def post_xml(self, url: str, xml: str,
                 extra_headers: dict | None = None) -> HttpResponse:
        blocked = self._blocked_write(url)
        if blocked:
            return blocked
        headers = self._prepare_headers(extra_headers); headers["Content-Type"] = "application/xml"
        return self._execute(Request(url, data=xml.encode(), headers=headers))
