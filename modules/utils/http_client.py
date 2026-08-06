import ssl
import time
import urllib.parse
import random
import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from http.client import IncompleteRead

from .logger import buggy_logger

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]

WAF_BYPASS_HEADERS = {
    "X-Forwarded-For": "127.0.0.1",
    "X-Forwarded-Host": "127.0.0.1",
    "X-Client-IP": "127.0.0.1",
    "X-Remote-IP": "127.0.0.1",
    "X-Remote-Addr": "127.0.0.1",
    "X-Originating-IP": "127.0.0.1",
    "Client-IP": "127.0.0.1",
    "True-Client-IP": "127.0.0.1",
}


class HttpResponse:
    def __init__(self, status: int, headers: dict, body: str, url: str, elapsed: float, error: Exception | None = None):
        self.status = status
        self.headers = headers
        self.body = body
        self.url = url
        self.elapsed = elapsed
        self.error = error

    @property
    def is_success(self) -> bool:
        return 200 <= self.status < 300


class HttpClient:
    """
    Robust HTTP client that wraps urllib.request.
    Implements retries, timeout handling, and consistent error capturing.
    """
    def __init__(self, timeout: float = 10.0, max_retries: int = 2, waf_bypass: bool = True):
        self.timeout = timeout
        self.max_retries = max_retries
        self.waf_bypass = waf_bypass

    def _prepare_headers(self, extra_headers: dict = None) -> dict:
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "*/*",
        }
        if self.waf_bypass:
            headers.update(WAF_BYPASS_HEADERS)
        if extra_headers:
            headers.update(extra_headers)
        return headers

    def _execute(self, req: Request) -> HttpResponse:
        retries = 0
        backoff = 1.0

        while retries <= self.max_retries:
            t0 = time.time()
            try:
                resp = urlopen(req, timeout=self.timeout, context=SSL_CTX)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                
                try:
                    body = resp.read(512 * 1024).decode("utf-8", errors="ignore")
                except IncompleteRead as e:
                    body = e.partial.decode("utf-8", errors="ignore")

                elapsed = time.time() - t0
                return HttpResponse(resp.status, headers, body, resp.url, elapsed)

            except HTTPError as e:
                elapsed = time.time() - t0
                headers = {k.lower(): v for k, v in e.headers.items()} if hasattr(e, 'headers') else {}
                try:
                    body = e.read(512 * 1024).decode("utf-8", errors="ignore") if e.fp else ""
                except IncompleteRead as ex:
                    body = ex.partial.decode("utf-8", errors="ignore")
                
                # Retry on 5xx errors
                if 500 <= e.code < 600 and retries < self.max_retries:
                    buggy_logger.debug(f"HTTP {e.code} for {req.full_url}, retrying in {backoff}s...")
                    time.sleep(backoff)
                    retries += 1
                    backoff *= 2
                    continue
                    
                return HttpResponse(e.code, headers, body, req.full_url, elapsed, error=e)

            except (URLError, TimeoutError, ConnectionResetError) as e:
                elapsed = time.time() - t0
                if retries < self.max_retries:
                    buggy_logger.debug(f"Connection error ({type(e).__name__}) for {req.full_url}, retrying in {backoff}s...")
                    time.sleep(backoff)
                    retries += 1
                    backoff *= 2
                    continue
                
                buggy_logger.debug(f"Failed to fetch {req.full_url} after {self.max_retries} retries: {e}")
                return HttpResponse(0, {}, "", req.full_url, elapsed, error=e)
                
            except Exception as e:
                elapsed = time.time() - t0
                buggy_logger.debug(f"Unexpected error fetching {req.full_url}: {e}")
                return HttpResponse(0, {}, "", req.full_url, elapsed, error=e)
                
        # Fallback (should not be reached)
        return HttpResponse(0, {}, "", req.full_url, 0)

    def get(self, url: str, extra_headers: dict = None, allow_redirects: bool = True) -> HttpResponse:
        headers = self._prepare_headers(extra_headers)
        req = Request(url, headers=headers)
        return self._execute(req)

    def post(self, url: str, data: dict = None, extra_headers: dict = None) -> HttpResponse:
        """Alias for post_form to maintain compatibility"""
        return self.post_form(url, data, extra_headers)

    def post_form(self, url: str, data: dict, extra_headers: dict = None) -> HttpResponse:
        headers = self._prepare_headers(extra_headers)
        headers["Content-Type"] = "application/x-www-form-urlencoded"
            
        if isinstance(data, list):
            encoded = urllib.parse.urlencode(data).encode()
        elif data:
            encoded = urllib.parse.urlencode(data, doseq=True).encode()
        else:
            encoded = b""
            
        req = Request(url, data=encoded, headers=headers)
        return self._execute(req)
        
    def post_json(self, url: str, data: dict, extra_headers: dict = None) -> HttpResponse:
        headers = self._prepare_headers(extra_headers)
        headers["Content-Type"] = "application/json"
        
        encoded = json.dumps(data).encode("utf-8")
        req = Request(url, data=encoded, headers=headers)
        return self._execute(req)

    def post_xml(self, url: str, xml: str, extra_headers: dict = None) -> HttpResponse:
        headers = self._prepare_headers(extra_headers)
        headers["Content-Type"] = "application/xml"
            
        req = Request(url, data=xml.encode(), headers=headers)
        return self._execute(req)
