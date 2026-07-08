import ssl
import time
import urllib.parse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from http.client import IncompleteRead

from .logger import buggy_logger

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; Buggy/1.0)",
    "Accept": "*/*",
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
    def __init__(self, timeout: float = 10.0, max_retries: int = 2):
        self.timeout = timeout
        self.max_retries = max_retries

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
        headers = DEFAULT_HEADERS.copy()
        if extra_headers:
            headers.update(extra_headers)
            
        req = Request(url, headers=headers)
        return self._execute(req)

    def post_form(self, url: str, data: dict, extra_headers: dict = None) -> HttpResponse:
        headers = DEFAULT_HEADERS.copy()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        if extra_headers:
            headers.update(extra_headers)
            
        if isinstance(data, list):
            encoded = urllib.parse.urlencode(data).encode()
        else:
            encoded = urllib.parse.urlencode(data, doseq=True).encode()
            
        req = Request(url, data=encoded, headers=headers)
        return self._execute(req)

    def post_xml(self, url: str, xml: str, extra_headers: dict = None) -> HttpResponse:
        headers = DEFAULT_HEADERS.copy()
        headers["Content-Type"] = "application/xml"
        if extra_headers:
            headers.update(extra_headers)
            
        req = Request(url, data=xml.encode(), headers=headers)
        return self._execute(req)
