import ssl

import pytest

from Buggy import _normalize_target, build_parser
from modules.utils.http_client import (
    HTTP_CONFIG,
    HttpClient,
    ScopeViolation,
    UnsafeMethodBlocked,
    configure_http,
    validate_scoped_url,
)
from modules.InjectionAttk.runner import (
    _contains_auth_token, _test_cmdi, _test_json_login_sqli, _test_ssti,
)


@pytest.fixture(autouse=True)
def reset_http_config():
    configure_http("https://example.com", max_rate=1000)
    yield
    HTTP_CONFIG.allowed_hosts.clear()


def test_target_normalization_and_rejection():
    assert _normalize_target("example.com") == "http://example.com"
    assert _normalize_target("https://example.com/app/") == "https://example.com/app"
    with pytest.raises(ValueError):
        _normalize_target("ftp://example.com")
    with pytest.raises(ValueError):
        _normalize_target("https://user:secret@example.com")
    with pytest.raises(ValueError):
        _normalize_target("https://example.com/?next=other")


def test_parser_defaults_to_safe_profile():
    args = build_parser().parse_args(["-t", "example.com", "-m", "infra"])
    assert args.profile == "safe"
    assert args.insecure is False
    assert args.waf_bypass is False


def test_scope_is_exact_and_supports_explicit_extra_hosts():
    configure_http("https://app.example.com", allowed_hosts=["api.example.com"])
    validate_scoped_url("https://app.example.com/account")
    validate_scoped_url("https://api.example.com/v1")
    with pytest.raises(ScopeViolation):
        validate_scoped_url("https://evil.example/account")
    with pytest.raises(ScopeViolation):
        validate_scoped_url("file:///etc/passwd")


def test_safe_profile_blocks_state_changing_requests_without_network():
    client = HttpClient()
    response = client.post_json("https://example.com/api", {"role": "admin"})
    assert response.status == 0
    assert isinstance(response.error, UnsafeMethodBlocked)


def test_tls_verification_is_on_by_default():
    client = HttpClient()
    assert client._ssl_context.verify_mode == ssl.CERT_REQUIRED
    assert client._ssl_context.check_hostname is True


def test_json_login_sqli_requires_token_absent_from_baseline():
    class Response:
        def __init__(self, status, body):
            self.status, self.body = status, body

    class Client:
        def post_json(self, url, data):
            if data["email"].startswith("buggy-invalid-"):
                return Response(401, '{"error":"invalid credentials"}')
            return Response(200, '{"authentication":{"token":"header.payload.signature"}}')

    assert _contains_auth_token('{"authentication":{"token":"header.payload.signature"}}')
    finding = _test_json_login_sqli(Client(), "https://example.com/rest/user/login")
    assert finding["subtype"] == "authentication_bypass"
    assert finding["confidence"] == "confirmed"


def test_json_login_sqli_rejects_token_already_returned_by_baseline():
    class Response:
        status = 200
        body = '{"token":"baseline-token-value"}'
    class Client:
        def post_json(self, url, data): return Response()
    assert _test_json_login_sqli(Client(), "https://example.com/login") is None


def test_reflected_payloads_are_not_command_or_template_execution():
    class Response:
        elapsed = 0.01
        def __init__(self, body): self.body = body
    class Client:
        def get(self, url):
            return Response(urllib.parse.unquote(url))

    import urllib.parse
    client = Client()
    assert _test_cmdi(client, "https://example.com/search?q=", "q") is None
    assert _test_ssti(client, "https://example.com/search?q=", "q") is None
