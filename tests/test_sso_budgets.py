from types import SimpleNamespace

from modules.AutheAndAutho import payloads
from modules.AutheAndAutho.sso_scanner import SSOScanner


def response(status=200, body="", headers=None):
    return SimpleNamespace(status=status, body=body, headers=headers or {})


class SPAClient:
    def __init__(self):
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(url)
        return response(200, "<app-root>same SPA shell</app-root>")


def test_spa_fallback_is_not_treated_as_sso_endpoints():
    client = SPAClient()
    scanner = SSOScanner("http://localhost:3000", client)
    findings = scanner.discover_endpoints(threads=2)
    assert findings == []
    assert scanner._discovered_endpoints == []
    assert len(client.calls) == len(payloads.SSO_ENDPOINTS) + 1


def test_sso_followup_tasks_have_hard_budgets(monkeypatch):
    client = SPAClient()
    scanner = SSOScanner("http://localhost:3000", client)
    scanner._discovered_endpoints = [f"http://localhost:3000/oauth/{i}" for i in range(12)]
    redirect_calls = []
    idp_calls = []

    def fake_redirect(endpoint, param, value):
        redirect_calls.append((endpoint, param, value))

    monkeypatch.setattr(scanner, "_test_redirect", fake_redirect)
    scanner.test_open_redirects(threads=2)
    assert len(redirect_calls) == scanner.MAX_REDIRECT_TESTS

    def counted_get(url, **kwargs):
        idp_calls.append(url)
        return response(404)

    client.get = counted_get
    scanner.enumerate_idps(threads=2)
    assert len(idp_calls) == scanner.MAX_IDP_TESTS
