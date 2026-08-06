"""
sso_scanner.py — SSO Brute Scanner
Descobre endpoints SSO/OAuth/SAML, testa open redirect via redirect_uri,
detecta token leakage em URLs e enumera IdPs configurados.
"""

from __future__ import annotations

import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import payloads as P
from modules.utils.http_client import HttpClient
from modules.utils.logger import buggy_logger


class SSOScanner:
    """
    Brute-force scanner para superfície SSO.
    Não faz login real — apenas descobre endpoints e testa misconfigurations.
    """

    def __init__(self, target: str, client: HttpClient):
        self.target = target.rstrip("/")
        self.client = client
        self.findings: list[dict] = []
        self._domain = urllib.parse.urlparse(self.target).hostname or ""
        self._discovered_endpoints: list[str] = []

    # ── 1. SSO Endpoint Discovery ────────────────────────────────────────────

    def _probe_endpoint(self, path: str) -> dict | None:
        url = self.target + path
        resp = self.client.get(url)

        # Endpoints SSO geralmente retornam 200, 302 (redirect ao IdP),
        # 401 (não autenticado), ou 400 (falta de params).
        # 404 = não existe, ignorar.
        if resp.status in (200, 301, 302, 303, 307, 308, 400, 401, 403):
            self._discovered_endpoints.append(url)

            finding = {
                "type": "sso_endpoint_found",
                "url": url,
                "parameter": "path",
                "payload": path,
                "evidence": f"SSO endpoint responded with HTTP {resp.status}",
                "confidence": "medium" if resp.status in (200, 302, 401) else "low",
            }

            # Se for .well-known, extrair info extra
            if ".well-known" in path and resp.status == 200:
                finding["confidence"] = "high"
                finding["evidence"] += " — OIDC discovery document exposed"
                # Verifica se tem redirect_uris muito abertos
                body = resp.body.lower()
                if '"redirect_uris"' in body or '"registration_endpoint"' in body:
                    finding["evidence"] += "; dynamic client registration may be enabled"

            return finding

        return None

    def discover_endpoints(self, threads: int = 10) -> list[dict]:
        buggy_logger.info("  [SSO] Brute-forcing SSO endpoints...")
        findings = []

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {
                ex.submit(self._probe_endpoint, path): path
                for path in P.SSO_ENDPOINTS
            }
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    findings.append(result)
                    buggy_logger.info(
                        f"    ✓ {result['url']} → {result['evidence']}"
                    )

        if not findings:
            buggy_logger.info("  [SSO] No SSO endpoints found.")
        else:
            buggy_logger.info(f"  [SSO] {len(findings)} SSO endpoint(s) discovered.")

        return findings

    # ── 2. Open Redirect via redirect_uri ────────────────────────────────────

    def _test_redirect(self, endpoint: str, param: str, payload: str) -> dict | None:
        # Monta URL com o param malicioso
        sep = "&" if "?" in endpoint else "?"
        test_url = f"{endpoint}{sep}{param}={urllib.parse.quote(payload, safe='')}"

        resp = self.client.get(test_url)

        # Checamos se o servidor redireciona para o domínio malicioso
        location = resp.headers.get("location", "")

        if not location:
            # Pode ser um meta refresh ou JS redirect no body
            if "evil.com" in resp.body.lower():
                return {
                    "type": "sso_open_redirect",
                    "url": test_url,
                    "parameter": param,
                    "payload": payload,
                    "evidence": f"Redirect to attacker domain found in response body (HTTP {resp.status})",
                    "confidence": "medium",
                }
            return None

        # Location header contém o domínio malicioso?
        if "evil.com" in location.lower():
            return {
                "type": "sso_open_redirect",
                "url": test_url,
                "parameter": param,
                "payload": payload,
                "evidence": f"Location header redirects to attacker domain: {location[:200]}",
                "confidence": "high",
            }

        return None

    def test_open_redirects(self, threads: int = 10) -> list[dict]:
        if not self._discovered_endpoints:
            buggy_logger.info("  [SSO] No endpoints to test for open redirect.")
            return []

        buggy_logger.info("  [SSO] Testing open redirects on SSO endpoints...")
        findings = []
        tasks = []

        for endpoint in self._discovered_endpoints:
            for param in P.SSO_PARAMS:
                for raw_payload in P.SSO_REDIRECT_PAYLOADS:
                    payload = raw_payload.replace("{domain}", self._domain)
                    tasks.append((endpoint, param, payload))

        buggy_logger.info(f"  [SSO] {len(tasks)} redirect test(s) queued.")

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {
                ex.submit(self._test_redirect, ep, param, payload): (ep, param)
                for ep, param, payload in tasks
            }
            done = 0
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    findings.append(result)
                    buggy_logger.info(
                        f"    🔓 Open redirect: {result['url'][:120]}"
                    )
                done += 1
                if done % 50 == 0:
                    buggy_logger.info(
                        f"  [SSO] ... {done}/{len(tasks)} redirect tests, "
                        f"{len(findings)} finding(s)"
                    )

        if findings:
            buggy_logger.info(f"  [SSO] {len(findings)} open redirect(s) found!")
        else:
            buggy_logger.info("  [SSO] No open redirects found.")

        return findings

    # ── 3. Token Leakage ─────────────────────────────────────────────────────

    def test_token_leakage(self) -> list[dict]:
        buggy_logger.info("  [SSO] Checking for token leakage in URLs...")
        findings = []

        for endpoint in self._discovered_endpoints:
            # Testa response_type=token (implicit flow — tokens na URL)
            sep = "&" if "?" in endpoint else "?"
            implicit_url = (
                f"{endpoint}{sep}response_type=token"
                f"&client_id=test&redirect_uri={urllib.parse.quote(self.target)}"
                f"&scope=openid"
            )
            resp = self.client.get(implicit_url)

            # Verifica se a resposta ou Location contém tokens
            check_text = resp.headers.get("location", "") + " " + resp.body[:2000]

            for pattern in P.SSO_TOKEN_PATTERNS:
                matches = re.findall(pattern, check_text)
                if matches:
                    findings.append({
                        "type": "sso_token_leakage",
                        "url": implicit_url,
                        "parameter": "response_type",
                        "payload": "token (implicit flow)",
                        "evidence": (
                            f"Token/code found in URL/redirect: pattern={pattern}, "
                            f"sample={matches[0][:30]}..."
                        ),
                        "confidence": "high",
                    })
                    buggy_logger.info(
                        f"    🔑 Token leak: {pattern} at {endpoint[:80]}"
                    )

        if not findings:
            buggy_logger.info("  [SSO] No token leakage detected.")

        return findings

    # ── 4. IdP Enumeration ───────────────────────────────────────────────────

    def enumerate_idps(self, threads: int = 5) -> list[dict]:
        if not self._discovered_endpoints:
            return []

        buggy_logger.info("  [SSO] Enumerating Identity Providers...")
        findings = []
        tasks = []

        for endpoint in self._discovered_endpoints:
            for hint_param in P.IDP_HINT_PARAMS:
                for hint_val in P.IDP_HINT_VALUES:
                    tasks.append((endpoint, hint_param, hint_val))

        def _test_idp(endpoint: str, param: str, value: str) -> dict | None:
            sep = "&" if "?" in endpoint else "?"
            url = f"{endpoint}{sep}{param}={value}"
            resp = self.client.get(url)

            # Se recebemos redirect (302) para um IdP real ou 200 com
            # conteúdo diferente de erro genérico → IdP existe
            if resp.status in (200, 302, 303, 307):
                location = resp.headers.get("location", "")
                # Heurística: se o redirect vai para um domínio diferente do target,
                # provavelmente é um IdP real
                if location:
                    loc_host = urllib.parse.urlparse(location).hostname or ""
                    if loc_host and loc_host != self._domain:
                        return {
                            "type": "sso_idp_found",
                            "url": url,
                            "parameter": param,
                            "payload": value,
                            "evidence": (
                                f"IdP '{value}' redirects to {loc_host} "
                                f"(HTTP {resp.status})"
                            ),
                            "confidence": "medium",
                        }
            return None

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = [ex.submit(_test_idp, ep, p, v) for ep, p, v in tasks]
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    findings.append(result)
                    buggy_logger.info(
                        f"    🏢 IdP found: {result['payload']} → "
                        f"{result['evidence'][:80]}"
                    )

        if findings:
            buggy_logger.info(f"  [SSO] {len(findings)} IdP(s) enumerated.")
        else:
            buggy_logger.info("  [SSO] No IdPs enumerated.")

        return findings

    # ── Pipeline ─────────────────────────────────────────────────────────────

    def exec(self, threads: int = 10) -> list[dict]:
        buggy_logger.info(f"\n{'─'*60}")
        buggy_logger.info(f"  SSO Brute Scanner — {self.target}")
        buggy_logger.info(f"{'─'*60}\n")

        self.findings.extend(self.discover_endpoints(threads=threads))
        self.findings.extend(self.test_open_redirects(threads=threads))
        self.findings.extend(self.test_token_leakage())
        self.findings.extend(self.enumerate_idps(threads=min(threads, 5)))

        buggy_logger.info(f"\n  [SSO] Complete — {len(self.findings)} total finding(s)")
        return self.findings
