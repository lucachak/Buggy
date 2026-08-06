"""
AutheAndAutho - Authentication & Authorization Scanner
Testa falhas de IDOR básicas, ausência de headers de rate limit,
cookies inseguros e misconfigurações SSO/OAuth/SAML.
"""

from .runner import AuthScanner
from .sso_scanner import SSOScanner


def run_auth(target: str, args, output_dir: str) -> None:
    scanner = AuthScanner(target=target, output_dir=output_dir)
    scanner.exec(
        threads=getattr(args, "threads", 20),
        timeout=getattr(args, "timeout", 10.0),
    )


__all__ = ["run_auth", "AuthScanner", "SSOScanner"]
