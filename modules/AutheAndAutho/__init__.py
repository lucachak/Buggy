"""
AutheAndAutho - Authentication & Authorization Scanner
Testa falhas de IDOR básicas, ausência de headers de rate limit e
cookies inseguros.
"""

from .runner import AuthScanner


def run_auth(target: str, args, output_dir: str) -> None:
    scanner = AuthScanner(target=target, output_dir=output_dir)
    scanner.exec(
        threads=getattr(args, "threads", 20),
        timeout=getattr(args, "timeout", 10.0),
    )


__all__ = ["run_auth", "AuthScanner"]
