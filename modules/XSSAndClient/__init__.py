"""
XSSAndClient — Reflected/Stored XSS, CSRF, Open Redirect.
"""

from .runner import XSSScanner


def run_xss(target: str, args, output_dir: str) -> None:
    scanner = XSSScanner(target=target, output_dir=output_dir)
    scanner.exec(
        threads=getattr(args, "threads", 20),
        timeout=getattr(args, "timeout", 10.0),
    )


__all__ = ["run_xss", "XSSScanner"]
