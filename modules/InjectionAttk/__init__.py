"""
InjectionAttk — SQL Injection, Command Injection, SSTI, XXE.
"""

from .runner import InjectionScanner


def run_injection(target: str, args, output_dir: str) -> None:
    scanner = InjectionScanner(target=target, output_dir=output_dir)
    scanner.exec(
        threads=getattr(args, "threads", 20),
        timeout=getattr(args, "timeout", 10.0),
    )


__all__ = ["run_injection", "InjectionScanner"]
