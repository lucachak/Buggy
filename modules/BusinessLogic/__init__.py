"""
BusinessLogic - Business Logic Flaw Scanner
Testa Parameter Pollution (HPP) e Mass Assignment heurístico em formulários e endpoints.
"""

from .runner import BusinessLogicScanner


def run_business(target: str, args, output_dir: str) -> None:
    scanner = BusinessLogicScanner(target=target, output_dir=output_dir)
    scanner.exec(
        threads=getattr(args, "threads", 20),
        timeout=getattr(args, "timeout", 10.0),
    )


__all__ = ["run_business", "BusinessLogicScanner"]
