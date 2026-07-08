"""
Infra - Infrastructure Security Scanner
Testa configurações de CORS, headers de segurança e exposição de arquivos sensíveis.
"""

from .runner import InfraScanner


def run_infra(target: str, args, output_dir: str) -> None:
    scanner = InfraScanner(target=target, output_dir=output_dir)
    scanner.exec(
        threads=getattr(args, "threads", 20),
        timeout=getattr(args, "timeout", 10.0),
    )


__all__ = ["run_infra", "InfraScanner"]
