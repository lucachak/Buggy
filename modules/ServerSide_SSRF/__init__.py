"""
ServerSide_SSRF — SSRF, Blind SSRF, Path Traversal, LFI.
"""

from .runner import SSRFScanner


def run_ssrf(target: str, args, output_dir: str) -> None:
    oob_host = getattr(args, "oob_host", "") or ""
    scanner  = SSRFScanner(target=target, output_dir=output_dir, oob_host=oob_host)
    scanner.exec(
        threads=getattr(args, "threads", 20),
        timeout=getattr(args, "timeout", 10.0),
        oob_host=oob_host,
    )


__all__ = ["run_ssrf", "SSRFScanner"]
