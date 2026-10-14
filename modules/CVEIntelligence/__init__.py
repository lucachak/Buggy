from .runner import CVEIntelligence


def run_cve_intelligence(target: str, args, output_dir: str):
    scanner = CVEIntelligence(
        target, output_dir,
        offline=getattr(args, "offline", False),
        refresh=getattr(args, "refresh_intel", False),
    )
    result = scanner.exec()
    summary = result["summary"]
    print(f"\n  CVE Intelligence: {summary['components']} componentes, "
          f"{summary['cves']} CVEs, {summary['kev']} KEV")
    print(f"  Output: {scanner.intel_dir / 'cves.json'}")
    return result


__all__ = ["CVEIntelligence", "run_cve_intelligence"]
