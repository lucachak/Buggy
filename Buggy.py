import argparse
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime

banner = """
██████╗   ██╗   ██╗   ██████╗    ██████╗   ██╗   ██╗
██╔══██╗  ██║   ██║  ██╔════╝   ██╔════╝   ╚██╗ ██╔╝
██████╔╝  ██║   ██║  ██║  ███╗  ██║  ███╗   ╚████╔╝
██╔══██╗  ██║   ██║  ██║   ██║  ██║   ██║    ╚██╔╝
██████╔╝  ╚██████╔╝  ╚██████╔╝  ╚██████╔╝     ██║
╚═════╝    ╚═════╝    ╚═════╝    ╚═════╝      ╚═╝
  Modular WebApp Exploiter  |  bug bounty / ethical hacking only
"""

required_tools = [
    "subfinder",
    "dnsx",
    "amass",
    "assetfinder",
    "curl",
    "jq",
    "sed",
    "sort",
    "dig",
    "grep",
]

MODULE_REGISTRY = {
    "recon": "Reconnaissance",
    "surface": "SurfaceMapping",
    "infra": "Infra",
    "auth": "AutheAndAutho",
    "business": "BusinessLogic",
    "injection": "InjectionAttk",
    "ssrf": "ServerSide(SSRF)",
    "xss": "XSSAndClient",
    "report": "Report",
}

IMPLEMENTED_MODULES = {"recon"}
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _report_missing(tool: str) -> None:
    print(f" {RED}✗{RESET} {BOLD}{tool}{RESET}  —  required dependency missing")


def validate_requirements() -> bool:
    from modules.OS_info import SystemInstaller

    missing = []
    for tool in required_tools:
        if shutil.which(tool) is None:
            _report_missing(tool)
            missing.append(tool)
        else:
            print(f" {GREEN}✓{RESET} {BOLD}{tool}{RESET}  —  found")

    if not missing:
        print(f"\n{GREEN}all required components found{RESET}")
        return True

    print(
        f"\n{YELLOW}Missing components — want me to try installing them? [Y/n]{RESET}"
    )
    answer = input("> ").strip().lower()
    if answer in ("y", "yes", ""):
        SystemInstaller().install_packages(missing)
        return True
    return False


def create_output_structure(target: str) -> str:
    """
    Cria a estrutura de pastas para o scan.
    Retorna o path da pasta raiz do output.
    """
    from urllib.parse import urlparse
    import re

    # Extrai domínio limpo
    parsed = urlparse(target)
    domain = parsed.hostname or target
    domain = re.sub(r'[^a-zA-Z0-9.-]', '_', domain)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_root = os.path.join("output", f"{domain}_{timestamp}")

    # Estrutura de pastas
    folders = [
        output_root,
        os.path.join(output_root, "recon"),
        os.path.join(output_root, "recon", "subdomains"),
        os.path.join(output_root, "recon", "dns"),
        os.path.join(output_root, "recon", "dirbust"),
        os.path.join(output_root, "reports"),
        os.path.join(output_root, "logs"),
    ]

    for folder in folders:
        os.makedirs(folder, exist_ok=True)

    print(f"\n{CYAN}[i] Output directory: {BOLD}{output_root}{RESET}")

    return output_root


def run_recon(target: str, args, output_dir: str) -> None:
    from modules.Reconnaissance.Discovery import Discovery

    print(f"\n{BOLD}[>] Starting Reconnaissance on {target}{RESET}\n")
    discovery = Discovery(target=target, output_dir=output_dir)
    discovery.exec(
        threads=args.threads,
        recursive=args.recursive,
        timeout=args.timeout,
        wordlist=args.wordlist,
    )


def run_all(target: str, args, output_dir: str) -> None:
    run_recon(target, args, output_dir)


MODULE_RUNNERS = {
    "recon": lambda t, a, o: run_recon(t, a, o),
    "all": lambda t, a, o: run_all(t, a, o),
}


def build_parser() -> argparse.ArgumentParser:
    valid_modules = list(MODULE_REGISTRY.keys()) + ["all"]

    parser = argparse.ArgumentParser(
        prog="Buggy",
        description="Modular WebApp Exploiter — bug bounty / ethical hacking only",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "--target", "-t",
        required=True,
        metavar="TARGET",
        help="Target domain or IP  (e.g. testphp.vulnweb.com)",
    )
    parser.add_argument(
        "--module", "-m",
        required=True,
        metavar="MODULE",
        choices=valid_modules,
        help=(
            "Module to run. Available:\n"
            + "\n".join(
                f"  {k:<12} {MODULE_REGISTRY[k]}"
                + ("" if k in IMPLEMENTED_MODULES else "  [coming soon]")
                for k in MODULE_REGISTRY
            )
            + "\n  all          Run all implemented modules in order"
        ),
    )
    parser.add_argument("--threads", type=int, default=50, help="Dir busting threads (default: 50)")
    parser.add_argument("--recursive", action="store_true", help="Recursive dir busting")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--wordlist", default="default.txt", help="Wordlist file (default: default.txt)")
    parser.add_argument("--output-dir", "-o", metavar="DIR", help="Custom output directory (default: output/<target>_<timestamp>)")
    parser.add_argument("--skip-deps", action="store_true", help="Skip dependency check")
    parser.add_argument("--no-banner", action="store_true", help="Suppress ASCII banner")

    return parser


CYAN = "\033[96m"
BOLD_CYAN = "\033[1m\033[96m"


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.no_banner:
        print(banner)
        time.sleep(0.6)
        os.system("cls" if os.name == "nt" else "clear")

    if not args.skip_deps:
        if not validate_requirements():
            print(f"\n{RED}Aborting — missing required tools.{RESET}")
            sys.exit(1)
        os.system("cls" if os.name == "nt" else "clear")
        time.sleep(0.2)

    requested = args.module
    if requested != "all" and requested not in IMPLEMENTED_MODULES:
        print(
            f"{YELLOW}[!] Module '{requested}' ({MODULE_REGISTRY[requested]}) "
            f"is not yet implemented.{RESET}"
        )
        sys.exit(0)

    runner = MODULE_RUNNERS.get(requested)
    if runner is None:
        print(f"{RED}[!] No runner found for module '{requested}'. This is a bug.{RESET}")
        sys.exit(1)

    # Criar estrutura de output
    if args.output_dir:
        output_dir = args.output_dir
        os.makedirs(output_dir, exist_ok=True)
    else:
        output_dir = create_output_structure(args.target)

    runner(args.target, args, output_dir)


if __name__ == "__main__":
    main()