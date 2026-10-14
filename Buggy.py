import argparse
import os
import shutil
import sys
import time
import urllib.parse
from datetime import datetime

VERSION = "0.4.0"

banner = """
██████╗   ██╗   ██╗   ██████╗    ██████╗   ██╗   ██╗
██╔══██╗  ██║   ██║  ██╔════╝   ██╔════╝   ╚██╗ ██╔╝
██████╔╝  ██║   ██║  ██║  ███╗  ██║  ███╗   ╚████╔╝
██╔══██╗  ██║   ██║  ██║   ██║  ██║   ██║    ╚██╔╝
██████╔╝  ╚██████╔╝  ╚██████╔╝  ╚██████╔╝     ██║
╚═════╝    ╚═════╝    ╚═════╝    ╚═════╝      ╚═╝
  Modular WebApp Exploiter  |  bug bounty / ethical hacking only
"""

RECON_TOOLS = [
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
    "cve": "CVEIntelligence",
    "plan": "ValidatorRegistry",
    "nuclei": "NucleiAdapter",
    "approve": "Approval",
    "execute": "SandboxExecutor",
    "ui": "FastAPIWebUI",
    "infra": "Infra",
    "auth": "AutheAndAutho",
    "business": "BusinessLogic",
    "injection": "InjectionAttk",
    "ssrf": "ServerSide_SSRF",
    "xss": "XSSAndClient",
    "report": "Report",
}

IMPLEMENTED_MODULES = set(MODULE_REGISTRY)
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _report_missing(tool: str) -> None:
    print(f" {RED}✗{RESET} {BOLD}{tool}{RESET}  —  required dependency missing")


def validate_requirements(tools: list[str], install_missing: bool = False) -> bool:
    from modules.OS_info import SystemInstaller

    missing = []
    for tool in tools:
        if shutil.which(tool) is None:
            _report_missing(tool)
            missing.append(tool)
        else:
            print(f" {GREEN}✓{RESET} {BOLD}{tool}{RESET}  —  found")

    if not missing:
        print(f"\n{GREEN}all required components found{RESET}")
        return True

    if install_missing:
        SystemInstaller().install_packages(missing)
        still_missing = [tool for tool in missing if shutil.which(tool) is None]
        return not still_missing
    print(f"\n{YELLOW}Install them manually or rerun with --install-missing.{RESET}")
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
        rate=args.rate,
        recursive=args.recursive,
        max_depth=args.max_depth,
        timeout=args.timeout,
        wordlist=args.wordlist,
        insecure=args.insecure,
    )


def run_surface(target: str, args, output_dir: str) -> None:
    """Wrapper para o módulo SurfaceMapping."""
    from modules.SurfaceMapping.surface import run_surface as _run_surface

    print(f"\n{BOLD}[>] Starting Surface Mapping on {target}{RESET}\n")
    _run_surface(target, args, output_dir)


def run_cve(target: str, args, output_dir: str) -> None:
    from modules.CVEIntelligence import run_cve_intelligence
    run_cve_intelligence(target, args, output_dir)


def run_plan(target: str, args, output_dir: str) -> None:
    from modules.Validation import run_validation_plan
    run_validation_plan(target, args, output_dir)


def run_nuclei(target: str, args, output_dir: str) -> None:
    from modules.Validation import run_nuclei_adapter
    run_nuclei_adapter(target, args, output_dir)


def run_approve(target: str, args, output_dir: str) -> None:
    from modules.Validation import run_approval
    run_approval(target, args, output_dir)


def run_execute(target: str, args, output_dir: str) -> None:
    from modules.Validation import run_execution
    run_execution(target, args, output_dir)


def run_ui(target: str, args, output_dir: str) -> None:
    from modules.WebUI import run_web_ui
    run_web_ui(args)


def run_injection(target: str, args, output_dir: str) -> None:
    """Wrapper para o módulo InjectionAttk."""
    from modules.InjectionAttk import run_injection as _run_injection

    print(f"\n{BOLD}[>] Starting Injection Scan on {target}{RESET}\n")
    _run_injection(target, args, output_dir)


def run_xss(target: str, args, output_dir: str) -> None:
    """Wrapper para o módulo XSSAndClient."""
    from modules.XSSAndClient import run_xss as _run_xss

    print(f"\n{BOLD}[>] Starting XSS/Client Scan on {target}{RESET}\n")
    _run_xss(target, args, output_dir)


def run_ssrf(target: str, args, output_dir: str) -> None:
    """Wrapper para o módulo ServerSide_SSRF."""
    from modules.ServerSide_SSRF import run_ssrf as _run_ssrf
    _run_ssrf(target, args, output_dir)


def run_infra(target: str, args, output_dir: str) -> None:
    """Wrapper para o módulo Infra."""
    from modules.Infra import run_infra as _run_infra
    print(f"\n{BOLD}[>] Starting Infra Scan on {target}{RESET}\n")
    _run_infra(target, args, output_dir)


def run_auth(target: str, args, output_dir: str) -> None:
    """Wrapper para o módulo AutheAndAutho."""
    from modules.AutheAndAutho import run_auth as _run_auth
    print(f"\n{BOLD}[>] Starting Auth Scan on {target}{RESET}\n")
    _run_auth(target, args, output_dir)


def run_business(target: str, args, output_dir: str) -> None:
    """Wrapper para o módulo BusinessLogic."""
    from modules.BusinessLogic import run_business as _run_business
    print(f"\n{BOLD}[>] Starting Business Logic Scan on {target}{RESET}\n")
    _run_business(target, args, output_dir)


def run_report(target: str, args, output_dir: str) -> None:
    """Generate a consolidated report from an existing scan directory."""
    from modules.Report.report import generate

    generate(output_dir)


def run_all(target: str, args, output_dir: str) -> None:
    """Executa pipeline completo incluindo inteligência de CVEs e relatório."""
    print(f"\n{BOLD}[>] Starting Full Pipeline on {target}{RESET}\n")

    print(f"{CYAN}{'='*60}{RESET}")
    print(f"{CYAN}  PHASE 1/9: Reconnaissance{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")
    run_recon(target, args, output_dir)

    print(f"\n{CYAN}{'='*60}{RESET}")
    print(f"{CYAN}  PHASE 2/9: Surface Mapping{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")
    run_surface(target, args, output_dir)

    print(f"\n{CYAN}{'='*60}{RESET}")
    print(f"{CYAN}  PHASE 3/9: CVE Intelligence & Prioritization{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")
    try:
        run_cve(target, args, output_dir)
        run_plan(target, args, output_dir)
        run_execute(target, args, output_dir)
    except Exception as e:
        print(f"{YELLOW}  [!] CVE intelligence/validation error: {e}{RESET}")

    print(f"\n{CYAN}{'='*60}{RESET}")
    print(f"{CYAN}  PHASE 4/9: Infrastructure Security{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")
    try:
        run_infra(target, args, output_dir)
    except Exception as e:
        print(f"{YELLOW}  [!] Infra scan error: {e}{RESET}")

    print(f"\n{CYAN}{'='*60}{RESET}")
    print(f"{CYAN}  PHASE 5/9: Authentication & Authorization{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")
    try:
        run_auth(target, args, output_dir)
    except Exception as e:
        print(f"{YELLOW}  [!] Auth scan error: {e}{RESET}")

    print(f"\n{CYAN}{'='*60}{RESET}")
    print(f"{CYAN}  PHASE 6/9: Business Logic{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")
    try:
        run_business(target, args, output_dir)
    except Exception as e:
        print(f"{YELLOW}  [!] Business Logic scan error: {e}{RESET}")

    print(f"\n{CYAN}{'='*60}{RESET}")
    print(f"{CYAN}  PHASE 7/9: Injection Attacks{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")
    try:
        run_injection(target, args, output_dir)
    except Exception as e:
        print(f"{YELLOW}  [!] Injection scan error: {e}{RESET}")

    print(f"\n{CYAN}{'='*60}{RESET}")
    print(f"{CYAN}  PHASE 8/9: XSS & Client-Side{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")
    try:
        run_xss(target, args, output_dir)
    except Exception as e:
        print(f"{YELLOW}  [!] XSS scan error: {e}{RESET}")

    print(f"\n{CYAN}{'='*60}{RESET}")
    print(f"{CYAN}  PHASE 9/9: SSRF & Server-Side{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")
    try:
        run_ssrf(target, args, output_dir)
    except Exception as e:
        print(f"{YELLOW}  [!] SSRF scan error: {e}{RESET}")

    # Gera relatório HTML consolidado
    try:
        from modules.Report.report import generate
        report_path = generate(output_dir)
        print(f"\n{GREEN}  📊  Report: {report_path}{RESET}")
    except Exception as e:
        print(f"{YELLOW}  [!] Report generation failed: {e}{RESET}")

    print(f"\n{GREEN}{'='*60}{RESET}")
    print(f"{GREEN}  ✅ Full Pipeline Complete!{RESET}")
    print(f"{GREEN}  Output: {output_dir}{RESET}")
    print(f"{GREEN}{'='*60}{RESET}")



def run_watch(target: str, args, output_dir: str) -> None:
    """
    Watch mode: re-executa o pipeline em loop e reporta delta entre scans.
    Intervalo configurável via --watch-interval (default: 3600s).
    """
    from modules.Report import rotate_snapshot, load_and_diff, print_delta

    interval = getattr(args, "watch_interval", 3600)
    iteration = 0

    print(f"\n{BOLD}👁  Watch mode — target: {target}{RESET}")
    print(f"     {CYAN}Interval : {interval}s  |  Output: {output_dir}{RESET}")
    print(f"     {YELLOW}Press Ctrl+C to stop.{RESET}\n")

    try:
        while True:
            iteration += 1
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"\n{CYAN}{'='*60}{RESET}")
            print(f"{CYAN}  WATCH SCAN #{iteration}  [{ts}]{RESET}")
            print(f"{CYAN}{'='*60}{RESET}")

            # Rotaciona snapshot antes de escanear
            rotate_snapshot(output_dir)

            # Roda pipeline completo
            run_all(target, args, output_dir)

            # Calcula e imprime delta
            print(f"\n{BOLD}  📊  Delta since last scan:{RESET}")
            delta = load_and_diff(output_dir)
            print_delta(delta)

            if iteration > 1 and delta.get("has_changes"):
                print(f"\n{YELLOW}  [!] Surface changed — review findings above.{RESET}")

            print(f"\n{CYAN}  Next scan in {interval}s  (Ctrl+C to stop){RESET}")
            time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\n\n{GREEN}  Watch mode stopped after {iteration} scan(s).{RESET}")


MODULE_RUNNERS = {
    "recon":     lambda t, a, o: run_recon(t, a, o),
    "surface":   lambda t, a, o: run_surface(t, a, o),
    "cve":       lambda t, a, o: run_cve(t, a, o),
    "plan":      lambda t, a, o: run_plan(t, a, o),
    "nuclei":    lambda t, a, o: run_nuclei(t, a, o),
    "approve":   lambda t, a, o: run_approve(t, a, o),
    "execute":   lambda t, a, o: run_execute(t, a, o),
    "ui":        lambda t, a, o: run_ui(t, a, o),
    "infra":     lambda t, a, o: run_infra(t, a, o),
    "auth":      lambda t, a, o: run_auth(t, a, o),
    "business":  lambda t, a, o: run_business(t, a, o),
    "injection": lambda t, a, o: run_injection(t, a, o),
    "xss":       lambda t, a, o: run_xss(t, a, o),
    "ssrf":      lambda t, a, o: run_ssrf(t, a, o),
    "report":    lambda t, a, o: run_report(t, a, o),
    "all":       lambda t, a, o: run_all(t, a, o),
    "watch":     lambda t, a, o: run_watch(t, a, o),
}


class HelpFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawTextHelpFormatter):
    def _get_help_string(self, action):
        text = action.help or ""
        if ("%(default)" not in text and action.default not in (None, False, "", [])
                and action.default is not argparse.SUPPRESS):
            text += " (padrão: %(default)s)"
        return text


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return number


def _positive_float(value: str) -> float:
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return number


def _normalize_target(raw: str) -> str:
    if not raw or any(ch.isspace() for ch in raw):
        raise ValueError("target cannot be empty or contain whitespace")
    value = raw if "://" in raw else "http://" + raw
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("target must be an HTTP(S) URL, hostname or IP")
    if parsed.username or parsed.password:
        raise ValueError("credentials in --target are not allowed; use explicit auth options")
    if parsed.query or parsed.fragment:
        raise ValueError("--target must not contain a query string or fragment")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("target contains an invalid port") from exc
    return parsed.geturl().rstrip("/")


def build_parser() -> argparse.ArgumentParser:
    valid_modules = list(MODULE_REGISTRY.keys()) + ["all", "watch"]

    parser = argparse.ArgumentParser(
        prog="Buggy",
        description=(
            "Scanner modular para reconhecimento e validação de segurança web.\n"
            "Use somente em ativos próprios ou com autorização explícita. O perfil\n"
            "safe é o padrão e bloqueia requisições que alteram estado."
        ),
        epilog=(
            "Exemplos:\n"
            "  Buggy -t https://app.example.com -m recon\n"
            "  Buggy -t http://localhost:8000 -m all --skip-deps\n"
            "  Buggy -t https://app.example.com -m cve -o output/scan\n"
            "  Buggy -t https://app.example.com -m plan -o output/scan\n"
            "  Buggy -m execute -o output/scan\n"
            "  Buggy -m ui --ui-port 8787\n"
            "  Buggy -t https://app.example.com -m injection -o output/scan --profile standard\n"
            "  Buggy -m report -o output/scan\n\n"
            "Fluxo recomendado: recon -> surface -> cve -> plan -> execute -> report.\n"
            "Itens safe executam automaticamente; riscos maiores exigem approve.\n"
            "Use o mesmo -o ao executar fases separadas."
        ),
        formatter_class=HelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"Buggy {VERSION}")

    required = parser.add_argument_group("seleção")
    required.add_argument(
        "--target", "-t",
        metavar="TARGET",
        help="URL, domínio ou IP autorizado (dispensável em ui/report/approve/execute)",
    )
    required.add_argument(
        "--module", "-m",
        required=True,
        metavar="MODULE",
        choices=valid_modules,
        help=(
            "Módulo a executar:\n"
            + "\n".join(
                f"  {k:<12} {MODULE_REGISTRY[k]}"
                + ("  [ativo]" if k in IMPLEMENTED_MODULES else "  [em breve]")
                for k in MODULE_REGISTRY
    )
    + "\n  all          pipeline completo"
    + "\n  watch        pipeline periódico com delta"
),
    )

    scan = parser.add_argument_group("controle do scan")
    scan.add_argument("--profile", choices=("safe", "standard"), default="safe",
                      help="safe bloqueia POST/XML/JSON; standard habilita testes ativos")
    scan.add_argument("--threads", type=_positive_int, default=20,
                      help="máximo de workers concorrentes")
    scan.add_argument("--rate", type=_positive_float, default=10.0, metavar="REQ/S",
                      help="limite aproximado de requisições por segundo por cliente")
    scan.add_argument("--timeout", type=_positive_float, default=10.0, metavar="SECONDS",
                      help="timeout de cada requisição")
    scan.add_argument("--recursive", action="store_true", help="habilita dir busting recursivo")
    scan.add_argument("--max-depth", type=_positive_int, default=2, metavar="N",
                      help="profundidade máxima do dir busting recursivo")
    scan.add_argument("--wordlist", default="default.txt", help="arquivo de wordlist do recon")
    scan.add_argument("--output-dir", "-o", metavar="DIR",
                      help="diretório novo ou existente do scan")
    scan.add_argument(
        "--watch-interval",
        type=_positive_int,
        default=3600,
        metavar="SECONDS",
        help="intervalo do modo watch",
    )

    safety = parser.add_argument_group("escopo e segurança")
    safety.add_argument("--allow-host", action="append", default=[], metavar="HOST",
                        help="host adicional explicitamente autorizado (repetível)")
    safety.add_argument("--insecure", action="store_true",
                        help="desabilita validação TLS (somente laboratório)")
    safety.add_argument("--waf-bypass", action="store_true",
                        help="envia headers de spoofing/bypass (opt-in)")
    safety.add_argument(
        "--oob-host",
        default="",
        metavar="HOST",
        help="host OOB controlado por você para detecção blind SSRF",
    )
    runtime = parser.add_argument_group("execução")
    runtime.add_argument("--skip-deps", action="store_true", help="não verifica ferramentas externas")
    runtime.add_argument("--offline", action="store_true",
                         help="não consulta NVD/KEV/EPSS; usa somente cache local")
    runtime.add_argument("--refresh-intel", action="store_true",
                         help="ignora cache válido e atualiza fontes de inteligência")
    runtime.add_argument("--nuclei-templates", default="", metavar="DIR",
                         help="raiz local confiável dos templates Nuclei")
    runtime.add_argument("--nuclei-manifest", default="", metavar="FILE",
                         help="manifesto com caminhos e SHA-256 permitidos")
    runtime.add_argument("--approve-item", action="append", default=[], metavar="ITEM_ID",
                         help="item do plano a aprovar (repetível)")
    runtime.add_argument("--approved-by", default="", metavar="IDENTITY",
                         help="identidade responsável pela aprovação")
    runtime.add_argument("--approval-ttl", type=_positive_int, default=3600, metavar="SECONDS",
                         help="validade da aprovação")
    runtime.add_argument("--lab-mode", action="store_true",
                         help="permite validators lab-exploit somente contra alvo privado")
    runtime.add_argument("--ui-port", type=_positive_int, default=8787, metavar="PORT",
                         help="porta local da API/UI")
    runtime.add_argument("--install-missing", action="store_true",
                         help="tenta instalar dependências ausentes (pode solicitar sudo)")
    runtime.add_argument("--no-banner", action="store_true", help="oculta o banner")

    return parser


CYAN = "\033[96m"
BOLD_CYAN = "\033[1m\033[96m"


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.module == "ui":
        if args.ui_port > 65535:
            parser.error("--ui-port deve estar entre 1 e 65535")
        run_ui("", args, "")
        return

    local_modules = {"report", "approve", "execute"}
    if args.module in local_modules:
        if not args.output_dir:
            parser.error(f"o módulo {args.module} exige --output-dir com um scan existente")
        if not os.path.isdir(args.output_dir):
            parser.error(f"diretório de scan não encontrado: {args.output_dir}")
        if args.module in {"approve", "execute"}:
            plan_path = os.path.join(args.output_dir, "validation", "plan.json")
            if not os.path.isfile(plan_path):
                parser.error("validation/plan.json não encontrado; execute -m plan")
            with open(plan_path, encoding="utf-8") as plan_file:
                import json
                args.target = json.load(plan_file).get("target", "")
        else:
            args.target = args.target or ""
    else:
        if not args.target:
            parser.error("--target é obrigatório para este módulo")
        try:
            args.target = _normalize_target(args.target)
        except ValueError as exc:
            parser.error(str(exc))

    allowed_hosts = []
    for value in args.allow_host:
        candidate = value if "://" in value else "//" + value
        host = urllib.parse.urlparse(candidate).hostname
        if not host:
            parser.error(f"--allow-host inválido: {value!r}")
        allowed_hosts.append(host)

    if args.oob_host and not all(c.isalnum() or c in ".-:" for c in args.oob_host):
        parser.error("--oob-host deve conter apenas hostname/IP e porta opcionais")

    if not args.no_banner:
        print(banner)

    requested = args.module
    needs_recon_tools = requested in {"recon", "all", "watch"}
    target_host = urllib.parse.urlparse(args.target).hostname or ""
    is_local = target_host in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
    if needs_recon_tools and not is_local and not args.skip_deps:
        if not validate_requirements(RECON_TOOLS, args.install_missing):
            print(f"\n{RED}Aborting — missing required tools.{RESET}")
            sys.exit(1)

    if requested not in ("all", "watch") and requested not in IMPLEMENTED_MODULES:
        print(
            f"{YELLOW}[!] Module '{requested}' ({MODULE_REGISTRY[requested]}) "
            f"is not yet implemented.{RESET}"
        )
        sys.exit(0)

    runner = MODULE_RUNNERS.get(requested)
    if runner is None:
        print(f"{RED}[!] No runner found for module '{requested}'. This is a bug.{RESET}")
        sys.exit(1)

    if args.output_dir:
        output_dir = args.output_dir
        if requested not in local_modules:
            os.makedirs(output_dir, exist_ok=True)
    else:
        output_dir = create_output_structure(args.target)

    if requested not in local_modules:
        from modules.utils.http_client import configure_http
        configure_http(
            args.target,
            allowed_hosts=allowed_hosts,
            verify_tls=not args.insecure,
            waf_bypass=args.waf_bypass,
            active_tests=args.profile == "standard",
            max_rate=args.rate,
        )

    try:
        from modules.utils.logger import buggy_logger
        buggy_logger.setup_file_logging(output_dir)
    except ImportError:
        pass

    runner(args.target, args, output_dir)


if __name__ == "__main__":
    main()
