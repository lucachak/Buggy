import subprocess
import sys
import os
import re
import shutil
import time
import json
from datetime import datetime
from urllib.parse import urlparse, urljoin


commands_dns_subdomain = [
    "curl -s 'https://crt.sh/?q=*.{0}&output=json' | jq -r '.[].name_value' | sed 's/\\*\\.//g' | sort -u > {1}/ct-subs.txt",
    "subfinder -d {0} -all -silent -o {1}/subfinder-subs.txt",
    "amass enum --passive -d {0} -dir {1}/amass-subs",
    "assetfinder -subs-only {0} > {1}/passive-subs.txt",
    "cat {1}/ct-subs.txt {1}/subfinder-subs.txt {1}/amass-subs/amass.txt {1}/passive-subs.txt 2>/dev/null | sort -u > {1}/all-subs.txt"
]

commands_dns_resolution = [
    "dnsx -l {0}/all-subs.txt -a -aaaa -cname -mx -txt -resp -o {0}/dnsx-resolved.txt",
    "dnsx -l {0}/all-subs.txt -a -resp-only -o {0}/live-ips.txt",
]

commands_origin_ip_discovery = [
    "curl -s https://securitytrails.com/domain/{}/history/a",
    "shodan search 'ssl.cert.subject.cn:{} http.title:{}'",
    "shodan search 'http.html:{}' -org:'Cloudflare'",
]


class Discovery:
    """ 
    this class is responsible for the discovery of subdomains and endpoints 
    """

    def __init__(self,
        target: str = "http://localhost:8000/",
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        proxy: dict | None = None,
        output_dir: str | None = None,
    ) -> None:
        if proxy is None:
            proxy = {"http": "http://127.0.0.1", "https": "http://127.0.0.1"}

        self.__target: str = target 
        self.__user_agent: str = user_agent
        self.__proxy: dict = proxy

        self.__output_root = output_dir or "."
        self.__recon_dir = os.path.join(self.__output_root, "recon")
        self.__subdomains_dir = os.path.join(self.__recon_dir, "subdomains")
        self.__dns_dir = os.path.join(self.__recon_dir, "dns")
        self.__dirbust_dir = os.path.join(self.__recon_dir, "dirbust")
        self.__reports_dir = os.path.join(self.__output_root, "reports")
        self.__logs_dir = os.path.join(self.__output_root, "logs")

        for d in [self.__subdomains_dir, self.__dns_dir, self.__dirbust_dir, self.__reports_dir, self.__logs_dir]:
            os.makedirs(d, exist_ok=True)

        self.__subdomains = []
        self.__endpoints = []
        self.__pages = []
        self.__params = []
        self.__headers = {}
        self.__cookies = {}
        self.__auth = None

    def _banner(self, stage: str, color: str = "\033[96m") -> None:
        BOLD  = "\033[1m"
        RESET = "\033[0m"
        sep   = "─" * 60
        print(f"\n{color}{BOLD}{sep}")
        print(f"  {stage}")
        print(f"{sep}{RESET}")

    def _run_cmd(self, cmd: str) -> subprocess.CompletedProcess:
        CYAN  = "\033[96m"
        YELLOW = "\033[93m"
        RED   = "\033[91m"
        RESET = "\033[0m"
        print(f"{YELLOW}  ▶ {RESET}{cmd}")
        result = subprocess.run(
            cmd,
            shell=True,
            text=True,
            capture_output=True
        )
        if result.stdout.strip():
            out = result.stdout.strip()
            if len(out) > 500:
                out = out[:500] + f"\n{YELLOW}  ... (truncated {len(out)} chars total){RESET}"
            print(out)
        if result.returncode != 0 and result.stderr.strip():
            print(f"{RED}  [!] stderr: {result.stderr.strip()[:300]}{RESET}")
        return result

    def _extract_domain(self) -> str:
        parsed = urlparse(self.__target)
        host = parsed.hostname or self.__target
        host = re.sub(r'^www\.', '', host)
        return re.sub(r'[^a-zA-Z0-9.-]', '', host)

    def _is_local_target(self) -> bool:
        """Check if target is localhost, loopback, or private IP — no external enum needed."""
        domain = self._extract_domain()
        local_names = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
        if domain in local_names:
            return True
        if re.match(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)', domain):
            return True
        return False

    def _find_dirpy_binary(self) -> str | None:
        """
        Locate the Dirpy v2 Go binary.
        Search order:
          1. DIRPY_BIN environment variable
          2. modules/Reconnaissance/Dirpy/DirGo
          3. modules/Reconnaissance/DirGO/DirGo
          4. PATH (just 'DirGo')
        """
        env_bin = os.environ.get("DIRPY_BIN")
        if env_bin and os.path.exists(env_bin):
            return env_bin

        base_dir = os.path.dirname(os.path.abspath(__file__))
        candidates = [
            os.path.join(base_dir, "Dirpy", "DirGo"),
            os.path.join(base_dir, "DirGO", "DirGo"),
        ]
        for c in candidates:
            if os.path.exists(c):
                return c

        if shutil.which("DirGo"):
            return "DirGo"

        return None

    def _get_own_ip(self) -> str:
        try:
            r = subprocess.run(
                "curl -s https://ifconfig.me",
                shell=True, text=True, capture_output=True, timeout=5
            )
            ip = r.stdout.strip()
            if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', ip):
                return ip
        except Exception:
            pass
        return "127.0.0.1"


    def run_subdomain_enum(self) -> None:
        domain = self._extract_domain()
        self._banner(f"[1/4] SUBDOMAIN ENUMERATION  →  {domain}", "\033[95m")
        t0 = time.time()

        if self._is_local_target():
            YELLOW = "\033[93m"
            RESET = "\033[0m"
            print(f"{YELLOW}  [i] Local/private target — skipping external subdomain enumeration.{RESET}")
            self.__subdomains = [domain]
            return

        sub_dir = self.__subdomains_dir

        for cmd in commands_dns_subdomain:
            formatted = cmd.format(domain, sub_dir)
            self._run_cmd(formatted)

        all_subs_path = os.path.join(sub_dir, "all-subs.txt")
        try:
            with open(all_subs_path) as f:
                subs = [line.strip() for line in f if line.strip()]
            self.__subdomains = subs
            GREEN = "\033[92m"
            RESET = "\033[0m"
            print(f"\n{GREEN}  [✔] {len(subs)} unique subdomains collected  ({time.time()-t0:.1f}s){RESET}")
        except FileNotFoundError:
            print(f"  [!] {all_subs_path} not found — continuing with empty list")

    def run_dns_resolution(self) -> None:
        domain = self._extract_domain()
        self._banner(f"[2/4] DNS RESOLUTION & ZONE TRANSFER  →  {domain}", "\033[96m")
        t0 = time.time()

        if self._is_local_target():
            YELLOW = "\033[93m"
            RESET = "\033[0m"
            print(f"{YELLOW}  [i] Local/private target — skipping DNS resolution.{RESET}")
            self.__endpoints = [domain]
            return

        dns_dir = self.__dns_dir

        for cmd in commands_dns_resolution:
            formatted = cmd.format(dns_dir)
            self._run_cmd(formatted)

        live_ips_path = os.path.join(dns_dir, "live-ips.txt")
        try:
            with open(live_ips_path) as f:
                ips = [line.strip() for line in f if line.strip()]
            self.__endpoints = ips
            GREEN = "\033[92m"
            RESET = "\033[0m"
            print(f"\n{GREEN}  [✔] {len(ips)} live IPs found  ({time.time()-t0:.1f}s){RESET}")
        except FileNotFoundError:
            print(f"  [!] {live_ips_path} not found — skipping IP harvest")

    # ─────────────────────────────────────────────
    # Stage 3 — Origin IP Discovery
    # ─────────────────────────────────────────────

    def run_origin_ip_discovery(self) -> None:
        domain = self._extract_domain()
        self._banner(f"[3/4] ORIGIN IP DISCOVERY  →  {domain}", "\033[93m")
        t0 = time.time()

        if self._is_local_target():
            YELLOW = "\033[93m"
            RESET = "\033[0m"
            print(f"{YELLOW}  [i] Local/private target — skipping origin IP discovery.{RESET}")
            self.__pages = []
            return

        origin_ips: list[str] = []

        for cmd in commands_origin_ip_discovery:
            placeholders = cmd.count("{}")
            if placeholders == 2:
                formatted = cmd.format(domain, domain)
            else:
                formatted = cmd.format(domain)

            result = self._run_cmd(formatted)

            if result.stdout:
                found = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', result.stdout)
                origin_ips.extend(found)

        origin_ips = list(dict.fromkeys(origin_ips)) 
        self.__pages = origin_ips

        GREEN = "\033[92m"
        RESET = "\033[0m"
        print(f"\n{GREEN}  [✔] {len(origin_ips)} potential origin IPs identified  ({time.time()-t0:.1f}s){RESET}")
        if origin_ips:
            for ip in origin_ips:
                print(f"        {ip}")

    def run_dir_busting(
        self,
        wordlist: str = "default.txt",
        threads: int = 50,
        allowed_status: set | None = None,
        recursive: bool = False,
        timeout: float = 10.0,
    ) -> None:
        """
        Stage 4 — Directory / endpoint bruteforcing (powered by Dirpy v2 Go binary).
        Runs against the primary target URL and every live subdomain found in Stage 1.
        """
        YELLOW = "\033[93m"
        GREEN  = "\033[92m"
        RED    = "\033[91m"
        BOLD   = "\033[1m"
        CYAN   = "\033[96m"
        RESET  = "\033[0m"

        if allowed_status is None:
            allowed_status = {200, 201, 301, 302, 403}

        self._banner("[4/4] DIRECTORY BRUTEFORCE  (Dirpy v2 Go)", "\033[35m")
        t0 = time.time()

        # Locate binary
        dirpy_bin = self._find_dirpy_binary()
        if dirpy_bin is None:
            print(f"{RED}  [!] Dirpy v2 binary not found.{RESET}")
            print(f"{YELLOW}  [i] Build it with:  cd modules/Reconnaissance/Dirpy && make build{RESET}")
            print(f"{YELLOW}  [i] Or set DIRPY_BIN environment variable.{RESET}")
            return

        print(f"{CYAN}  [i] Using binary: {dirpy_bin}{RESET}")

        # Find wordlist
        base_dir = os.path.dirname(os.path.abspath(__file__))
        wordlist_paths = [
            os.path.join(base_dir, "Dirpy", "wordlist", wordlist),
            os.path.join(base_dir, "DirGO", "wordlist", wordlist),
            wordlist,
        ]
        wordlist_path = None
        for w in wordlist_paths:
            if os.path.exists(w):
                wordlist_path = w
                break

        if wordlist_path is None:
            print(f"{RED}  [!] Wordlist not found: {wordlist}{RESET}")
            return

        with open(wordlist_path) as f:
            word_count = sum(1 for line in f if line.strip())
        print(f"{YELLOW}  ▶ {RESET}Wordlist: {wordlist}  ({word_count} words)  |  Threads: {threads}")

        # Build target list — avoid duplicates
        scheme = urlparse(self.__target).scheme or "https"
        targets: list[str] = [self.__target.rstrip("/")]
        for sub in self.__subdomains:
            sub_url = f"{scheme}://{sub}".rstrip("/")
            if sub_url != self.__target.rstrip("/"):
                targets.append(sub_url)
        targets = list(dict.fromkeys(targets))

        all_found: list[str] = []
        dirbust_dir = self.__dirbust_dir

        for target_url in targets:
            print(f"\n{YELLOW}  ▶ {RESET}Busting: {BOLD}{target_url}{RESET}")

            # Nome único pro JSON de output
            safe_target = target_url.replace("://", "_").replace(":", "-").replace("/", "_")
            json_filename = f"scan_{safe_target}.json"
            json_file = os.path.join(dirbust_dir, json_filename)

            cmd = [
                dirpy_bin,
                "-u", target_url,
                "-w", wordlist_path,
                "-t", str(threads),
                "--timeout", str(timeout),
                "--output-dir", dirbust_dir,
                "--json", json_filename,
                "--silent",
            ]

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout * len(targets) + 60
                )
                if result.stdout.strip():
                    print(result.stdout.strip())
                if result.stderr.strip():
                    stderr_lines = result.stderr.strip().split("\n")
                    for line in stderr_lines[:5]:
                        print(f"{RED}  {line}{RESET}")

            except subprocess.TimeoutExpired:
                print(f"{RED}  [!] Dirpy timed out on {target_url}{RESET}")
                continue
            except Exception as e:
                print(f"{RED}  [!] Error running Dirpy: {e}{RESET}")
                continue

            # Coleta resultados DESTE target
            if os.path.exists(json_file):
                try:
                    with open(json_file) as f:
                        data = json.load(f)
                    results = data.get("results", [])
                    for r in results:
                        url = r.get("url", "")
                        status = r.get("status", 0)
                        redirect = r.get("redirect", "")
                        if status in allowed_status:
                            if status in {301, 302, 307, 308} and redirect:
                                if redirect.startswith("/"):
                                    redirect = urljoin(target_url, redirect)
                                all_found.append(redirect)
                            else:
                                all_found.append(url)
                except json.JSONDecodeError:
                    print(f"{RED}  [!] Failed to parse Dirpy JSON output: {json_file}{RESET}")

        self.__params = list(dict.fromkeys(all_found))
        elapsed = time.time() - t0
        print(f"\n{GREEN}  [✔] {len(self.__params)} paths discovered across {len(targets)} target(s)  ({elapsed:.1f}s){RESET}")

    def GetSubdomains(self) -> list:
        return self.__subdomains

    def GetSummary(self) -> dict:
        return {
            "target":           self.__target,
            "domain":           self._extract_domain(),
            "subdomains":       self.__subdomains,
            "live_ips":         self.__endpoints,
            "origin_ips":       self.__pages,
            "discovered_paths": self.__params,
            "headers":          self.__headers,
            "cookies":          self.__cookies,
            "auth":             self.__auth,
        }

    def SaveReport(self, output_dir: str | None = None) -> tuple[str, str]:
        CYAN  = "\033[96m"
        GREEN = "\033[92m"
        BOLD  = "\033[1m"
        RESET = "\033[0m"

        summary   = self.GetSummary()
        domain    = summary["domain"]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"{domain}_recon_{timestamp}"

        reports_dir = output_dir or self.__reports_dir
        os.makedirs(reports_dir, exist_ok=True)
        txt_path  = os.path.join(reports_dir, base_name + ".txt")
        json_path = os.path.join(reports_dir, base_name + ".json")

        def _is_valid(v):
            if v is None:
                return False
            if isinstance(v, (list, dict)):
                return len(v) > 0
            return bool(str(v).strip())

        valid = {k: v for k, v in summary.items() if _is_valid(v)}

        sep   = "═" * 64
        tsep  = "─" * 64
        lines = [
            sep,
            f"  BUGGY RECON REPORT",
            f"  Target  : {summary['target']}",
            f"  Domain  : {domain}",
            f"  Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            sep,
            "",
        ]

        section_labels = {
            "subdomains":       "SUBDOMAINS",
            "live_ips":         "LIVE IPs  (DNS resolution)",
            "origin_ips":       "ORIGIN IPs  (CDN bypass)",
            "discovered_paths": "DISCOVERED PATHS  (dir-bust)",
            "headers":          "HTTP HEADERS",
            "cookies":          "COOKIES",
            "auth":             "AUTH",
        }

        for key, label in section_labels.items():
            val = valid.get(key)
            if val is None:
                continue
            lines.append(f"┌─ {label} ({'%d entries' % len(val) if isinstance(val, list) else 'captured'})")     
            lines.append(tsep)
            if isinstance(val, list):
                for item in val:
                    lines.append(f"  {item}")
            elif isinstance(val, dict):
                for k, v in val.items():
                    lines.append(f"  {k}: {v}")
            else:
                lines.append(f"  {val}")
            lines.append("")

        with open(txt_path, "w") as f:
            f.write("\n".join(lines))

        json_data = {
            "meta": {
                "tool":      "Buggy",
                "target":    summary["target"],
                "domain":    domain,
                "timestamp": timestamp,
            },
            "results": valid,
        }
        with open(json_path, "w") as f:
            json.dump(json_data, f, indent=2, default=str)

        print(f"\n{GREEN}{BOLD}  📄  Report saved:{RESET}")
        print(f"      {CYAN}TXT  {RESET}→  {txt_path}")
        print(f"      {CYAN}JSON {RESET}→  {json_path}")

        return txt_path, json_path


    def exec(
        self,
        dir_bust: bool = True,
        wordlist: str = "default.txt",
        threads: int = 50,
        recursive: bool = False,
        allowed_status: set | None = None,
        timeout: float = 10.0,
    ) -> dict:
        BOLD  = "\033[1m"
        GREEN = "\033[92m"
        RESET = "\033[0m"
        CYAN   = "\033[96m"
        domain = self._extract_domain()
        print(f"\n{BOLD}🔍  Buggy Recon  —  target: {domain}{RESET}")
        print(f"     {CYAN}Output: {self.__output_root}{RESET}")
        total_start = time.time()

        self.run_subdomain_enum()
        self.run_dns_resolution()
        self.run_origin_ip_discovery()
        if dir_bust:
            self.run_dir_busting(
                wordlist=wordlist,
                threads=threads,
                recursive=recursive,
                allowed_status=allowed_status,
                timeout=timeout,
            )

        elapsed = time.time() - total_start
        summary = self.GetSummary()

        print(f"\n{GREEN}{BOLD}  ✅  Recon complete in {elapsed:.1f}s{RESET}")
        print(f"       Subdomains      : {len(summary['subdomains'])}")
        print(f"       Live IPs        : {len(summary['live_ips'])}")
        print(f"       Origin IPs      : {len(summary['origin_ips'])}")
        print(f"       Paths found     : {len(summary['discovered_paths'])}\n")

        self.SaveReport()

        return summary


    def get_target(self) -> str: 
        return self.__target
    def get_user_agent(self) -> str:     
        return self.__user_agent
    def get_proxy(self) -> dict: 
        return self.__proxy
    def get_subdomains(self) -> list: 
        return self.__subdomains
    def get_endpoints(self) -> list: 
        return self.__endpoints
    def get_pages(self) -> list: 
        return self.__pages
    def get_params(self) -> list: 
        return self.__params
    def get_headers(self) -> dict: 
        return self.__headers
    def get_cookies(self) -> dict: 
        return self.__cookies
    def get_auth(self) -> any: 
        return self.__auth  

    def set_target(self, target: str) -> None: 
        self.__target = target
    def set_user_agent(self, user_agent: str) -> None: 
        self.__user_agent = user_agent
    def set_proxy(self, proxy: dict) -> None: 
        self.__proxy = proxy
    def set_subdomains(self, subdomains: list) -> None: 
        self.__subdomains = subdomains
    def set_endpoints(self, endpoints: list) -> None: 
        self.__endpoints = endpoints
    def set_pages(self, pages: list) -> None: 
        self.__pages = pages
    def set_params(self, params: list) -> None: 
        self.__params = params
    def set_headers(self, headers: dict) -> None: 
        self.__headers = headers
    def set_cookies(self, cookies: dict) -> None: 
        self.__cookies = cookies
    def set_auth(self, auth: any) -> None: 
        self.__auth = auth