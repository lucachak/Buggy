import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse


def _sanitize_domain(raw: str) -> str:
    """Strip to safe characters only — no shell-special chars can survive."""
    return re.sub(r"[^a-zA-Z0-9.-]", "", raw)


# ── Safe command builders ──────────────────────────────────────────────────────
# Each returns a list of (is_shell: bool, cmd: str | list[str]) tuples.
# Shell-mode is kept ONLY for unavoidable pipelines (curl|jq|sort).
# In those cases the domain is always the already-sanitised value from
# _sanitize_domain(), never the raw user-supplied string.
# ──────────────────────────────────────────────────────────────────────────────

def _build_subdomain_cmds(domain: str, sub_dir: str) -> list:
    ct_out    = os.path.join(sub_dir, "ct-subs.txt")
    sf_out    = os.path.join(sub_dir, "subfinder-subs.txt")
    amass_dir = os.path.join(sub_dir, "amass-subs")
    pas_out   = os.path.join(sub_dir, "passive-subs.txt")
    all_out   = os.path.join(sub_dir, "all-subs.txt")
    amass_out = os.path.join(amass_dir, "amass.txt")

    crt_cmd = (
        f"curl -s 'https://crt.sh/?q=*.{domain}&output=json'"
        f" | jq -r '.[].name_value'"
        f" | sed 's/\\*\\.//g'"
        f" | sort -u > {ct_out}"
    )
    merge_cmd = (
        f"cat {ct_out} {sf_out} {amass_out} {pas_out} 2>/dev/null"
        f" | sort -u > {all_out}"
    )
    return [
        (True,  crt_cmd),
        (False, ["subfinder", "-d", domain, "-all", "-silent", "-o", sf_out]),
        (False, ["amass", "enum", "--passive", "-d", domain, "-dir", amass_dir]),
        (False, ["assetfinder", "-subs-only", domain], pas_out),  # stdout → file
        (True,  merge_cmd),
    ]


def _build_dns_resolution_cmds(subs_dir: str, dns_dir: str) -> list:
    all_subs = os.path.join(subs_dir, "all-subs.txt")
    resolved = os.path.join(dns_dir, "dnsx-resolved.txt")
    live_ips = os.path.join(dns_dir, "live-ips.txt")
    return [
        (False, ["dnsx", "-l", all_subs, "-a", "-aaaa", "-cname",
                 "-mx", "-txt", "-resp", "-o", resolved]),
        (False, ["dnsx", "-l", all_subs, "-a", "-resp-only", "-o", live_ips]),
    ]


def _build_origin_ip_cmds(domain: str) -> list:
    return [
        (False, ["curl", "-s",
                 f"https://securitytrails.com/domain/{domain}/history/a"]),
        (False, ["shodan", "search",
                 f"ssl.cert.subject.cn:{domain} http.title:{domain}"]),
        (False, ["shodan", "search", f"http.html:{domain}", "-org:Cloudflare"]),
    ]


class Discovery:
    """
    Recon pipeline: subdomain enum → DNS resolution → origin IP discovery
    → directory bruteforce.
    Writes recon/discovery_summary.json so SurfaceMapper can consume results.
    """

    def __init__(
        self,
        target: str = "http://localhost:8000/",
        user_agent: str = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0 Safari/537.36"
        ),
        proxy: dict | None = None,   # None = no proxy; pass dict to enable
        output_dir: str | None = None,
    ) -> None:
        # proxy=None means no proxy — the old default of localhost:missing-port
        # caused every request to fail silently.
        self.__target: str = target
        self.__user_agent: str = user_agent
        self.__proxy: dict | None = proxy

        self.__output_root = output_dir or "."
        self.__recon_dir      = os.path.join(self.__output_root, "recon")
        self.__subdomains_dir = os.path.join(self.__recon_dir, "subdomains")
        self.__dns_dir        = os.path.join(self.__recon_dir, "dns")
        self.__dirbust_dir    = os.path.join(self.__recon_dir, "dirbust")
        self.__reports_dir    = os.path.join(self.__output_root, "reports")
        self.__logs_dir       = os.path.join(self.__output_root, "logs")

        for d in [
            self.__subdomains_dir,
            self.__dns_dir,
            self.__dirbust_dir,
            self.__reports_dir,
            self.__logs_dir,
        ]:
            os.makedirs(d, exist_ok=True)

        self.__subdomains: list = []
        self.__endpoints: list  = []
        self.__pages: list      = []
        self.__params: list     = []
        self.__headers: dict    = {}
        self.__cookies: dict    = {}
        self.__auth             = None

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _banner(self, stage: str, color: str = "\033[96m") -> None:
        BOLD  = "\033[1m"
        RESET = "\033[0m"
        sep   = "─" * 60
        print(f"\n{color}{BOLD}{sep}")
        print(f"  {stage}")
        print(f"{sep}{RESET}")

    def _run_cmd(
        self,
        cmd: str | list,
        stdout_file: str | None = None,
    ) -> subprocess.CompletedProcess:
        """
        Run a command safely.
        - list cmd  → subprocess without shell (safe, preferred)
        - str  cmd  → shell=True (only for pipeline cmds with pre-sanitised domain)
        stdout_file: if given, write process stdout to that path (for tools that
                     don't support -o flags, e.g. assetfinder).
        """
        YELLOW = "\033[93m"
        RED    = "\033[91m"
        RESET  = "\033[0m"

        display = cmd if isinstance(cmd, str) else " ".join(cmd)
        print(f"{YELLOW}  ▶ {RESET}{display}")

        is_shell = isinstance(cmd, str)
        result = subprocess.run(
            cmd,
            shell=is_shell,
            text=True,
            capture_output=True,
        )

        if stdout_file and result.stdout:
            os.makedirs(os.path.dirname(stdout_file) or ".", exist_ok=True)
            with open(stdout_file, "w") as f:
                f.write(result.stdout)

        if result.stdout.strip() and not stdout_file:
            out = result.stdout.strip()
            if len(out) > 500:
                out = out[:500] + f"\n{YELLOW}  ... (truncated){RESET}"
            print(out)

        if result.returncode != 0 and result.stderr.strip():
            print(f"{RED}  [!] stderr: {result.stderr.strip()[:300]}{RESET}")

        return result

    def _extract_domain(self) -> str:
        parsed = urlparse(self.__target)
        host = parsed.hostname or self.__target
        host = re.sub(r"^www\.", "", host)
        return re.sub(r"[^a-zA-Z0-9.-]", "", host)

    def _is_local_target(self) -> bool:
        domain = self._extract_domain()
        local_names = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
        if domain in local_names:
            return True
        if re.match(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)", domain):
            return True
        return False

    def _find_dirpy_binary(self) -> str | None:
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
                ["curl", "-s", "https://ifconfig.me"],
                text=True,
                capture_output=True,
                timeout=5,
            )
            ip = r.stdout.strip()
            if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
                return ip
        except Exception:
            pass
        return "127.0.0.1"

    # ── Stage 1 — Subdomain Enumeration ──────────────────────────────────────

    def run_subdomain_enum(self) -> None:
        domain = _sanitize_domain(self._extract_domain())
        self._banner(f"[1/4] SUBDOMAIN ENUMERATION  →  {domain}", "\033[95m")
        t0 = time.time()

        if self._is_local_target():
            print("\033[93m  [i] Local/private target — skipping external subdomain enum.\033[0m")
            self.__subdomains = [domain]
            return

        sub_dir = self.__subdomains_dir
        cmds = _build_subdomain_cmds(domain, sub_dir)

        for entry in cmds:
            if len(entry) == 3:
                _, cmd, out_file = entry
                self._run_cmd(cmd, stdout_file=out_file)
            else:
                _, cmd = entry
                self._run_cmd(cmd)

        all_subs_path = os.path.join(sub_dir, "all-subs.txt")
        try:
            with open(all_subs_path) as f:
                subs = [line.strip() for line in f if line.strip()]
            self.__subdomains = subs
            print(f"\n\033[92m  [✔] {len(subs)} unique subdomains collected  ({time.time()-t0:.1f}s)\033[0m")
        except FileNotFoundError:
            print(f"  [!] {all_subs_path} not found — continuing with empty list")

    # ── Stage 2 — DNS Resolution ──────────────────────────────────────────────

    def run_dns_resolution(self) -> None:
        domain = _sanitize_domain(self._extract_domain())
        self._banner(f"[2/4] DNS RESOLUTION & ZONE TRANSFER  →  {domain}", "\033[96m")
        t0 = time.time()

        if self._is_local_target():
            print("\033[93m  [i] Local/private target — skipping DNS resolution.\033[0m")
            self.__endpoints = [domain]
            return

        cmds = _build_dns_resolution_cmds(self.__subdomains_dir, self.__dns_dir)
        for _, cmd in cmds:
            self._run_cmd(cmd)

        live_ips_path = os.path.join(self.__dns_dir, "live-ips.txt")
        try:
            with open(live_ips_path) as f:
                ips = [line.strip() for line in f if line.strip()]
            self.__endpoints = ips
            print(f"\n\033[92m  [✔] {len(ips)} live IPs found  ({time.time()-t0:.1f}s)\033[0m")
        except FileNotFoundError:
            print(f"  [!] {live_ips_path} not found — skipping IP harvest")

    # ── Stage 3 — Origin IP Discovery ────────────────────────────────────────

    def run_origin_ip_discovery(self) -> None:
        domain = _sanitize_domain(self._extract_domain())
        self._banner(f"[3/4] ORIGIN IP DISCOVERY  →  {domain}", "\033[93m")
        t0 = time.time()

        if self._is_local_target():
            print("\033[93m  [i] Local/private target — skipping origin IP discovery.\033[0m")
            self.__pages = []
            return

        origin_ips: list[str] = []
        cmds = _build_origin_ip_cmds(domain)

        for _, cmd in cmds:
            result = self._run_cmd(cmd)
            if result.stdout:
                found = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", result.stdout)
                origin_ips.extend(found)

        origin_ips = list(dict.fromkeys(origin_ips))
        self.__pages = origin_ips
        print(f"\n\033[92m  [✔] {len(origin_ips)} potential origin IPs identified  ({time.time()-t0:.1f}s)\033[0m")
        for ip in origin_ips:
            print(f"        {ip}")

    # ── Stage 4 — Directory Bruteforce ───────────────────────────────────────

    def run_dir_busting(
        self,
        wordlist: str = "default.txt",
        threads: int = 50,
        allowed_status: set | None = None,
        recursive: bool = False,
        timeout: float = 10.0,
    ) -> None:
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

        dirpy_bin = self._find_dirpy_binary()
        if dirpy_bin is None:
            print(f"{RED}  [!] Dirpy v2 binary not found.{RESET}")
            print(f"{YELLOW}  [i] Build:  cd modules/Reconnaissance/Dirpy && make build{RESET}")
            print(f"{YELLOW}  [i] Or set DIRPY_BIN env var.{RESET}")
            return

        print(f"{CYAN}  [i] Using binary: {dirpy_bin}{RESET}")

        base_dir = os.path.dirname(os.path.abspath(__file__))
        wordlist_paths = [
            os.path.join(base_dir, "Dirpy", "wordlist", wordlist),
            os.path.join(base_dir, "DirGO", "wordlist", wordlist),
            wordlist,
        ]
        wordlist_path = next((w for w in wordlist_paths if os.path.exists(w)), None)
        if wordlist_path is None:
            print(f"{RED}  [!] Wordlist not found: {wordlist}{RESET}")
            return

        with open(wordlist_path) as f:
            word_count = sum(1 for line in f if line.strip())
        print(f"{YELLOW}  ▶ {RESET}Wordlist: {wordlist}  ({word_count} words)  |  Threads: {threads}")

        scheme  = urlparse(self.__target).scheme or "https"
        targets = [self.__target.rstrip("/")]
        for sub in self.__subdomains:
            sub_url = f"{scheme}://{sub}".rstrip("/")
            if sub_url != self.__target.rstrip("/"):
                targets.append(sub_url)
        targets = list(dict.fromkeys(targets))

        all_found: list[str] = []

        for target_url in targets:
            print(f"\n{YELLOW}  ▶ {RESET}Busting: {BOLD}{target_url}{RESET}")
            safe_target  = target_url.replace("://", "_").replace(":", "-").replace("/", "_")
            json_filename = f"scan_{safe_target}.json"
            json_file     = os.path.join(self.__dirbust_dir, json_filename)

            cmd = [
                dirpy_bin,
                "-u", target_url,
                "-w", wordlist_path,
                "-t", str(threads),
                "--timeout", str(timeout),
                "--output-dir", self.__dirbust_dir,
                "--json", json_filename,
                "--silent",
            ]

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout * len(targets) + 60,
                )
                if result.stdout.strip():
                    print(result.stdout.strip())
                if result.stderr.strip():
                    for line in result.stderr.strip().split("\n")[:5]:
                        print(f"{RED}  {line}{RESET}")
            except subprocess.TimeoutExpired:
                print(f"{RED}  [!] Dirpy timed out on {target_url}{RESET}")
                continue
            except Exception as e:
                print(f"{RED}  [!] Error running Dirpy: {e}{RESET}")
                continue

            if os.path.exists(json_file):
                try:
                    with open(json_file) as f:
                        data = json.load(f)
                    for r in data.get("results", []):
                        url    = r.get("url", "")
                        status = r.get("status", 0)
                        redir  = r.get("redirect", "")
                        if status in allowed_status:
                            if status in {301, 302, 307, 308} and redir:
                                if redir.startswith("/"):
                                    redir = urljoin(target_url, redir)
                                all_found.append(redir)
                            else:
                                all_found.append(url)
                except json.JSONDecodeError:
                    print(f"{RED}  [!] Failed to parse Dirpy JSON: {json_file}{RESET}")

        self.__params = list(dict.fromkeys(all_found))
        elapsed = time.time() - t0
        print(f"\n{GREEN}  [✔] {len(self.__params)} paths across {len(targets)} target(s)  ({elapsed:.1f}s){RESET}")

    # ── Summary & Reporting ───────────────────────────────────────────────────

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

        sep  = "═" * 64
        tsep = "─" * 64
        lines = [
            sep,
            "  BUGGY RECON REPORT",
            f"  Target  : {summary['target']}",
            f"  Domain  : {domain}",
            f"  Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            sep, "",
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

        # ── Session handoff ──────────────────────────────────────────────────
        # SurfaceMapper._load_recon_data() reads recon/discovery_summary.json.
        # We write a stable flat file so the next pipeline stage always finds it,
        # regardless of the timestamped report filename.
        session_path = os.path.join(self.__recon_dir, "discovery_summary.json")
        session_data = {
            "meta": {
                "tool":        "Buggy",
                "target":      summary["target"],
                "domain":      domain,
                "timestamp":   timestamp,
                "report_json": json_path,
                "report_txt":  txt_path,
            },
            "subdomains":       summary.get("subdomains", []),
            "live_ips":         summary.get("live_ips", []),
            "resolved_ips":     summary.get("live_ips", []),   # alias Surface expects
            "origin_ips":       summary.get("origin_ips", []),
            "discovered_paths": summary.get("discovered_paths", []),
        }
        with open(session_path, "w") as f:
            json.dump(session_data, f, indent=2, default=str)
        # ────────────────────────────────────────────────────────────────────

        print(f"\n{GREEN}{BOLD}  📄  Report saved:{RESET}")
        print(f"      {CYAN}TXT     {RESET}→  {txt_path}")
        print(f"      {CYAN}JSON    {RESET}→  {json_path}")
        print(f"      {CYAN}SESSION {RESET}→  {session_path}")

        return txt_path, json_path

    # ── Pipeline executor ─────────────────────────────────────────────────────

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
        CYAN  = "\033[96m"
        RESET = "\033[0m"
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

    # ── Getters & Setters ─────────────────────────────────────────────────────

    def get_target(self) -> str:          return self.__target
    def get_user_agent(self) -> str:      return self.__user_agent
    def get_proxy(self) -> dict | None:   return self.__proxy
    def get_subdomains(self) -> list:     return self.__subdomains
    def get_endpoints(self) -> list:      return self.__endpoints
    def get_pages(self) -> list:          return self.__pages
    def get_params(self) -> list:         return self.__params
    def get_headers(self) -> dict:        return self.__headers
    def get_cookies(self) -> dict:        return self.__cookies
    def get_auth(self):                   return self.__auth

    def set_target(self, target: str) -> None:           self.__target = target
    def set_user_agent(self, ua: str) -> None:           self.__user_agent = ua
    def set_proxy(self, proxy: dict | None) -> None:     self.__proxy = proxy
    def set_subdomains(self, v: list) -> None:           self.__subdomains = v
    def set_endpoints(self, v: list) -> None:            self.__endpoints = v
    def set_pages(self, v: list) -> None:                self.__pages = v
    def set_params(self, v: list) -> None:               self.__params = v
    def set_headers(self, v: dict) -> None:              self.__headers = v
    def set_cookies(self, v: dict) -> None:              self.__cookies = v
    def set_auth(self, v) -> None:                       self.__auth = v