"""
SurfaceMapper - Orquestrador do SurfaceMapping
Integrado ao pipeline Buggy.py
"""

import json
import logging
import os
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

# Importações relativas
from .utils import load_json, save_json, run_go_binary, make_request
from .endpoint_mapper.mapper import EndpointMapper
from .form_mapper.forms import FormMapper

logger = logging.getLogger(__name__)


class SurfaceMapper:
    """
    SurfaceMapper - Transforma dados brutos do Recon em inteligência acionável.
    
    Pipeline:
    1. Tech Detection (Go) - WAF, CMS, Frameworks
    2. Endpoint Mapper (Python) - robots.txt, sitemap, .well-known/
    3. JS Analyzer (Go) - Secrets, API keys, endpoints em JS
    4. Form Mapper (Python) - Formulários HTML, injection points
    5. API Discovery (Go) - Swagger, GraphQL, OpenAPI
    6. Port Scanner (Go) - Serviços expostos
    """
    
    def __init__(self, target: str, output_dir: str):
        """
        Args:
            target: Domínio alvo (ex: example.com)
            output_dir: Diretório de output do Buggy
        """
        self.target = target
        self.output_dir = Path(output_dir)
        
        # Cria subdiretórios específicos
        self.surface_dir = self.output_dir / "surface"
        self.surface_dir.mkdir(parents=True, exist_ok=True)
        
        # Diretório de binários Go
        self.bin_dir = Path(__file__).parent / "bin"
        
        # Resultados
        self.results = {
            "target": target,
            "timestamp": time.time(),
            "technologies": {},
            "endpoints": {},
            "js_secrets": {},
            "forms": {},
            "apis": {},
            "open_ports": {},
            "summary": {}
        }
        
        # Dados que serão populados pelo Recon
        self.base_urls = []
        self.paths = []
        self.hosts = []
        self.resolved_ips = []
        self.subdomains = []
        
        logger.info(f"SurfaceMapper initialized for {target}")
    
    def exec(self, threads: int = 50, recursive: bool = False, 
             timeout: float = 10.0, wordlist: str = "default.txt", **kwargs):
        """
        Executa o pipeline completo do SurfaceMapping.
        
        Args:
            threads: Número de threads (passado aos binários)
            recursive: Modo recursivo
            timeout: Timeout de requisições
            wordlist: Wordlist (não usado diretamente, mas mantido por compatibilidade)
        """
        print(f"\n{'='*60}")
        print(f"  SurfaceMapping Pipeline - {self.target}")
        print(f"{'='*60}\n")
        
        # Carrega dados do Recon se disponíveis
        self._load_recon_data()
        
        # Pipeline
        start_time = time.time()
        
        # 1. Tech Detection (Go)
        print(f"[1/6] 🔍 Tech Detection (WAF, CMS, Frameworks)...")
        self.results["technologies"] = self._run_tech_detection(threads, timeout)
        self._print_tech_summary()
        
        # 2. Endpoint Mapper (Python)
        print(f"\n[2/6] 🗺️  Endpoint Mapping (robots.txt, sitemap)...")
        self.results["endpoints"] = self._run_endpoint_mapper(timeout)
        self._print_endpoint_summary()
        
        # 3. JS Analyzer (Go)
        print(f"\n[3/6] 📜 JS Analysis (secrets, API keys)...")
        self.results["js_secrets"] = self._run_js_analyzer(threads, timeout)
        self._print_js_summary()
        
        # 4. Form Mapper (Python)
        print(f"\n[4/6] 📝 Form Mapping (injection points)...")
        self.results["forms"] = self._run_form_mapper(timeout)
        self._print_form_summary()
        
        # 5. API Discovery (Go)
        print(f"\n[5/6] 🚀 API Discovery (Swagger, GraphQL)...")
        self.results["apis"] = self._run_api_discoverer(threads, timeout)
        self._print_api_summary()
        
        # 6. Port Scanner (Go)
        print(f"\n[6/6] 🔌 Port Scanning (exposed services)...")
        self.results["open_ports"] = self._run_port_scanner(threads, timeout)
        self._print_port_summary()
        
        # Gera sumário
        self.results["summary"] = self._generate_summary()
        
        # Salva resultados
        self._save_results()
        
        elapsed = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"  ✅ SurfaceMapping Complete! ({elapsed:.1f}s)")
        print(f"{'='*60}")
        self._print_final_summary()
        
        return self.results
    
    def _load_recon_data(self):
        """Carrega dados do Recon se existirem."""
        recon_file = self.output_dir / "recon" / "discovery_summary.json"
        
        if recon_file.exists():
            recon_data = load_json(str(recon_file))
            self.base_urls = self._extract_base_urls(recon_data)
            self.paths = recon_data.get("discovered_paths", [])
            self.hosts = recon_data.get("live_ips", [])
            self.resolved_ips = recon_data.get("resolved_ips", [])
            self.subdomains = recon_data.get("subdomains", [])
            
            print(f"📂 Loaded Recon data: {len(self.base_urls)} URLs, "
                  f"{len(self.paths)} paths, {len(self.hosts)} hosts")
        else:
            # Modo standalone - constrói URLs básicas
            print(f"⚠️  No Recon data found, running in standalone mode")
            self.base_urls = [
                f"http://{self.target}",
                f"https://{self.target}",
                f"http://www.{self.target}",
                f"https://www.{self.target}"
            ]
    
    def _extract_base_urls(self, recon_data: Dict) -> List[str]:
        """Extrai URLs base dos dados do Recon."""
        urls = set()
        
        # De subdomínios
        for sub in recon_data.get("subdomains", []):
            if isinstance(sub, dict):
                domain = sub.get("domain") or sub.get("host", "")
            else:
                domain = str(sub)
            if domain:
                urls.add(f"https://{domain}")
                urls.add(f"http://{domain}")
        
        # De IPs
        for host in recon_data.get("live_ips", []):
            if isinstance(host, dict):
                ip = host.get("ip", "")
                port = host.get("port", "")
            else:
                ip = str(host)
                port = ""
            
            if ip:
                base = f"{ip}:{port}" if port else ip
                urls.add(f"http://{base}")
                urls.add(f"https://{base}")
        
        return list(urls)
    
    def _run_tech_detection(self, threads: int, timeout: float) -> Dict:
        """Executa Tech Detection via binário Go."""
        # Prepara input
        urls_file = self.surface_dir / "urls_to_scan.json"
        save_json(self.base_urls[:20], str(urls_file))  # Limita 20 URLs
        
        output_file = self.surface_dir / "tech_results.json"
        
        # Executa binário
        result = run_go_binary(
            str(self.bin_dir / "tech_detector"),
            [
                "-urls", str(urls_file),
                "-output", str(output_file),
                "-workers", str(min(threads, 30))
            ],
            timeout=timeout * 3
        )
        
        return result if result else {}
    
    def _run_endpoint_mapper(self, timeout: float) -> Dict:
        """Executa Endpoint Mapper em Python."""
        waf_detected = self.results.get("technologies", {}).get("summary", {}).get("waf_detected", False)
        
        mapper = EndpointMapper(
            self.base_urls[:10],  # Limita hosts
            self.paths,
            waf_detected=waf_detected
        )
        
        return mapper.discover()
    
    def _run_js_analyzer(self, threads: int, timeout: float) -> Dict:
        """Executa JS Analyzer via binário Go."""
        # Coleta URLs de JS dos endpoints descobertos
        js_urls = []
        endpoints_data = self.results.get("endpoints", {})
        all_endpoints = endpoints_data.get("endpoints", [])
        
        for endpoint in all_endpoints:
            if str(endpoint).endswith('.js'):
                js_urls.append(endpoint)
        
        if not js_urls:
            # Busca em paths comuns
            for base_url in self.base_urls[:5]:
                common_js = [
                    f"{base_url}/static/js/main.js",
                    f"{base_url}/js/app.js",
                    f"{base_url}/assets/js/bundle.js",
                ]
                js_urls.extend(common_js)
        
        js_urls = list(set(js_urls))[:30]  # Limita 30 arquivos
        
        if not js_urls:
            return {"results": [], "summary": {"total_files": 0, "total_secrets": 0}}
        
        # Prepara input
        js_file = self.surface_dir / "js_urls.json"
        save_json(js_urls, str(js_file))
        
        output_file = self.surface_dir / "js_results.json"
        
        # Executa binário
        result = run_go_binary(
            str(self.bin_dir / "js_analyzer"),
            [
                "-urls", str(js_file),
                "-output", str(output_file),
                "-workers", str(min(threads, 15))
            ],
            timeout=timeout * 5  # JS pode ser pesado
        )
        
        return result if result else {"results": [], "summary": {}}
    
    def _run_form_mapper(self, timeout: float) -> Dict:
        """Executa Form Mapper em Python."""
        endpoints_data = self.results.get("endpoints", {})
        all_endpoints = endpoints_data.get("endpoints", [])
        
        form_mapper = FormMapper(
            self.base_urls[:5],
            all_endpoints
        )
        
        return form_mapper.extract_forms()
    
    def _run_api_discoverer(self, threads: int, timeout: float) -> Dict:
        """Executa API Discovery via binário Go."""
        # Prepara input
        urls_file = self.surface_dir / "api_base_urls.json"
        save_json(self.base_urls[:10], str(urls_file))
        
        output_file = self.surface_dir / "api_results.json"
        
        # Executa binário
        result = run_go_binary(
            str(self.bin_dir / "api_discoverer"),
            [
                "-urls", str(urls_file),
                "-output", str(output_file),
                "-workers", str(min(threads, 20))
            ],
            timeout=timeout * 3
        )
        
        return result if result else {"results": [], "total_apis": 0}
    
    def _run_port_scanner(self, threads: int, timeout: float) -> Dict:
        """Executa Port Scanner via binário Go."""
        # Coleta todos os IPs
        all_ips = set()
        
        for host in self.hosts + self.resolved_ips:
            if isinstance(host, dict):
                ip = host.get("ip", "")
            else:
                ip = str(host)
            if ip:
                all_ips.add(ip)
        
        if not all_ips:
            # Fallback: resolve o target
            import socket
            try:
                ip = socket.gethostbyname(self.target)
                all_ips.add(ip)
            except:
                pass
        
        if not all_ips:
            return {}
        
        # Prepara input
        hosts_file = self.surface_dir / "hosts_to_scan.json"
        save_json(list(all_ips), str(hosts_file))
        
        output_file = self.surface_dir / "port_results.json"
        
        # Executa binário
        result = run_go_binary(
            str(self.bin_dir / "port_scanner"),
            [
                "-hosts", str(hosts_file),
                "-ports", "top100",
                "-timeout", str(int(timeout / 5)),  # Timeout por porta
                "-workers", str(min(threads, 30)),
                "-output", str(output_file)
            ],
            timeout=timeout * len(all_ips)  # Tempo proporcional aos hosts
        )
        
        # Converte array para dict
        if isinstance(result, list):
            port_dict = {}
            for host_result in result:
                host = host_result.get("host", "unknown")
                port_dict[host] = {
                    "open_ports": host_result.get("open_ports", []),
                    "services": host_result.get("services", {})
                }
            return port_dict
        
        return result if result else {}
    
    def _save_results(self):
        """Salva todos os resultados."""
        # Resultado completo
        final_file = self.surface_dir / "surface_mapping.json"
        save_json(self.results, str(final_file))
        
        # Sumário executivo
        summary_file = self.surface_dir / "summary.json"
        save_json(self.results["summary"], str(summary_file))
        
        # Dados para módulos de ataque
        attack_file = self.surface_dir / "attack_surface.json"
        save_json(self._export_for_attack_modules(), str(attack_file))
        
        print(f"\n📁 Results saved to: {self.surface_dir}/")
    
    def _export_for_attack_modules(self) -> Dict:
        """Exporta dados para módulos de ataque."""
        return {
            "injection_targets": {
                "forms": self.results.get("forms", {}).get("forms", []),
                "login_pages": self._filter_admin_endpoints(),
                "search_endpoints": self._filter_search_endpoints(),
            },
            "api_endpoints": self.results.get("apis", {}).get("results", []),
            "exposed_services": self._detect_exposed_databases(),
            "tech_context": {
                "cms": self.results.get("technologies", {}).get("summary", {}).get("all_cms", []),
                "waf": self.results.get("technologies", {}).get("summary", {}).get("waf_detected", False),
                "frameworks": self.results.get("technologies", {}).get("summary", {}).get("all_frameworks", []),
            },
            "js_secrets": self.results.get("js_secrets", {}).get("results", []),
        }
    
    def _filter_admin_endpoints(self) -> List[str]:
        """Filtra endpoints administrativos."""
        admin_kw = ["admin", "login", "dashboard", "wp-admin", "panel", "manage"]
        endpoints = self.results.get("endpoints", {}).get("endpoints", [])
        return [ep for ep in endpoints if any(kw in str(ep).lower() for kw in admin_kw)]
    
    def _filter_search_endpoints(self) -> List[str]:
        """Filtra endpoints de busca."""
        search_kw = ["search", "query", "find", "lookup", "filter"]
        endpoints = self.results.get("endpoints", {}).get("endpoints", [])
        return [ep for ep in endpoints if any(kw in str(ep).lower() for kw in search_kw)]
    
    def _detect_exposed_databases(self) -> List[str]:
        """Detecta bancos de dados expostos."""
        db_ports = {
            3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB",
            6379: "Redis", 9200: "Elasticsearch", 1433: "MSSQL", 1521: "Oracle"
        }
        
        exposed = []
        open_ports = self.results.get("open_ports", {})
        
        for host, data in open_ports.items():
            ports = data.get("open_ports", []) if isinstance(data, dict) else data
            for port in ports:
                if port in db_ports:
                    exposed.append(f"{host}:{port} ({db_ports[port]})")
        
        return exposed
    
    def _generate_summary(self) -> Dict:
        """Gera sumário executivo."""
        return {
            "target": self.target,
            "timestamp": time.time(),
            "attack_surface": {
                "total_endpoints": len(self.results.get("endpoints", {}).get("endpoints", [])),
                "total_forms": self.results.get("forms", {}).get("total_forms", 0),
                "total_apis": self.results.get("apis", {}).get("total_apis", 0),
                "js_secrets_found": self.results.get("js_secrets", {}).get("summary", {}).get("total_secrets", 0),
                "open_ports_count": sum(
                    len(data.get("open_ports", [])) if isinstance(data, dict) else len(data)
                    for data in self.results.get("open_ports", {}).values()
                )
            },
            "technologies": {
                "cms": self.results.get("technologies", {}).get("summary", {}).get("all_cms", []),
                "waf": self.results.get("technologies", {}).get("summary", {}).get("waf_detected", False),
                "waf_type": self.results.get("technologies", {}).get("summary", {}).get("waf_type", None),
                "frameworks": self.results.get("technologies", {}).get("summary", {}).get("all_frameworks", []),
                "servers": self.results.get("technologies", {}).get("summary", {}).get("all_servers", []),
            },
            "high_value_targets": {
                "admin_panels": self._filter_admin_endpoints(),
                "api_specs": self.results.get("apis", {}).get("openapi_specs", []),
                "graphql": self.results.get("apis", {}).get("graphqls", []),
                "exposed_dbs": self._detect_exposed_databases(),
            },
            "risk_indicators": {
                "waf_present": self.results.get("technologies", {}).get("summary", {}).get("waf_detected", False),
                "exposed_admin": len(self._filter_admin_endpoints()) > 0,
                "exposed_databases": len(self._detect_exposed_databases()) > 0,
                "js_secrets_leaked": self.results.get("js_secrets", {}).get("summary", {}).get("total_secrets", 0) > 0,
            }
        }
    
    # Métodos de exibição
    def _print_tech_summary(self):
        tech = self.results.get("technologies", {}).get("summary", {})
        if tech:
            print(f"  ├─ CMS: {', '.join(tech.get('all_cms', [])) or 'None'}")
            print(f"  ├─ WAF: {tech.get('waf_type') or 'None detected'}")
            print(f"  ├─ Frameworks: {', '.join(tech.get('all_frameworks', [])) or 'None'}")
            print(f"  └─ Servers: {', '.join(tech.get('all_servers', [])) or 'Unknown'}")
    
    def _print_endpoint_summary(self):
        ep = self.results.get("endpoints", {})
        print(f"  └─ Discovered: {len(ep.get('endpoints', []))} endpoints")
    
    def _print_js_summary(self):
        js = self.results.get("js_secrets", {}).get("summary", {})
        print(f"  ├─ Files analyzed: {js.get('total_files', 0)}")
        print(f"  └─ Secrets found: {js.get('total_secrets', 0)} ({js.get('high_severity', 0)} high/critical)")
    
    def _print_form_summary(self):
        forms = self.results.get("forms", {})
        print(f"  ├─ Forms found: {forms.get('total_forms', 0)}")
        print(f"  └─ Injection points: {len(forms.get('injection_points', []))}")
    
    def _print_api_summary(self):
        apis = self.results.get("apis", {})
        print(f"  ├─ APIs found: {apis.get('total_apis', 0)}")
        print(f"  └─ OpenAPI specs: {len(apis.get('openapi_specs', []))}")
    
    def _print_port_summary(self):
        ports = self.results.get("open_ports", {})
        total = sum(
            len(data.get("open_ports", [])) if isinstance(data, dict) else len(data)
            for data in ports.values()
        )
        exposed_dbs = self._detect_exposed_databases()
        print(f"  ├─ Open ports: {total}")
        print(f"  └─ Exposed databases: {len(exposed_dbs)}")
    
    def _print_final_summary(self):
        summary = self.results.get("summary", {})
        attack = summary.get("attack_surface", {})
        risk = summary.get("risk_indicators", {})
        
        print(f"\n{'='*60}")
        print(f"  EXECUTIVE SUMMARY")
        print(f"{'='*60}")
        print(f"  Attack Surface:")
        print(f"    • Endpoints: {attack.get('total_endpoints', 0)}")
        print(f"    • Forms: {attack.get('total_forms', 0)}")
        print(f"    • APIs: {attack.get('total_apis', 0)}")
        print(f"    • JS Secrets: {attack.get('js_secrets_found', 0)}")
        print(f"    • Open Ports: {attack.get('open_ports_count', 0)}")
        print(f"\n  Risk Indicators:")
        print(f"    • WAF: {'⚠️  Present' if risk.get('waf_present') else '✅ None'}")
        print(f"    • Admin exposed: {'⚠️  Yes' if risk.get('exposed_admin') else '✅ No'}")
        print(f"    • DB exposed: {'🔴 Yes!' if risk.get('exposed_databases') else '✅ No'}")
        print(f"    • JS leaks: {'🔴 Yes!' if risk.get('js_secrets_leaked') else '✅ No'}")
        print(f"{'='*60}")


# Função de entrada para o Buggy.py
def run_surface(target: str, args, output_dir: str) -> None:
    """
    Entry point chamado pelo Buggy.py.
    
    Args:
        target: Domínio alvo
        args: Argumentos do CLI
        output_dir: Diretório de output
    """
    mapper = SurfaceMapper(target=target, output_dir=output_dir)
    mapper.exec(
        threads=args.threads if hasattr(args, 'threads') else 50,
        recursive=args.recursive if hasattr(args, 'recursive') else False,
        timeout=args.timeout if hasattr(args, 'timeout') else 10.0,
        wordlist=args.wordlist if hasattr(args, 'wordlist') else "default.txt"
    )