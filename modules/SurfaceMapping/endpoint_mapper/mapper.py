import re
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Set, Optional
import logging

logger = logging.getLogger(__name__)


class EndpointMapper:
    """
    Mapeia endpoints não descobertos por bruteforce.
    Lê arquivos de configuração públicos que o servidor expõe.
    """
    
    # Paths conhecidos que revelam estrutura
    DISCOVERY_PATHS = [
        "robots.txt",
        "sitemap.xml",
        "sitemap_index.xml",
        "crossdomain.xml",
        "clientaccesspolicy.xml",
        ".well-known/security.txt",
        ".well-known/assetlinks.json",
        ".well-known/apple-app-site-association",
    ]
    
    def __init__(self, base_urls: List[str], discovered_paths: List[str], 
                 waf_detected: bool = False):
        self.base_urls = base_urls
        self.known_paths = set(discovered_paths)
        self.waf_detected = waf_detected
        self.endpoints: Set[str] = set()
        self.interesting_findings: List[Dict] = []
        
        # Headers que indicam rate limiting
        self.rate_limit_headers = [
            'retry-after', 'x-rate-limit-remaining', 
            'x-ratelimit-remaining', 'x-ratelimit-reset'
        ]
    
    def discover(self) -> Dict[str, any]:
        """
        Orquestra todas as descobertas.
        
        Returns:
            Dict com endpoints, arquivos sensíveis e metadados
        """
        logger.info(f"Starting endpoint discovery on {len(self.base_urls)} hosts")
        
        for base_url in self.base_urls[:10]:  # Limita hosts
            self._discover_host(base_url)
        
        # Filtra e categoriza
        categorized = self._categorize_endpoints()
        
        return {
            "endpoints": list(self.endpoints),
            "total_discovered": len(self.endpoints),
            "categorized": categorized,
            "interesting": self.interesting_findings,
            "discovery_sources": self._get_sources_used()
        }
    
    def _discover_host(self, base_url: str):
        """Descobre endpoints em um host específico."""
        for path in self.DISCOVERY_PATHS:
            url = urljoin(base_url, path)
            try:
                content = self._fetch_url(url)
                if content:
                    logger.debug(f"Found {path} at {base_url}")
                    
                    if "robots.txt" in path:
                        self._parse_robots(content, base_url)
                    elif "sitemap" in path:
                        self._parse_sitemap(content, base_url)
                    elif "crossdomain.xml" in path:
                        self._parse_crossdomain(content, base_url)
                    elif ".well-known" in path:
                        self._parse_well_known(content, base_url, path)
            
            except Exception as e:
                logger.debug(f"Error fetching {url}: {e}")
    
    def _fetch_url(self, url: str, timeout: int = 5) -> Optional[str]:
        """Busca conteúdo de URL com rate limiting awareness."""
        from urllib.request import Request, urlopen
        from urllib.error import URLError, HTTPError
        import ssl
        
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        
        try:
            req = Request(url, headers={
                "User-Agent": "Buggy/1.0 SurfaceMapper",
                "Accept": "text/plain,text/html,application/xml"
            })
            
            response = urlopen(req, timeout=timeout, context=ssl_ctx)
            
            # Detecta rate limiting
            for header in self.rate_limit_headers:
                if header in response.headers:
                    logger.warning(f"Rate limiting detected at {url}: {header}")
                    if self.waf_detected:
                        import time
                        time.sleep(2)  # Backoff se WAF presente
            
            content = response.read(1024 * 1024).decode('utf-8', errors='ignore')
            return content
            
        except HTTPError as e:
            if e.code == 403:
                # 403 em robots.txt é normal, não logamos como erro
                if "robots.txt" in url:
                    logger.debug(f"robots.txt returns 403 (common): {url}")
                else:
                    logger.debug(f"403 Forbidden: {url}")
            return None
        except Exception as e:
            logger.debug(f"Failed to fetch {url}: {e}")
            return None
    
    def _parse_robots(self, content: str, base_url: str):
        """
        Parse inteligente de robots.txt.
        Extrai Disallow (caminhos escondidos), Allow, Sitemap.
        """
        patterns = {
            'disallow': [],
            'allow': [],
            'sitemap': []
        }
        
        current_user_agent = None
        
        for line in content.split('\n'):
            line = line.strip().lower()
            
            # Ignora comentários e linhas vazias
            if not line or line.startswith('#'):
                continue
            
            # Detecta seção de user-agent
            if line.startswith('user-agent:'):
                current_user_agent = line.split(':', 1)[1].strip()
                continue
            
            # Só interessa regras para todos (*) ou user-agents principais
            if current_user_agent and current_user_agent not in ['*', 'googlebot', 'bingbot']:
                continue
            
            # Extrai regras
            if 'disallow' in line:
                path = line.split(':', 1)[1].strip()
                if path:
                    patterns['disallow'].append(path)
                    full_url = urljoin(base_url, path)
                    self.endpoints.add(full_url)
                    
                    # Disallow é ouro - são paths que o admin quer esconder
                    self.interesting_findings.append({
                        'type': 'robots_disallow',
                        'url': full_url,
                        'severity': 'high',
                        'description': 'Path explicitly hidden in robots.txt'
                    })
            
            elif 'allow' in line:
                path = line.split(':', 1)[1].strip()
                if path:
                    patterns['allow'].append(path)
            
            elif 'sitemap' in line:
                sitemap_url = line.split(':', 1)[1].strip()
                patterns['sitemap'].append(sitemap_url)
                # Busca sitemaps adicionais recursivamente
                sitemap_content = self._fetch_url(sitemap_url)
                if sitemap_content:
                    self._parse_sitemap(sitemap_content, base_url)
        
        logger.info(f"robots.txt at {base_url}: {len(patterns['disallow'])} disallowed paths")
    
    def _parse_sitemap(self, content: str, base_url: str):
        """
        Parse de sitemap.xml (normal e index).
        Extrai todas as URLs listadas.
        """
        try:
            # Remove namespaces para facilitar parsing
            content_clean = re.sub(r' xmlns="[^"]+"', '', content)
            root = ET.fromstring(content_clean)
            
            # Detecta se é sitemap index
            if root.tag == 'sitemapindex':
                for sitemap in root.findall('.//sitemap/loc'):
                    loc = sitemap.text.strip() if sitemap.text else None
                    if loc:
                        logger.debug(f"Found child sitemap: {loc}")
                        child_content = self._fetch_url(loc)
                        if child_content:
                            self._parse_sitemap(child_content, base_url)
            
            # Sitemap normal
            elif root.tag == 'urlset':
                for url_elem in root.findall('.//url/loc'):
                    url = url_elem.text.strip() if url_elem.text else None
                    if url:
                        self.endpoints.add(url)
                        
                        # Extrai informações adicionais
                        parent = url_elem.getparent() if hasattr(url_elem, 'getparent') else None
                        if parent is not None:
                            priority = parent.findtext('priority', '')
                            changefreq = parent.findtext('changefreq', '')
                            lastmod = parent.findtext('lastmod', '')
                            
                            if priority and float(priority) > 0.8:
                                self.interesting_findings.append({
                                    'type': 'sitemap_high_priority',
                                    'url': url,
                                    'priority': priority,
                                    'changefreq': changefreq,
                                    'description': f'High priority page (p={priority})'
                                })
            
            logger.info(f"Parsed sitemap: {len(self.endpoints)} URLs found")
            
        except ET.ParseError as e:
            logger.debug(f"XML parse error in sitemap: {e}")
        except Exception as e:
            logger.debug(f"Error parsing sitemap: {e}")
    
    def _parse_crossdomain(self, content: str, base_url: str):
        """
        Parse de crossdomain.xml (Flash policy file).
        Pode revelar domínios confiáveis e endpoints internos.
        """
        try:
            content_clean = re.sub(r' xmlns="[^"]+"', '', content)
            root = ET.fromstring(content_clean)
            
            # Domínios permitidos (possível SSRF)
            for allow in root.findall('.//allow-access-from'):
                domain = allow.get('domain', '')
                if domain and domain != '*':
                    self.interesting_findings.append({
                        'type': 'crossdomain_trusted',
                        'domain': domain,
                        'base_url': base_url,
                        'severity': 'medium',
                        'description': f'Trusted domain in crossdomain.xml: {domain}'
                    })
            
            # Endpoints permitidos
            for allow in root.findall('.//allow-http-request-headers-from'):
                headers = allow.get('headers', '')
                if headers:
                    self.interesting_findings.append({
                        'type': 'crossdomain_headers',
                        'headers': headers,
                        'description': 'Custom headers allowed in crossdomain.xml'
                    })
            
        except ET.ParseError:
            logger.debug("Invalid crossdomain.xml")
        except Exception as e:
            logger.debug(f"Error parsing crossdomain.xml: {e}")
    
    def _parse_well_known(self, content: str, base_url: str, path: str):
        """
        Parse de arquivos .well-known/.
        security.txt, assetlinks.json, etc.
        """
        if 'security.txt' in path:
            self._parse_security_txt(content, base_url)
        elif 'assetlinks.json' in path:
            self._parse_assetlinks(content, base_url)
    
    def _parse_security_txt(self, content: str, base_url: str):
        """Parse de security.txt (RFC 9116)."""
        for line in content.split('\n'):
            line = line.strip()
            if line.startswith('Contact:'):
                contact = line.split(':', 1)[1].strip()
                self.interesting_findings.append({
                    'type': 'security_contact',
                    'contact': contact,
                    'url': urljoin(base_url, '.well-known/security.txt'),
                    'severity': 'info',
                    'description': f'Security contact found: {contact}'
                })
            elif line.startswith('Policy:'):
                policy = line.split(':', 1)[1].strip()
                self.interesting_findings.append({
                    'type': 'security_policy',
                    'policy_url': policy,
                    'description': 'Security policy URL found'
                })
    
    def _parse_assetlinks(self, content: str, base_url: str):
        """Parse de assetlinks.json (Android App Links)."""
        import json
        try:
            data = json.loads(content)
            for item in data:
                if 'target' in item:
                    target = item['target']
                    if 'package_name' in target:
                        self.interesting_findings.append({
                            'type': 'android_app_link',
                            'package': target['package_name'],
                            'description': 'Android app linked to domain'
                        })
        except json.JSONDecodeError:
            logger.debug("Invalid assetlinks.json")
    
    def _categorize_endpoints(self) -> Dict[str, List[str]]:
        """Categoriza endpoints por tipo."""
        categories = {
            'admin_panels': [],
            'api_endpoints': [],
            'backup_files': [],
            'config_files': [],
            'login_pages': [],
            'uploads': [],
            'debug': []
        }
        
        patterns = {
            'admin_panels': [r'/(admin|wp-admin|administrator|panel|dashboard|manage)'],
            'api_endpoints': [r'/(api|graphql|rest|v[0-9]+/|swagger)'],
            'backup_files': [r'\.(bak|backup|old|save|zip|tar\.gz|sql)$'],
            'config_files': [r'/(\.env|config|wp-config|settings|\.git)'],
            'login_pages': [r'/(login|signin|auth|oauth|sso)'],
            'uploads': [r'/(uploads?|files?|media|assets?/images?)'],
            'debug': [r'/(debug|test|dev|staging|phpinfo|info)']
        }
        
        for endpoint in self.endpoints:
            for category, regex_list in patterns.items():
                for regex in regex_list:
                    if re.search(regex, endpoint, re.IGNORECASE):
                        categories[category].append(endpoint)
                        break
        
        return categories
    
    def _get_sources_used(self) -> List[str]:
        """Retorna quais fontes foram encontradas."""
        sources = []
        endpoints_str = ' '.join(self.endpoints)
        
        if 'robots.txt' in endpoints_str:
            sources.append('robots.txt')
        if 'sitemap' in endpoints_str:
            sources.append('sitemap.xml')
        if 'crossdomain.xml' in endpoints_str:
            sources.append('crossdomain.xml')
        if '.well-known' in endpoints_str:
            sources.append('.well-known/')
        
        return sources