"""
FormMapper - Extrai formulários HTML das páginas descobertas.
Alimenta os módulos de Injection (SQLi, XSS, CSRF).
"""

import re
import logging
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional, Set
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import ssl

logger = logging.getLogger(__name__)


class FormExtractor(HTMLParser):
    """
    Parser HTML especializado em extrair formulários.
    Identifica campos, métodos, actions e campos ocultos.
    """
    
    def __init__(self):
        super().__init__()
        self.forms: List[Dict] = []
        self._current_form: Optional[Dict] = None
        self._current_field: Optional[Dict] = None
        self._in_form = False
        self._in_select = False
        self._select_options: List[str] = []
        
        # Campos que interessam para ataques
        self._relevant_tags = {'input', 'textarea', 'select', 'button'}
    
    def handle_starttag(self, tag: str, attrs: List[tuple]):
        attrs_dict = dict(attrs)
        
        if tag == 'form':
            self._in_form = True
            self._current_form = {
                'action': attrs_dict.get('action', ''),
                'method': attrs_dict.get('method', 'GET').upper(),
                'id': attrs_dict.get('id', ''),
                'class': attrs_dict.get('class', ''),
                'enctype': attrs_dict.get('enctype', 'application/x-www-form-urlencoded'),
                'fields': [],
                'has_file_upload': False,
                'has_csrf': False
            }
        
        elif self._in_form and tag in self._relevant_tags:
            if tag == 'input':
                input_type = attrs_dict.get('type', 'text').lower()
                field = {
                    'tag': 'input',
                    'type': input_type,
                    'name': attrs_dict.get('name', ''),
                    'id': attrs_dict.get('id', ''),
                    'value': attrs_dict.get('value', ''),
                    'placeholder': attrs_dict.get('placeholder', ''),
                    'required': 'required' in attrs_dict,
                    'disabled': 'disabled' in attrs_dict,
                    'readonly': 'readonly' in attrs_dict,
                }
                
                # Detecta campos especiais
                if input_type == 'hidden':
                    field['is_hidden'] = True
                    # CSRF detection
                    if any(csrf_name in field['name'].lower() 
                           for csrf_name in ['csrf', 'token', 'nonce', '_wpnonce']):
                        self._current_form['has_csrf'] = True
                        field['is_csrf'] = True
                
                elif input_type == 'file':
                    self._current_form['has_file_upload'] = True
                
                elif input_type in ('password', 'text', 'email', 'search'):
                    field['is_input_field'] = True
                
                elif input_type == 'submit':
                    field['is_submit'] = True
                
                self._current_form['fields'].append(field)
            
            elif tag == 'textarea':
                self._current_field = {
                    'tag': 'textarea',
                    'type': 'textarea',
                    'name': attrs_dict.get('name', ''),
                    'id': attrs_dict.get('id', ''),
                    'placeholder': attrs_dict.get('placeholder', ''),
                    'required': 'required' in attrs_dict,
                    'is_input_field': True
                }
                self._current_form['fields'].append(self._current_field)
            
            elif tag == 'select':
                self._in_select = True
                self._current_field = {
                    'tag': 'select',
                    'type': 'select',
                    'name': attrs_dict.get('name', ''),
                    'id': attrs_dict.get('id', ''),
                    'required': 'required' in attrs_dict,
                    'options': [],
                    'is_input_field': True
                }
                self._current_form['fields'].append(self._current_field)
            
            elif tag == 'button':
                self._current_form['fields'].append({
                    'tag': 'button',
                    'type': attrs_dict.get('type', 'submit'),
                    'name': attrs_dict.get('name', ''),
                    'is_submit': True
                })
    
    def handle_endtag(self, tag: str):
        if tag == 'form' and self._in_form:
            self._in_form = False
            if self._current_form:
                # Análise de risco do formulário
                self._analyze_form_risk()
                self.forms.append(self._current_form)
                self._current_form = None
        
        elif tag == 'select':
            self._in_select = False
    
    def handle_data(self, data: str):
        if self._in_select and self._current_field:
            option = data.strip()
            if option:
                self._current_field['options'].append(option)
    
    def _analyze_form_risk(self):
        """
        Análise de risco para priorização de ataques.
        """
        form = self._current_form
        risk_score = 0
        risk_factors = []
        
        # Login forms (alta prioridade)
        is_login = any(
            keyword in form.get('action', '').lower() or
            keyword in form.get('id', '').lower() or
            keyword in form.get('class', '').lower()
            for keyword in ['login', 'signin', 'auth', 'logon']
        )
        
        if is_login:
            risk_score += 10
            risk_factors.append('login_form')
        
        # Has password field
        has_password = any(
            f.get('type') == 'password' 
            for f in form.get('fields', [])
        )
        if has_password:
            risk_score += 8
            risk_factors.append('password_field')
        
        # No CSRF protection
        if not form.get('has_csrf', False):
            risk_score += 5
            risk_factors.append('no_csrf')
        
        # File upload
        if form.get('has_file_upload', False):
            risk_score += 7
            risk_factors.append('file_upload')
        
        # GET method (CSRF possible)
        if form.get('method') == 'GET':
            risk_score += 3
            risk_factors.append('get_method')
        
        # Many input fields (potential injection points)
        input_count = sum(1 for f in form.get('fields', []) 
                         if f.get('is_input_field', False))
        if input_count > 5:
            risk_score += 2
            risk_factors.append('many_inputs')
        
        form['risk_score'] = risk_score
        form['risk_factors'] = risk_factors
        form['risk_level'] = (
            'critical' if risk_score >= 20 else
            'high' if risk_score >= 15 else
            'medium' if risk_score >= 10 else
            'low'
        )


class FormMapper:
    """
    Mapeia formulários em páginas web.
    Alimenta módulos de Injection com alvos concretos.
    """
    
    def __init__(self, base_urls: List[str], endpoints: List[str]):
        self.base_urls = base_urls
        self.endpoints = endpoints
        self.all_forms: List[Dict] = []
        
        # Headers para simular navegador
        self.headers = {
            'User-Agent': 'Buggy/1.0 FormMapper',
            'Accept': 'text/html,application/xhtml+xml',
            'Accept-Language': 'en-US,en;q=0.9',
        }
    
    def extract_forms(self) -> Dict[str, any]:
        """
        Extrai formulários de todos os endpoints.
        
        Returns:
            Dict com formulários categorizados e análise de risco
        """
        logger.info(f"Extracting forms from {len(self.endpoints)} endpoints")
        
        # Prioriza endpoints que provavelmente têm formulários
        priority_endpoints = [
            ep for ep in self.endpoints
            if any(kw in str(ep).lower() for kw in [
                'login', 'signin', 'register', 'signup', 'auth',
                'contact', 'search', 'admin', 'checkout', 'payment',
                'profile', 'account', 'settings', 'upload'
            ])
        ]
        
        # Também verifica URLs base
        all_urls = set(self.base_urls + priority_endpoints + self.endpoints[:20])
        
        for url in list(all_urls)[:30]:  # Limita a 30 para não sobrecarregar
            try:
                forms = self._extract_from_url(url)
                if forms:
                    self.all_forms.extend(forms)
                    logger.debug(f"Found {len(forms)} form(s) at {url}")
            except Exception as e:
                logger.debug(f"Error extracting forms from {url}: {e}")
        
        # Categoriza e analisa
        categorized = self._categorize_forms()
        
        return {
            'total_forms': len(self.all_forms),
            'forms': self.all_forms,
            'categorized': categorized,
            'high_value_targets': self._get_high_value_targets(),
            'injection_points': self._get_injection_points(),
            'summary': self._generate_summary()
        }
    
    def _extract_from_url(self, url: str) -> List[Dict]:
        """Extrai formulários de uma URL específica."""
        try:
            # Fetch página
            req = Request(url, headers=self.headers)
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            
            response = urlopen(req, timeout=10, context=ssl_ctx)
            
            # Só processa HTML
            content_type = response.headers.get('Content-Type', '')
            if 'html' not in content_type.lower():
                return []
            
            html = response.read(1024 * 1024).decode('utf-8', errors='ignore')
            
            # Parse forms
            parser = FormExtractor()
            parser.feed(html)
            
            # Adiciona URL aos formulários
            for form in parser.forms:
                form['page_url'] = url
                form['form_url'] = urljoin(url, form['action']) if form['action'] else url
            
            return parser.forms
        
        except HTTPError as e:
            logger.debug(f"HTTP {e.code} for {url}")
            return []
        except Exception as e:
            logger.debug(f"Failed to fetch {url}: {e}")
            return []
    
    def _categorize_forms(self) -> Dict[str, List[Dict]]:
        """Categoriza formulários por tipo."""
        categories = {
            'login_forms': [],
            'search_forms': [],
            'contact_forms': [],
            'upload_forms': [],
            'registration_forms': [],
            'payment_forms': [],
            'other': []
        }
        
        for form in self.all_forms:
            action = form.get('action', '').lower()
            form_id = form.get('id', '').lower()
            form_class = form.get('class', '').lower()
            
            combined = f"{action} {form_id} {form_class}"
            
            if any(kw in combined for kw in ['login', 'signin', 'auth']):
                categories['login_forms'].append(form)
            elif any(kw in combined for kw in ['search', 'buscar', 'query']):
                categories['search_forms'].append(form)
            elif any(kw in combined for kw in ['contact', 'message', 'feedback']):
                categories['contact_forms'].append(form)
            elif form.get('has_file_upload'):
                categories['upload_forms'].append(form)
            elif any(kw in combined for kw in ['register', 'signup', 'create']):
                categories['registration_forms'].append(form)
            elif any(kw in combined for kw in ['payment', 'checkout', 'billing']):
                categories['payment_forms'].append(form)
            else:
                categories['other'].append(form)
        
        return categories
    
    def _get_high_value_targets(self) -> List[Dict]:
        """Retorna formulários de alto valor para bug bounty."""
        return [
            {
                'url': f['page_url'],
                'form_url': f['form_url'],
                'risk_level': f['risk_level'],
                'risk_factors': f['risk_factors'],
                'fields_count': len(f['fields']),
                'has_upload': f.get('has_file_upload', False),
                'has_csrf': f.get('has_csrf', False)
            }
            for f in self.all_forms
            if f.get('risk_level') in ('critical', 'high')
        ]
    
    def _get_injection_points(self) -> List[Dict]:
        """Lista todos os pontos de injeção encontrados."""
        injection_points = []
        
        for form in self.all_forms:
            for field in form.get('fields', []):
                if field.get('is_input_field') and not field.get('disabled'):
                    injection_points.append({
                        'url': form['form_url'],
                        'method': form.get('method', 'GET'),
                        'field_name': field.get('name'),
                        'field_type': field.get('type'),
                        'form_type': self._identify_form_type(form),
                        'risk_level': form.get('risk_level', 'low')
                    })
        
        return injection_points
    
    def _identify_form_type(self, form: Dict) -> str:
        """Identifica tipo de formulário para payloads específicos."""
        fields = form.get('fields', [])
        field_types = [f.get('type', '') for f in fields]
        field_names = ' '.join(f.get('name', '') for f in fields).lower()
        
        if 'password' in field_types:
            return 'login'
        elif any(kw in field_names for kw in ['search', 'query', 'q']):
            return 'search'
        elif 'file' in field_types:
            return 'upload'
        elif 'email' in field_types:
            return 'registration'
        elif 'textarea' in field_types:
            return 'comment'
        else:
            return 'generic'
    
    def _generate_summary(self) -> Dict:
        """Gera sumário executivo."""
        return {
            'total_forms': len(self.all_forms),
            'total_injection_points': len(self._get_injection_points()),
            'forms_by_risk': {
                'critical': len([f for f in self.all_forms if f.get('risk_level') == 'critical']),
                'high': len([f for f in self.all_forms if f.get('risk_level') == 'high']),
                'medium': len([f for f in self.all_forms if f.get('risk_level') == 'medium']),
                'low': len([f for f in self.all_forms if f.get('risk_level') == 'low'])
            },
            'csrf_protection': len([f for f in self.all_forms if f.get('has_csrf')]),
            'upload_forms': len([f for f in self.all_forms if f.get('has_file_upload')])
        }