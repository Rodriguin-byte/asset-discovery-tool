"""
Módulo de enumeração de subdomínios - Versão Corrigida
Com suporte a max_retries
"""

import requests
import time
import random
from urllib.parse import urlparse
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

class SubdomainEnumerator:
    def __init__(self, domain, timeout=15, max_retries=3):  # <-- ADICIONAR max_retries AQUI
        self.domain = domain.lower()
        self.timeout = timeout
        self.max_retries = max_retries  # <-- GUARDAR O VALOR
        self.subdomains = set()
        
        # Configurar sessão com retry
        self.session = requests.Session()
        
        # Configurar retry strategy
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.9'
        })
    
    def query_crtsh(self):
        """Consulta crt.sh com retry"""
        print("  [*] Querying crt.sh...")
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        
        for attempt in range(self.max_retries):  # <-- USAR self.max_retries
            try:
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    data = response.json()
                    for entry in data:
                        name = entry.get('name_value', '').lower()
                        if '\n' in name:
                            for sub in name.split('\n'):
                                sub = sub.strip()
                                if sub.endswith(self.domain) and sub != self.domain:
                                    self.subdomains.add(sub)
                        else:
                            if name.endswith(self.domain) and name != self.domain:
                                self.subdomains.add(name)
                    
                    print(f"    → Found {len(self.subdomains)} subdomains")
                    return True
                    
            except requests.exceptions.Timeout:
                print(f"    [!] Timeout (attempt {attempt + 1}/{self.max_retries})")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
                    
            except Exception as e:
                print(f"    [!] Error: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
        
        return False
    
    def query_alienvault(self):
        """Consulta AlienVault com rate limit handling"""
        print("  [*] Querying AlienVault OTX...")
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        
        for attempt in range(self.max_retries):  # <-- USAR self.max_retries
            try:
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    data = response.json()
                    count_before = len(self.subdomains)
                    
                    for record in data.get('passive_dns', []):
                        hostname = record.get('hostname', '').lower()
                        if hostname.endswith(self.domain) and hostname != self.domain:
                            self.subdomains.add(hostname)
                    
                    new_found = len(self.subdomains) - count_before
                    print(f"    → Found {new_found} new subdomains")
                    return True
                    
                elif response.status_code == 429:
                    wait_time = 2 ** attempt + random.randint(1, 3)
                    print(f"    [!] Rate limited. Waiting {wait_time}s...")
                    time.sleep(wait_time)
                    
                else:
                    print(f"    [!] Returned status {response.status_code}")
                    if attempt < self.max_retries - 1:
                        time.sleep(2 ** attempt)
                    
            except Exception as e:
                print(f"    [!] Error: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
        
        return False
    
    def query_wayback(self):
        """Consulta Wayback Machine"""
        print("  [*] Querying Wayback Machine...")
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}&output=json&fl=original&collapse=urlkey"
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                count_before = len(self.subdomains)
                
                for item in data[1:]:
                    if item and len(item) > 0:
                        url_str = item[0].lower()
                        parsed = urlparse(url_str)
                        hostname = parsed.netloc or parsed.path.split('/')[0]
                        
                        if hostname.endswith(self.domain) and hostname != self.domain:
                            self.subdomains.add(hostname)
                
                new_found = len(self.subdomains) - count_before
                print(f"    → Found {new_found} new subdomains")
                return True
            else:
                print(f"    [!] Returned status {response.status_code}")
        except Exception as e:
            print(f"    [!] Error: {e}")
        
        return False
    
    def local_fallback(self):
        """Fallback local quando fontes online falham"""
        print("  [*] Using local fallback...")
        
        common_subs = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap',
            'test', 'blog', 'dev', 'admin', 'forum', 'news', 'vpn', 'mx',
            'support', 'mobile', 'static', 'docs', 'beta', 'shop', 'sql',
            'secure', 'demo', 'cp', 'calendar', 'wiki', 'web', 'media',
            'email', 'images', 'download', 'dns', 'api', 'app', 'stage',
            'prod', 'sandbox', 'develop', 'dashboard', 'portal', 'intranet'
        ]
        
        for sub in common_subs:
            self.subdomains.add(f"{sub}.{self.domain}")
        
        print(f"    → Generated {len(common_subs)} subdomains")
    
    def enumerate(self, sources=None):
        """Executa enumeração com fallback"""
        if sources is None:
            sources = ['crtsh', 'alienvault', 'wayback']
        
        any_success = False
        
        # Tentar cada fonte, mas continuar mesmo se alguma falhar
        for source in sources:
            try:
                if source == 'crtsh':
                    if self.query_crtsh():
                        any_success = True
                elif source == 'alienvault':
                    if self.query_alienvault():
                        any_success = True
                elif source == 'wayback':
                    if self.query_wayback():
                        any_success = True
                
                # Pequena pausa entre fontes
                time.sleep(1)
                
            except Exception as e:
                print(f"  [!] Source {source} failed: {e}")
                continue
        
        # Se nenhuma fonte online funcionou, usar fallback
        if not any_success and not self.subdomains:
            print("  [!] All online sources failed, using local fallback...")
            self.local_fallback()
        
        return sorted(list(self.subdomains))