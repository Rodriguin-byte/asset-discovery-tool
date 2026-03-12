"""
Módulo de deteção de tecnologias - Fase 2
Identifica frameworks, servidores e CMS
"""

import requests
import re
import json
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class TechnologyDetector:
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Fingerprints baseados em headers
        self.header_fingerprints = {
            'server': {
                'Apache': r'Apache(?:/(\d+\.\d+))?',
                'nginx': r'nginx(?:/(\d+\.\d+))?',
                'IIS': r'Microsoft-IIS(?:/(\d+\.\d+))?',
                'Cloudflare': r'cloudflare',
                'Amazon S3': r'AmazonS3',
            },
            'x-powered-by': {
                'PHP': r'PHP(?:/(\d+\.\d+))?',
                'ASP.NET': r'ASP\.NET',
                'Node.js': r'Express',
                'Python': r'Python|Django|Flask',
            }
        }
        
        # Fingerprints baseados em HTML
        self.html_fingerprints = {
            'WordPress': [
                r'wp-content',
                r'wp-includes',
                r'wordpress',
                r'WordPress',
            ],
            'Joomla': [
                r'joomla',
                r'Joomla',
                r'com_content',
            ],
            'Drupal': [
                r'drupal',
                r'Drupal',
                r'sites/all',
            ],
            'Magento': [
                r'magento',
                r'Magento',
                r'skin/frontend',
            ],
            'Shopify': [
                r'shopify',
                r'Shopify',
                r'myshopify\.com',
            ],
            'Wix': [
                r'wix',
                r'Wix',
                r'static\.wixstatic\.com',
            ],
        }
        
        # Fingerprints baseados em cookies
        self.cookie_fingerprints = {
            'PHP': r'PHPSESSID',
            'ASP.NET': r'ASP\.NET_SessionId',
            'JSF': r'JSESSIONID',
            'Laravel': r'laravel_session',
            'Django': r'django_',
            'Ruby on Rails': r'_session',
        }
    
    def detect_from_headers(self, headers):
        """Detecta tecnologias a partir dos headers HTTP"""
        detected = []
        
        for header, patterns in self.header_fingerprints.items():
            if header in headers:
                header_value = headers[header]
                for tech, pattern in patterns.items():
                    if re.search(pattern, header_value, re.IGNORECASE):
                        version = None
                        version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', header_value)
                        if version_match:
                            version = version_match.group(1)
                        
                        detected.append({
                            'technology': tech,
                            'source': 'header',
                            'header': header,
                            'version': version,
                            'evidence': header_value
                        })
        
        return detected
    
    def detect_from_html(self, html, base_url):
        """Detecta tecnologias a partir do HTML"""
        detected = []
        soup = BeautifulSoup(html, 'html.parser')
        
        # Verificar fingerprints HTML
        for tech, patterns in self.html_fingerprints.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    detected.append({
                        'technology': tech,
                        'source': 'html',
                        'pattern': pattern,
                        'confidence': 'medium'
                    })
                    break
        
        # Verificar meta tags
        meta_generator = soup.find('meta', attrs={'name': 'generator'})
        if meta_generator and meta_generator.get('content'):
            detected.append({
                'technology': 'CMS',
                'source': 'meta_generator',
                'version': meta_generator['content'],
                'confidence': 'high'
            })
        
        # Verificar scripts
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script['src']
            if 'jquery' in src.lower():
                version = re.search(r'jquery[/-](\d+\.\d+\.\d+)', src.lower())
                detected.append({
                    'technology': 'jQuery',
                    'source': 'script',
                    'version': version.group(1) if version else None,
                    'confidence': 'high'
                })
            elif 'bootstrap' in src.lower():
                detected.append({'technology': 'Bootstrap', 'source': 'script'})
            elif 'angular' in src.lower():
                detected.append({'technology': 'Angular', 'source': 'script'})
            elif 'react' in src.lower():
                detected.append({'technology': 'React', 'source': 'script'})
            elif 'vue' in src.lower():
                detected.append({'technology': 'Vue.js', 'source': 'script'})
        
        return detected
    
    def detect_from_cookies(self, cookies):
        """Detecta tecnologias a partir dos cookies"""
        detected = []
        
        for cookie in cookies:
            for tech, pattern in self.cookie_fingerprints.items():
                if re.search(pattern, cookie.name, re.IGNORECASE):
                    detected.append({
                        'technology': tech,
                        'source': 'cookie',
                        'cookie': cookie.name,
                        'confidence': 'high'
                    })
        
        return detected
    
    def analyze_url(self, url):
        """Analisa uma URL completa"""
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            
            technologies = []
            
            # Headers
            techs = self.detect_from_headers(response.headers)
            technologies.extend(techs)
            
            # HTML
            if 'text/html' in response.headers.get('Content-Type', ''):
                techs = self.detect_from_html(response.text, url)
                technologies.extend(techs)
            
            # Cookies
            techs = self.detect_from_cookies(response.cookies)
            technologies.extend(techs)
            
            return {
                'url': url,
                'status': response.status_code,
                'technologies': technologies,
                'server': response.headers.get('Server', 'Unknown'),
                'content_type': response.headers.get('Content-Type', 'Unknown')
            }
            
        except Exception as e:
            return {
                'url': url,
                'error': str(e),
                'technologies': []
            }
    
    def analyze_bulk(self, urls, threads=10):
        """Analisa múltiplas URLs"""
        from concurrent.futures import ThreadPoolExecutor
        
        results = []
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self.analyze_url, url): url for url in urls}
            
            for future in futures:
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result.get('technologies'):
                        print(f"\n[+] {result['url']}")
                        for tech in result['technologies']:
                            print(f"    → {tech['technology']} ({tech.get('version', 'unknown')})")
                except:
                    pass
        
        return results
    
    