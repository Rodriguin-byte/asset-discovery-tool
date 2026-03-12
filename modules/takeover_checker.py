"""
Módulo de verificação de subdomain takeover - Fase 4
Detecta subdomínios vulneráveis a takeover
"""

import dns.resolver
import requests
import json
import re

class TakeoverChecker:
    def __init__(self):
        self.fingerprints = self.load_fingerprints()
        
    def load_fingerprints(self):
        """Carrega fingerprints de serviços vulneráveis"""
        return {
            'github': {
                'cname': ['github.io', 'github.com'],
                'response': 'There isn\'t a GitHub Pages site here',
                'service': 'GitHub Pages'
            },
            'heroku': {
                'cname': ['herokudns.com', 'herokuapp.com'],
                'response': 'no such app',
                'service': 'Heroku'
            },
            'aws': {
                'cname': ['amazonaws.com', 's3.amazonaws.com'],
                'response': 'NoSuchBucket',
                'service': 'AWS S3'
            },
            'azure': {
                'cname': ['azurewebsites.net', 'trafficmanager.net'],
                'response': '404 Site Not Found',
                'service': 'Azure'
            },
            'cloudfront': {
                'cname': ['cloudfront.net'],
                'response': 'ERROR: The request could not be satisfied',
                'service': 'CloudFront'
            },
            'shopify': {
                'cname': ['myshopify.com'],
                'response': 'Sorry, this shop is currently unavailable',
                'service': 'Shopify'
            },
            'wordpress': {
                'cname': ['wordpress.com'],
                'response': 'Do you want to register',
                'service': 'WordPress.com'
            },
            'tumblr': {
                'cname': ['tumblr.com'],
                'response': 'Whatever you were looking for doesn\'t currently exist',
                'service': 'Tumblr'
            },
            'squarespace': {
                'cname': ['squarespace.com'],
                'response': 'No Such Account',
                'service': 'Squarespace'
            },
            'unbounce': {
                'cname': ['unbouncepages.com'],
                'response': 'The requested URL was not found',
                'service': 'Unbounce'
            },
            'readme': {
                'cname': ['readme.io'],
                'response': 'Project doesnt exist... yet!',
                'service': 'Readme.io'
            },
            'strikingly': {
                'cname': ['strikinglydns.com'],
                'response': 'page not found',
                'service': 'Strikingly'
            }
        }
    
    def check_cname(self, subdomain):
        """Verifica registros CNAME do subdomínio"""
        try:
            answers = dns.resolver.resolve(subdomain, 'CNAME')
            cname = str(answers[0]).lower().rstrip('.')
            return cname
        except:
            return None
    
    def check_http_response(self, url):
        """Verifica resposta HTTP para fingerprints de takeover"""
        try:
            response = requests.get(url, timeout=10, verify=False)
            text = response.text.lower()
            
            for service, fp in self.fingerprints.items():
                for pattern in fp.get('response_patterns', [fp.get('response', '')]):
                    if isinstance(pattern, str) and pattern.lower() in text:
                        return service, fp['service']
                    elif isinstance(pattern, re.Pattern) and pattern.search(text):
                        return service, fp['service']
            
            return None, None
        except requests.exceptions.ConnectionError:
            return None, None
        except Exception as e:
            return None, None
    
    def check_subdomain(self, subdomain):
        """Verifica se um subdomínio é vulnerável a takeover"""
        result = {
            'subdomain': subdomain,
            'vulnerable': False,
            'service': None,
            'cname': None,
            'evidence': None
        }
        
        # Verificar CNAME
        cname = self.check_cname(subdomain)
        if cname:
            result['cname'] = cname
            
            # Verificar se CNAME corresponde a algum serviço conhecido
            for service, fp in self.fingerprints.items():
                for fp_cname in fp.get('cname', []):
                    if fp_cname in cname:
                        # Verificar resposta HTTP
                        service_name, full_service = self.check_http_response(f"http://{subdomain}")
                        if service_name:
                            result['vulnerable'] = True
                            result['service'] = full_service or fp['service']
                            result['evidence'] = f"CNAME points to {cname} and service returns fingerprint"
                        break
        
        return result
    
    def check_bulk(self, subdomains):
        """Verifica múltiplos subdomínios"""
        results = []
        vulnerable = []
        
        for sub in subdomains:
            print(f"[*] Checking: {sub}")
            result = self.check_subdomain(sub)
            results.append(result)
            
            if result['vulnerable']:
                vulnerable.append(result)
                print(f"  {Fore.RED}[!] VULNERABLE: {sub} -> {result['service']}{Style.RESET_ALL}")
        
        return {
            'checked': len(results),
            'vulnerable': len(vulnerable),
            'results': vulnerable
        }
    