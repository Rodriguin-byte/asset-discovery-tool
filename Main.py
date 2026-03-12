#!/usr/bin/env python3
"""
Asset Discovery Tool - Versão Completa e Otimizada
Descobre e analisa todos os ativos digitais de um domínio
"""

import os
import sys
import argparse
import json
import time
import re
import socket
import warnings
import urllib3
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style

# Desabilitar warnings de SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', category=urllib3.exceptions.InsecureRequestWarning)

# Importar módulos (com tratamento de erro)
try:
    from modules.subdomain import SubdomainEnumerator
    from modules.dns_utils import DNSResolver
    from modules.bruteforce import SubdomainBruteforcer
    from modules.tech_detector import TechnologyDetector
    from modules.port_scanner import PortScanner
    from modules.screenshotter import Screenshotter
    from modules.takeover_checker import TakeoverChecker
    from utils.report_generator import ReportGenerator
    MODULES_LOADED = True
except ImportError as e:
    print(f"{Fore.RED}[!] Erro ao importar módulos: {e}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] Certifica-te que todos os módulos estão nas pastas corretas{Style.RESET_ALL}")
    MODULES_LOADED = False

# Inicializar colorama
init(autoreset=True)

class AssetDiscoveryTool:
    def __init__(self, config=None):
        self.version = "3.0.0"
        self.start_time = None
        
        # Configuração padrão otimizada
        self.config = {
            'general': {
                'timeout': 30,              # Aumentado para 30 segundos
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'max_threads': 50,
                'output_dir': './output'
            },
            'bruteforce': {
                'enabled': True,
                'wordlists': {
                    'small': './wordlists/common.txt',
                    'medium': './wordlists/subdomains.txt'
                },
                'max_requests_per_second': 100
            },
            'tech_detection': {
                'enabled': True
            },
            'port_scan': {
                'enabled': True,
                'common_ports': [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443],
                'timeout': 3                  # Aumentado para 3 segundos
            },
            'screenshots': {
                'enabled': False,             # Desativado por padrão para evitar erros
                'width': 1280,
                'height': 720,
                'timeout': 30,
                'output_dir': './output/screenshots'
            },
            'takeover': {
                'enabled': True
            }
        }
        
        self.results = {
            'target': '',
            'timestamp': '',
            'subdomains': [],
            'resolved': {},
            'technologies': [],
            'open_ports': [],
            'screenshots': [],
            'vulnerabilities': [],
            'statistics': {}
        }
    
    def print_banner(self):
        """Mostra banner da ferramenta"""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
║                                                      ║
║   {Fore.YELLOW}⚡ Asset Discovery Tool v{self.version}{Fore.CYAN}                    ║
║   {Fore.GREEN}Complete Digital Asset Discovery Framework{Fore.CYAN}               ║
║                                                      ║
║   {Fore.WHITE}Fase 1: {Fore.GREEN}Passive Enumeration ✓{Fore.CYAN}                    ║
║   {Fore.WHITE}Fase 2: {Fore.GREEN}Bruteforce & Tech Detection ✓{Fore.CYAN}           ║
║   {Fore.WHITE}Fase 3: {Fore.GREEN}Port Scanning & Screenshots ✓{Fore.CYAN}           ║
║   {Fore.WHITE}Fase 4: {Fore.GREEN}Takeover Detection & Reporting ✓{Fore.CYAN}        ║
║                                                      ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)
    
    def normalize_domain(self, input_domain):
        """Normaliza formato do domínio"""
        if not input_domain:
            return None
        
        # Remover protocolo
        domain = input_domain.lower().strip()
        domain = domain.replace('http://', '').replace('https://', '')
        domain = domain.replace('www.', '')
        
        # Remover caminhos e parâmetros
        if '/' in domain:
            domain = domain.split('/')[0]
        if '?' in domain:
            domain = domain.split('?')[0]
        if ':' in domain:
            domain = domain.split(':')[0]
        
        return domain
    
    def validate_domain(self, domain):
        """Valida formato do domínio"""
        if not domain:
            return False
        
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if re.match(pattern, domain):
            return True
        
        print(f"{Fore.YELLOW}[!] Domínio '{domain}' pode ser inválido{Style.RESET_ALL}")
        return False
    
    def check_domain_exists(self, domain):
        """Verifica se o domínio existe através de DNS"""
        try:
            socket.gethostbyname(domain)
            return True
        except:
            return False
    
    def check_wordlists(self):
        """Verifica se as wordlists existem e cria se necessário"""
        wordlist_paths = [
            self.config['bruteforce']['wordlists']['small'],
            self.config['bruteforce']['wordlists']['medium']
        ]
        
        for path in wordlist_paths:
            if not os.path.exists(path):
                print(f"{Fore.YELLOW}[!] Wordlist não encontrada: {path}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[!] A criar wordlist mínima...{Style.RESET_ALL}")
                
                # Criar diretório se não existir
                os.makedirs(os.path.dirname(path), exist_ok=True)
                
                # Criar wordlist com subdomínios comuns
                common_subs = [
                    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1',
                    'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap',
                    'test', 'blog', 'dev', 'admin', 'forum', 'news', 'vpn', 'mx',
                    'support', 'mobile', 'static', 'docs', 'beta', 'shop', 'sql',
                    'secure', 'demo', 'cp', 'calendar', 'wiki', 'web', 'media',
                    'email', 'images', 'download', 'dns', 'api', 'app', 'stage',
                    'prod', 'sandbox', 'develop', 'dashboard', 'portal', 'intranet'
                ]
                
                with open(path, 'w') as f:
                    for word in common_subs:
                        f.write(f"{word}\n")
                
                print(f"{Fore.GREEN}[✓] Wordlist criada: {path}{Style.RESET_ALL}")
    
    def phase1_passive_enum(self, domain):
        """Fase 1: Enumeração passiva"""
        print(f"\n{Fore.CYAN}{Style.BRIGHT}[+] Phase 1: Passive Enumeration{Style.RESET_ALL}")
        
        try:
            enumerator = SubdomainEnumerator(domain, timeout=20, max_retries=3)
            subdomains = enumerator.enumerate()
            
            if subdomains:
                print(f"{Fore.GREEN}[✓] Found {len(subdomains)} subdomains via passive sources{Style.RESET_ALL}")
                for sub in subdomains[:10]:  # Mostrar apenas os primeiros 10
                    print(f"  → {sub}")
                if len(subdomains) > 10:
                    print(f"  → ... e mais {len(subdomains) - 10}")
                
                self.results['subdomains'].extend([{'name': s, 'source': 'passive'} for s in subdomains])
                return subdomains
            else:
                print(f"{Fore.YELLOW}[!] No subdomains found via passive sources{Style.RESET_ALL}")
                return []
                
        except Exception as e:
            print(f"{Fore.RED}[!] Error in passive enumeration: {e}{Style.RESET_ALL}")
            return []
    
    def phase2_bruteforce(self, domain):
        """Fase 2: Brute-force"""
        print(f"\n{Fore.CYAN}{Style.BRIGHT}[+] Phase 2: Active Bruteforce{Style.RESET_ALL}")
        
        if not self.config['bruteforce']['enabled']:
            print(f"{Fore.YELLOW}[!] Bruteforce disabled{Style.RESET_ALL}")
            return []
        
        wordlist_path = self.config['bruteforce']['wordlists']['medium']
        
        try:
            bruteforcer = SubdomainBruteforcer(
                domain=domain,
                threads=self.config['general']['max_threads'],
                timeout=self.config['general']['timeout'],
                wordlist_path=wordlist_path
            )
            
            found = bruteforcer.brute_force()
            
            if found:
                print(f"{Fore.GREEN}[✓] Found {len(found)} subdomains via bruteforce{Style.RESET_ALL}")
                for f in found[:10]:
                    print(f"  → {f['subdomain']} (HTTP {f['status']})")
                
                for f in found:
                    self.results['subdomains'].append({
                        'name': f['subdomain'],
                        'status': f['status'],
                        'source': 'bruteforce',
                        'url': f['url']
                    })
                
                return [f['subdomain'] for f in found]
            else:
                print(f"{Fore.YELLOW}[!] No subdomains found via bruteforce{Style.RESET_ALL}")
                return []
                
        except Exception as e:
            print(f"{Fore.RED}[!] Error in bruteforce: {e}{Style.RESET_ALL}")
            return []
    
    def phase2_tech_detection(self, urls):
        """Fase 2: Deteção de tecnologias"""
        print(f"\n{Fore.CYAN}{Style.BRIGHT}[+] Phase 2: Technology Detection{Style.RESET_ALL}")
        
        if not self.config['tech_detection']['enabled']:
            print(f"{Fore.YELLOW}[!] Tech detection disabled{Style.RESET_ALL}")
            return []
        
        if not urls:
            print(f"{Fore.YELLOW}[!] No URLs to analyze{Style.RESET_ALL}")
            return []
        
        try:
            detector = TechnologyDetector(timeout=self.config['general']['timeout'])
            results = detector.analyze_bulk(urls[:20])  # Limitar a 20 URLs
            
            tech_count = 0
            for result in results:
                if result.get('technologies'):
                    tech_count += len(result['technologies'])
                    self.results['technologies'].append(result)
            
            print(f"{Fore.GREEN}[✓] Analyzed {len(results)} URLs, found {tech_count} technologies{Style.RESET_ALL}")
            return results
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error in tech detection: {e}{Style.RESET_ALL}")
            return []
    
    def phase3_port_scan(self, hosts):
        """Fase 3: Scanner de portas"""
        print(f"\n{Fore.CYAN}{Style.BRIGHT}[+] Phase 3: Port Scanning{Style.RESET_ALL}")
        
        if not self.config['port_scan']['enabled']:
            print(f"{Fore.YELLOW}[!] Port scanning disabled{Style.RESET_ALL}")
            return []
        
        if not hosts:
            print(f"{Fore.YELLOW}[!] No hosts to scan{Style.RESET_ALL}")
            return []
        
        try:
            scanner = PortScanner(
                timeout=self.config['port_scan']['timeout'],
                threads=self.config['general']['max_threads']
            )
            
            # Limitar a 10 hosts para não sobrecarregar
            hosts_to_scan = hosts[:10]
            scanner.scan_hosts(hosts_to_scan, self.config['port_scan']['common_ports'])
            open_ports = scanner.get_open_ports_summary()
            
            if open_ports:
                self.results['open_ports'] = open_ports
                print(f"{Fore.GREEN}[✓] Found {len(open_ports)} open ports across {len(hosts_to_scan)} hosts{Style.RESET_ALL}")
                
                # Mostrar alguns exemplos
                for port in open_ports[:10]:
                    print(f"  → {port['host']}:{port['port']} - {port['service']}")
            else:
                print(f"{Fore.YELLOW}[!] No open ports found{Style.RESET_ALL}")
            
            return open_ports
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error in port scanning: {e}{Style.RESET_ALL}")
            return []
    
    def phase3_screenshots(self, urls):
        """Fase 3: Captura de screenshots (opcional)"""
        if not self.config['screenshots']['enabled']:
            return []
        
        print(f"\n{Fore.CYAN}{Style.BRIGHT}[+] Phase 3: Screenshots{Style.RESET_ALL}")
        
        try:
            screenshotter = Screenshotter(
                output_dir=self.config['screenshots']['output_dir'],
                width=self.config['screenshots']['width'],
                height=self.config['screenshots']['height'],
                timeout=self.config['screenshots']['timeout']
            )
            
            screenshots = screenshotter.take_bulk_screenshots(urls[:5])  # Apenas 5 screenshots
            screenshotter.close()
            
            if screenshots:
                self.results['screenshots'] = screenshots
                print(f"{Fore.GREEN}[✓] Captured {len(screenshots)} screenshots{Style.RESET_ALL}")
            
            return screenshots
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error in screenshots: {e}{Style.RESET_ALL}")
            return []
    
    def phase4_takeover_check(self, subdomains):
        """Fase 4: Verificação de subdomain takeover"""
        print(f"\n{Fore.CYAN}{Style.BRIGHT}[+] Phase 4: Subdomain Takeover Check{Style.RESET_ALL}")
        
        if not self.config['takeover']['enabled']:
            print(f"{Fore.YELLOW}[!] Takeover check disabled{Style.RESET_ALL}")
            return []
        
        if not subdomains:
            print(f"{Fore.YELLOW}[!] No subdomains to check{Style.RESET_ALL}")
            return []
        
        try:
            checker = TakeoverChecker()
            results = checker.check_bulk(subdomains[:30])  # Limitar a 30 subdomínios
            
            if results['vulnerable'] > 0:
                for vuln in results['results']:
                    self.results['vulnerabilities'].append({
                        'type': 'SUBDOMAIN_TAKEOVER',
                        'target': vuln['subdomain'],
                        'risk': 'HIGH',
                        'description': f"Vulnerable to takeover via {vuln['service']} (CNAME: {vuln['cname']})"
                    })
                
                print(f"{Fore.RED}[!] Found {results['vulnerable']} vulnerable subdomains!{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[✓] No vulnerable subdomains found{Style.RESET_ALL}")
            
            return results
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error in takeover check: {e}{Style.RESET_ALL}")
            return []
    
    def generate_final_report(self):
        """Gera relatório final"""
        print(f"\n{Fore.CYAN}{Style.BRIGHT}[+] Generating Final Report{Style.RESET_ALL}")
        
        # Calcular estatísticas
        resolved_count = len([s for s in self.results['subdomains'] if s.get('ip')])
        
        self.results['statistics'] = {
            'total_subdomains': len(self.results['subdomains']),
            'resolved_hosts': resolved_count,
            'technologies_detected': sum(len(t.get('technologies', [])) for t in self.results.get('technologies', [])),
            'open_ports': len(self.results.get('open_ports', [])),
            'vulnerabilities': len(self.results.get('vulnerabilities', []))
        }
        
        # Criar diretórios de output
        os.makedirs('./output/scans', exist_ok=True)
        
        # Salvar JSON
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_file = f"./output/scans/full_report_{timestamp}.json"
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"{Fore.GREEN}[✓] JSON report saved: {json_file}{Style.RESET_ALL}")
        
        # Tentar gerar relatório HTML (pode falhar se faltarem dependências)
        try:
            generator = ReportGenerator()
            generator.generate_report(self.results)
        except Exception as e:
            print(f"{Fore.YELLOW}[!] HTML report generation failed: {e}{Style.RESET_ALL}")
        
        # Mostrar resumo
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{Style.BRIGHT}📊 FINAL SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Target: {Fore.GREEN}{self.results['target']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Total Subdomains: {Fore.GREEN}{self.results['statistics']['total_subdomains']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Resolved Hosts: {Fore.GREEN}{self.results['statistics']['resolved_hosts']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Technologies Detected: {Fore.GREEN}{self.results['statistics']['technologies_detected']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Open Ports: {Fore.GREEN}{self.results['statistics']['open_ports']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Vulnerabilities: {Fore.RED if self.results['statistics']['vulnerabilities'] > 0 else Fore.GREEN}{self.results['statistics']['vulnerabilities']}{Style.RESET_ALL}")
    
    def run(self, domain, skip_phases=None):
        """Executa todas as fases do scan"""
        self.start_time = time.time()
        
        # Normalizar domínio
        original_domain = domain
        normalized_domain = self.normalize_domain(domain)
        
        if normalized_domain != original_domain:
            print(f"{Fore.YELLOW}[!] Domínio normalizado: {original_domain} → {normalized_domain}{Style.RESET_ALL}")
        
        self.results['target'] = normalized_domain
        self.results['timestamp'] = datetime.now().isoformat()
        
        print(f"\n{Fore.YELLOW}[*] Target: {normalized_domain}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Starting full asset discovery...{Style.RESET_ALL}")
        
        # Validar domínio
        if not self.validate_domain(normalized_domain):
            print(f"{Fore.RED}[!] Formato de domínio inválido{Style.RESET_ALL}")
            resposta = input(f"{Fore.YELLOW}Continuar mesmo assim? (s/n): {Style.RESET_ALL}")
            if resposta.lower() not in ['s', 'sim', 'yes', 'y']:
                return
        
        # Verificar se o domínio existe
        if not self.check_domain_exists(normalized_domain):
            print(f"{Fore.YELLOW}[!] O domínio '{normalized_domain}' pode não existir ou estar offline{Style.RESET_ALL}")
            resposta = input(f"{Fore.YELLOW}Continuar mesmo assim? (s/n): {Style.RESET_ALL}")
            if resposta.lower() not in ['s', 'sim', 'yes', 'y']:
                return
        
        # Verificar wordlists
        self.check_wordlists()
        
        all_subdomains = []
        
        # Fase 1: Enumeração passiva
        if not skip_phases or 1 not in skip_phases:
            try:
                subdomains_passive = self.phase1_passive_enum(normalized_domain)
                if subdomains_passive:
                    all_subdomains.extend(subdomains_passive)
            except Exception as e:
                print(f"{Fore.RED}[!] Phase 1 failed: {e}{Style.RESET_ALL}")
        
        # Fase 2: Brute-force (se fase 1 encontrou poucos ou nenhum)
        if (not skip_phases or 2 not in skip_phases) and len(all_subdomains) < 20:
            try:
                subdomains_bruteforce = self.phase2_bruteforce(normalized_domain)
                if subdomains_bruteforce:
                    all_subdomains.extend(subdomains_bruteforce)
            except Exception as e:
                print(f"{Fore.RED}[!] Phase 2 failed: {e}{Style.RESET_ALL}")
        
        # Remover duplicados
        all_subdomains = list(set(all_subdomains))
        
        if not all_subdomains:
            print(f"{Fore.RED}[-] No subdomains found. Exiting.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Dicas:{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}  • O domínio pode não ter subdomínios públicos{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}  • Tenta com um domínio maior (google.com, microsoft.com){Style.RESET_ALL}")
            print(f"{Fore.YELLOW}  • Verifica tua conexão com a internet{Style.RESET_ALL}")
            return
        
        print(f"{Fore.GREEN}[✓] Total unique subdomains: {len(all_subdomains)}{Style.RESET_ALL}")
        
        # Resolver DNS
        print(f"\n{Fore.CYAN}{Style.BRIGHT}[+] DNS Resolution{Style.RESET_ALL}")
        try:
            resolver = DNSResolver(timeout=5, threads=self.config['general']['max_threads'])
            resolved = resolver.resolve_multiple(all_subdomains)
            self.results['resolved'] = resolved
            print(f"{Fore.GREEN}[✓] Resolved {len(resolved)} hosts{Style.RESET_ALL}")
            
            # Atualizar subdomínios com IPs
            for sub in self.results['subdomains']:
                if sub['name'] in resolved:
                    sub['ip'] = ', '.join(resolved[sub['name']])
        except Exception as e:
            print(f"{Fore.RED}[!] DNS resolution failed: {e}{Style.RESET_ALL}")
            resolved = {}
        
        # Continuar com outras fases apenas se houver hosts resolvidos
        if resolved:
            # URLs para análise
            urls = [f"http://{host}" for host in list(resolved.keys())[:30]]
            
            # Fase 2: Deteção de tecnologias
            if not skip_phases or 2 not in skip_phases:
                self.phase2_tech_detection(urls)
            
            # Fase 3: Port scanning (apenas para hosts resolvidos)
            if not skip_phases or 3 not in skip_phases:
                self.phase3_port_scan(list(resolved.keys()))
            
            # Fase 3: Screenshots (opcional)
            if not skip_phases or 3 not in skip_phases:
                self.phase3_screenshots(urls[:5])
            
            # Fase 4: Takeover check
            if not skip_phases or 4 not in skip_phases:
                self.phase4_takeover_check(all_subdomains)
        else:
            print(f"{Fore.YELLOW}[!] No hosts resolved, skipping advanced phases{Style.RESET_ALL}")
        
        # Gerar relatório
        self.generate_final_report()
        
        # Tempo total
        duration = time.time() - self.start_time
        print(f"\n{Fore.GREEN}[✓] Scan completed in {duration:.2f} seconds{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(
        description='Asset Discovery Tool - Complete Digital Asset Discovery Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-d', '--domain', required=True, help='Domínio alvo (ex: google.com)')
    parser.add_argument('--skip-phase', type=int, choices=[1,2,3,4], action='append', help='Ignorar fase específica')
    parser.add_argument('--no-bruteforce', action='store_true', help='Ignorar brute-force')
    parser.add_argument('--no-portscan', action='store_true', help='Ignorar port scanning')
    parser.add_argument('--no-screenshots', action='store_true', help='Ignorar screenshots')
    parser.add_argument('--threads', type=int, default=50, help='Número de threads (padrão: 50)')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout em segundos (padrão: 30)')
    parser.add_argument('--output', '-o', help='Diretório de output')
    
    args = parser.parse_args()
    
    # Aviso legal
    print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}⚠️  AVISO LEGAL{Style.RESET_ALL}")
    print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Esta ferramenta é apenas para testes autorizados!{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Use apenas em domínios que possui ou tem permissão.{Style.RESET_ALL}")
    
    confirm = input(f"\n{Fore.WHITE}Tens permissão para testar {Fore.CYAN}{args.domain}{Fore.WHITE}? (s/n): {Style.RESET_ALL}")
    if confirm.lower() not in ['s', 'sim', 'yes', 'y']:
        print(f"{Fore.RED}Scan cancelado.{Style.RESET_ALL}")
        sys.exit(0)
    
    # Verificar se módulos foram carregados
    if not MODULES_LOADED:
        print(f"{Fore.RED}[!] Não é possível continuar sem os módulos necessários.{Style.RESET_ALL}")
        sys.exit(1)
    
    # Criar ferramenta
    tool = AssetDiscoveryTool()
    tool.print_banner()
    
    # Configurar skip phases
    skip_phases = args.skip_phase or []
    if args.no_bruteforce:
        skip_phases.append(2)
    if args.no_portscan:
        skip_phases.append(3)
    if args.no_screenshots:
        skip_phases.append(3)
    
    # Ajustar configurações
    tool.config['general']['max_threads'] = args.threads
    tool.config['general']['timeout'] = args.timeout
    
    if args.output:
        tool.config['general']['output_dir'] = args.output
    
    try:
        tool.run(args.domain, skip_phases=skip_phases)
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Scan interrompido pelo utilizador{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Erro: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
