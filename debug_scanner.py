#!/usr/bin/env python3
"""
Script de diagnóstico para o Asset Discovery Tool
Testa cada componente individualmente
"""

import sys
import dns.resolver
import requests
from colorama import init, Fore, Style

init(autoreset=True)

def test_domain(domain):
    """Testa um domínio específico"""
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Testing domain: {domain}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    # Teste 1: DNS Resolution
    print(f"\n{Fore.YELLOW}[1] Testing DNS resolution...{Style.RESET_ALL}")
    try:
        answers = dns.resolver.resolve(domain, 'A')
        print(f"  {Fore.GREEN}✓{Style.RESET_ALL} Domain resolves to: {answers[0]}")
    except Exception as e:
        print(f"  {Fore.RED}✗{Style.RESET_ALL} DNS resolution failed: {e}")
    
    # Teste 2: HTTP Connection
    print(f"\n{Fore.YELLOW}[2] Testing HTTP connection...{Style.RESET_ALL}")
    for proto in ['http', 'https']:
        try:
            url = f"{proto}://{domain}"
            response = requests.get(url, timeout=5, verify=False)
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {url} - Status: {response.status_code}")
        except Exception as e:
            print(f"  {Fore.RED}✗{Style.RESET_ALL} {proto} failed: {e}")
    
    # Teste 3: crt.sh
    print(f"\n{Fore.YELLOW}[3] Testing crt.sh...{Style.RESET_ALL}")
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} Found {len(data)} entries")
        else:
            print(f"  {Fore.RED}✗{Style.RESET_ALL} HTTP {response.status_code}")
    except Exception as e:
        print(f"  {Fore.RED}✗{Style.RESET_ALL} Failed: {e}")
    
    # Teste 4: AlienVault
    print(f"\n{Fore.YELLOW}[4] Testing AlienVault...{Style.RESET_ALL}")
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} Success")
        else:
            print(f"  {Fore.RED}✗{Style.RESET_ALL} HTTP {response.status_code}")
    except Exception as e:
        print(f"  {Fore.RED}✗{Style.RESET_ALL} Failed: {e}")
    
    # Teste 5: Wayback Machine
    print(f"\n{Fore.YELLOW}[5] Testing Wayback Machine...{Style.RESET_ALL}")
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} Found {len(data)-1} entries")
        else:
            print(f"  {Fore.RED}✗{Style.RESET_ALL} HTTP {response.status_code}")
    except Exception as e:
        print(f"  {Fore.RED}✗{Style.RESET_ALL} Failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Uso: {sys.argv[0]} <domínio>")
        print(f"Exemplo: {sys.argv[0]} google.com")
        sys.exit(1)
    
    test_domain(sys.argv[1])