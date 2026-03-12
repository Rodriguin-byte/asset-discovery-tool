"""
Módulo de utilitários DNS - Fase 1
Resolução de subdomínios e coleta de registros
"""

import dns.resolver
import dns.exception
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

class DNSResolver:
    def __init__(self, timeout=5, threads=10):
        self.timeout = timeout
        self.threads = threads
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
    def resolve_a_record(self, hostname):
        """
        Resolve registro A (IPv4) para um hostname
        """
        try:
            answers = self.resolver.resolve(hostname, 'A')
            return [str(r) for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []
        except Exception:
            return []
    
    def resolve_multiple(self, hostnames):
        """
        Resolve múltiplos hostnames em paralelo
        """
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_hostname = {
                executor.submit(self.resolve_a_record, hostname): hostname 
                for hostname in hostnames
            }
            
            for future in as_completed(future_to_hostname):
                hostname = future_to_hostname[future]
                try:
                    ips = future.result(timeout=self.timeout)
                    if ips:
                        results[hostname] = ips
                except Exception:
                    pass
        
        return results
    
    def get_all_records(self, hostname):
        """
        Obtém todos os tipos de registro DNS para um hostname
        """
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        
        for rtype in record_types:
            try:
                answers = self.resolver.resolve(hostname, rtype)
                records[rtype] = [str(r) for r in answers]
            except:
                pass
        
        return records
    
    def reverse_lookup(self, ip):
        """
        Reverse DNS lookup
        """
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None