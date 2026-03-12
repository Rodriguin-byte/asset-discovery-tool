"""
Módulo de scanner de portas - Fase 3
Verifica portas abertas em hosts descobertos
"""

import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import time

class PortScanner:
    def __init__(self, timeout=2, threads=50):
        self.timeout = timeout
        self.threads = threads
        self.open_ports = {}
        self.lock = threading.Lock()
        
        # Portas comuns e seus serviços
        self.common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            111: 'RPC',
            135: 'RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S',
            1723: 'PPTP',
            3306: 'MySQL',
            3389: 'RDP',
            5900: 'VNC',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt'
        }
    
    def scan_port(self, host, port):
        """Escaneia uma única porta"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            
            if result == 0:
                # Porta está aberta
                service = self.common_ports.get(port, 'unknown')
                
                # Tentar obter banner
                banner = None
                try:
                    if port in [80, 443, 8080, 8443]:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    else:
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                except:
                    pass
                
                with self.lock:
                    if host not in self.open_ports:
                        self.open_ports[host] = []
                    self.open_ports[host].append({
                        'port': port,
                        'service': service,
                        'banner': banner
                    })
                
                return True
            sock.close()
        except:
            pass
        return False
    
    def scan_host(self, host, ports=None):
        """Escaneia um host específico"""
        if ports is None:
            ports = list(self.common_ports.keys())
        
        print(f"[*] Scanning {host} for {len(ports)} ports...")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, host, port): port for port in ports}
            
            for future in futures:
                try:
                    future.result(timeout=self.timeout + 1)
                except:
                    pass
        
        return self.open_ports.get(host, [])
    
    def scan_hosts(self, hosts, ports=None):
        """Escaneia múltiplos hosts"""
        for host in hosts:
            self.scan_host(host, ports)
        
        return self.open_ports
    
    def get_open_ports_summary(self):
        """Retorna resumo das portas abertas"""
        summary = []
        for host, ports in self.open_ports.items():
            for port_info in ports:
                summary.append({
                    'host': host,
                    'port': port_info['port'],
                    'service': port_info['service'],
                    'banner': port_info.get('banner', '')
                })
        return summary
