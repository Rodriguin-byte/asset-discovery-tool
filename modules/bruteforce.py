"""
Módulo de brute-force de subdomínios - Fase 2
Testa wordlists contra o domínio alvo
"""

import aiohttp
import asyncio
from tqdm import tqdm
import time
from urllib.parse import urlparse
import ssl
import certifi
import random

class SubdomainBruteforcer:
    def __init__(self, domain, threads=50, timeout=5, wordlist_path=None):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.wordlist_path = wordlist_path
        self.found = []
        self.ssl_context = ssl.create_default_context(cafile=certifi.where())
        
    def load_wordlist(self):
        """Carrega wordlist de subdomínios"""
        if not self.wordlist_path:
            return []
        
        try:
            with open(self.wordlist_path, 'r') as f:
                words = [line.strip() for line in f if line.strip()]
            return words
        except Exception as e:
            print(f"Error loading wordlist: {e}")
            return []
    
    async def check_subdomain(self, session, subdomain, semaphore):
        """Verifica se um subdomínio existe"""
        async with semaphore:
            url = f"http://{subdomain}.{self.domain}"
            try:
                async with session.get(url, timeout=self.timeout, ssl=self.ssl_context) as response:
                    if response.status < 400:
                        return {
                            'subdomain': f"{subdomain}.{self.domain}",
                            'url': url,
                            'status': response.status,
                            'method': 'GET'
                        }
            except:
                pass
            
            # Tentar HTTPS se HTTP falhar
            url = f"https://{subdomain}.{self.domain}"
            try:
                async with session.get(url, timeout=self.timeout, ssl=self.ssl_context) as response:
                    if response.status < 400:
                        return {
                            'subdomain': f"{subdomain}.{self.domain}",
                            'url': url,
                            'status': response.status,
                            'method': 'HTTPS'
                        }
            except:
                pass
            
            return None
    
    async def run_async(self, wordlist):
        """Executa brute-force assíncrono"""
        semaphore = asyncio.Semaphore(self.threads)
        connector = aiohttp.TCPConnector(limit=self.threads, ssl=self.ssl_context)
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
            tasks = []
            for sub in wordlist:
                task = asyncio.create_task(self.check_subdomain(session, sub, semaphore))
                tasks.append(task)
            
            # Progress bar
            results = []
            for f in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Bruteforcing"):
                result = await f
                if result:
                    results.append(result)
                    tqdm.write(f"[+] Found: {result['subdomain']} ({result['status']})")
            
            return results
    
    def brute_force(self):
        """Executa brute-force (wrapper síncrono)"""
        wordlist = self.load_wordlist()
        if not wordlist:
            print("No wordlist loaded")
            return []
        
        print(f"[*] Starting brute-force with {len(wordlist)} words")
        print(f"[*] Threads: {self.threads}")
        
        # Executar async
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(self.run_async(wordlist))
        loop.close()
        
        return results
    