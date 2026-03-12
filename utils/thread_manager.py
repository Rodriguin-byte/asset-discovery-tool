"""
Gerenciador de threads para operações paralelas
"""

import threading
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

class ThreadManager:
    def __init__(self, max_workers=50, rate_limit=0):
        self.max_workers = max_workers
        self.rate_limit = rate_limit
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.futures = []
        self.lock = threading.Lock()
        
    def submit(self, fn, *args, **kwargs):
        """Submete uma tarefa para execução"""
        future = self.executor.submit(fn, *args, **kwargs)
        self.futures.append(future)
        return future
    
    def map(self, fn, items):
        """Mapeia função para lista de items em paralelo"""
        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(fn, item): item for item in items}
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    print(f"Error processing {futures[future]}: {e}")
                
                if self.rate_limit > 0:
                    time.sleep(1 / self.rate_limit)
        
        return results
    
    def wait_completion(self):
        """Aguarda todas as tarefas completarem"""
        for future in as_completed(self.futures):
            try:
                future.result()
            except Exception as e:
                print(f"Error: {e}")
    
    def shutdown(self):
        """Finaliza o executor"""
        self.executor.shutdown(wait=True)
        