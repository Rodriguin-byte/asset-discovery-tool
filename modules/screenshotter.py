"""
Módulo de screenshots - Fase 3
Captura screenshots de sites ativos
"""

import os
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from PIL import Image
import io
import hashlib

class Screenshotter:
    def __init__(self, output_dir='./output/screenshots', width=1280, height=720, timeout=30):
        self.output_dir = output_dir
        self.width = width
        self.height = height
        self.timeout = timeout
        self.driver = None
        
        # Criar diretório de output
        os.makedirs(output_dir, exist_ok=True)
    
    def init_driver(self):
        """Inicializa o Chrome driver"""
        chrome_options = Options()
        chrome_options.add_argument('--headless')  # Executar em background
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument(f'--window-size={self.width},{self.height}')
        chrome_options.add_argument('--ignore-certificate-errors')
        chrome_options.add_argument('--allow-insecure-localhost')
        
        # Desabilitar imagens para performance
        prefs = {
            'profile.managed_default_content_settings.images': 2,
            'permissions.default.stylesheet': 2
        }
        chrome_options.add_experimental_option('prefs', prefs)
        
        try:
            self.driver = webdriver.Chrome(
                service=Service(ChromeDriverManager().install()),
                options=chrome_options
            )
            self.driver.set_page_load_timeout(self.timeout)
            return True
        except Exception as e:
            print(f"Error initializing Chrome driver: {e}")
            return False
    
    def take_screenshot(self, url, filename=None):
        """Captura screenshot de uma URL"""
        if not self.driver:
            if not self.init_driver():
                return None
        
        if not filename:
            # Gerar nome de arquivo baseado na URL
            url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
            domain = url.replace('https://', '').replace('http://', '').split('/')[0]
            filename = f"{domain}_{url_hash}.png"
        
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            print(f"[*] Capturing: {url}")
            self.driver.get(url)
            time.sleep(2)  # Aguardar carregamento
            
            # Capturar screenshot
            screenshot = self.driver.get_screenshot_as_png()
            img = Image.open(io.BytesIO(screenshot))
            
            # Redimensionar se necessário
            if img.size != (self.width, self.height):
                img = img.resize((self.width, self.height), Image.Resampling.LANCZOS)
            
            img.save(filepath, 'PNG', quality=85)
            
            return {
                'url': url,
                'filepath': filepath,
                'size': img.size,
                'timestamp': time.time()
            }
            
        except Exception as e:
            print(f"Error capturing {url}: {e}")
            return None
    
    def take_bulk_screenshots(self, urls, max_concurrent=5):
        """Captura screenshots de múltiplas URLs"""
        results = []
        
        for i, url in enumerate(urls):
            if i >= max_concurrent:
                break
            
            result = self.take_screenshot(url)
            if result:
                results.append(result)
            
            # Pequena pausa entre capturas
            time.sleep(1)
        
        return results
    
    def close(self):
        """Fecha o driver"""
        if self.driver:
            self.driver.quit()
            