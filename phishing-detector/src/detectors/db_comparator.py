import os
import csv
import requests
import json
from urllib.parse import urlparse

class DbComparator:
    def __init__(self):
        # Tenta carregar uma base local em src/database/phishing_db.csv
        self.local_db = set()
        base = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'database'))
        csv_path = os.path.join(base, 'phishing_db.csv')
        if os.path.exists(csv_path):
            try:
                with open(csv_path, newline='', encoding='utf-8') as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if row:
                            self.local_db.add(row[0].strip().lower())
            except Exception:
                self.local_db = set()
        
        # Cache do OpenPhish (evita múltiplas requisições)
        self.openphish_cache = None
        self.openphish_cache_time = 0
    
    def _check_openphish(self, url):
        """
        Consulta o feed público do OpenPhish para verificar se a URL está reportada.
        OpenPhish Feed: https://openphish.com/feed.txt (atualizado a cada hora)
        """
        import time
        
        try:
            # Cache por 1 hora (3600 segundos)
            current_time = time.time()
            if self.openphish_cache is None or (current_time - self.openphish_cache_time) > 3600:
                # Baixa o feed do OpenPhish
                response = requests.get('https://openphish.com/feed.txt', timeout=5)
                if response.status_code == 200:
                    # Converte para conjunto de URLs normalizadas
                    urls = [line.strip().lower() for line in response.text.strip().split('\n') if line.strip()]
                    self.openphish_cache = set(urls)
                    self.openphish_cache_time = current_time
                else:
                    return False, None
            
            # Verifica se a URL está no feed
            url_normalized = url.lower().strip()
            
            # Verifica URL exata
            if url_normalized in self.openphish_cache:
                return True, 'OpenPhish'
            
            # Verifica URL sem protocolo (http:// ou https://)
            parsed = urlparse(url_normalized)
            url_without_protocol = parsed.netloc + parsed.path
            if parsed.path:
                url_without_protocol = url_without_protocol.rstrip('/')
            
            for cached_url in self.openphish_cache:
                if url_without_protocol in cached_url or cached_url in url_without_protocol:
                    return True, 'OpenPhish'
            
            return False, None
            
        except Exception:
            return False, None
    
    def _check_phishtank(self, url):
        """
        Consulta a API do PhishTank para verificar se a URL está reportada como phishing.
        PhishTank API: https://www.phishtank.com/api_info.php
        """
        try:
            # PhishTank requer registro para obter API key
            # Por padrão, tenta usar variável de ambiente PHISHTANK_API_KEY
            api_key = os.environ.get('PHISHTANK_API_KEY', '')
            
            # Endpoint público do PhishTank (checkurl)
            phishtank_url = 'https://checkurl.phishtank.com/checkurl/'
            
            data = {
                'url': url,
                'format': 'json'
            }
            
            if api_key:
                data['app_key'] = api_key
            
            headers = {
                'User-Agent': 'phishing-detector/1.0'
            }
            
            response = requests.post(
                phishtank_url,
                data=data,
                headers=headers,
                timeout=3
            )
            
            if response.status_code == 200:
                result = response.json()
                # PhishTank retorna: {"results": {"in_database": true/false, "valid": true/false}}
                if result.get('results', {}).get('in_database', False):
                    if result['results'].get('valid', False):
                        return True, 'PhishTank'
            
            return False, None
            
        except Exception:
            # Se falhar a consulta (sem API key, timeout, etc), continua com verificação local
            return False, None

    def _levenshtein(self, a: str, b: str) -> int:
        # Implementação simples e eficiente da distância de Levenshtein
        if a == b:
            return 0
        if len(a) == 0:
            return len(b)
        if len(b) == 0:
            return len(a)

        prev_row = list(range(len(b) + 1))
        for i, ca in enumerate(a, 1):
            curr_row = [i]
            for j, cb in enumerate(b, 1):
                insertions = prev_row[j] + 1
                deletions = curr_row[j - 1] + 1
                substitutions = prev_row[j - 1] + (0 if ca == cb else 1)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]

    def _is_similar_to_brand(self, domain: str):
        # Checa similaridade por Levenshtein contra marcas conhecidas
        famous_brands = ['google', 'facebook', 'amazon', 'paypal', 'apple', 'microsoft', 'netflix', 'instagram', 'itau', 'nubank', 'bradesco', 'santander', 'allegro', 'ebay', 'aliexpress', 'mercadolivre', 'americanas']
        d = domain.lower()
        for brand in famous_brands:
            # calcula distância e compara razão com o tamanho do brand
            dist = self._levenshtein(d, brand)
            if dist <= 2 and abs(len(d) - len(brand)) <= 3:
                return True, brand
        return False, ''

    def compare(self, url):
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace('www.', '')

        # 1. Verifica base local (CSV externo, sem hardcode)
        if domain in self.local_db:
            return {'status': 'FAIL', 'details': '⚠️ Domínio presente na base local de phishing'}

        # 2. Consulta OpenPhish (feed público, sem API key necessária)
        is_phishing_op, source_op = self._check_openphish(url)
        if is_phishing_op:
            return {'status': 'FAIL', 'details': '⚠️ PHISHING CONFIRMADO: URL reportada no OpenPhish'}

        # 3. Consulta PhishTank API em tempo real (requer API key para funcionar sem bloqueios)
        is_phishing_pt, source_pt = self._check_phishtank(url)
        if is_phishing_pt:
            return {'status': 'FAIL', 'details': '⚠️ PHISHING CONFIRMADO: URL reportada no PhishTank'}

        # 4. Verifica similaridade com marcas conhecidas (Levenshtein)
        similar, brand = self._is_similar_to_brand(domain)
        if similar:
            return {'status': 'FAIL', 'details': f'⚠️ Domínio similar a marca conhecida ({brand}) - possível typosquatting'}

        return {'status': 'OK', 'details': '✓ Verificado: OpenPhish + PhishTank + Base local + Typosquatting'}
