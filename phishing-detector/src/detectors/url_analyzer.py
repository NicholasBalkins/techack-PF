import re
from urllib.parse import urlparse

class UrlAnalyzer:
    def analyze(self, url):
        parsed = urlparse(url)
        # aceita entradas como 'google.com' adicionando esquema por padrão
        if not parsed.scheme or not parsed.netloc:
            # tentativa de recuperação assumindo https
            parsed = urlparse('https://' + url)
            if not parsed.netloc:
                return {'status': 'FAIL', 'details': 'URL inválida ou malformada.'}

        suspicious_points = []
        
        # Verifica uso de IP ao invés de domínio
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.match(ip_pattern, parsed.netloc):
            suspicious_points.append('Uso de endereço IP direto')
        
        # Verifica caracteres suspeitos no domínio
        if re.search(r'[^a-zA-Z0-9.-]', parsed.netloc):
            suspicious_points.append('Caracteres especiais no domínio')
        
        # Verifica subdomínios excessivos (phishing comum)
        subdomain_count = parsed.netloc.count('.')
        if subdomain_count > 3:
            suspicious_points.append(f'Muitos subdomínios ({subdomain_count})')
        
        # Verifica uso de números no domínio (substituição comum em phishing)
        if re.search(r'\d', parsed.netloc.split('.')[0]):
            suspicious_points.append('Números no nome do domínio')
        
        # Verifica URLs muito longas (comum em phishing)
        if len(url) > 75:
            suspicious_points.append(f'URL muito longa ({len(url)} caracteres)')
        
        # Verifica path suspeito: muitos caracteres aleatórios ou tokens longos
        if parsed.path and len(parsed.path) > 20:
            path_parts = [p for p in parsed.path.split('/') if p]
            for part in path_parts:
                # token longo sem estrutura clara (ex: ourgfivsp, token aleatório)
                if len(part) > 8 and not any(sep in part for sep in ['.', '-', '_']):
                    # checa se tem mistura de vogais/consoantes (heurística de aleatoriedade)
                    vowels = sum(1 for c in part.lower() if c in 'aeiou')
                    if vowels < len(part) * 0.2 or vowels > len(part) * 0.6:
                        suspicious_points.append(f'Path com token suspeito: {part}')
                        break
        
        # Verifica uso de @ na URL (técnica de phishing)
        if '@' in url:
            suspicious_points.append('Uso de @ na URL (redirecionamento)')
        
        # Verifica uso de encurtadores de URL conhecidos
        url_shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
        if any(shortener in parsed.netloc for shortener in url_shorteners):
            suspicious_points.append('URL encurtada (pode esconder destino real)')
        
        # Verifica hifens excessivos
        if parsed.netloc.count('-') > 3:
            suspicious_points.append('Muitos hifens no domínio')
        
        # Verifica TLDs suspeitos comumente usados para phishing
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.cfd', '.club', '.icu']
        if any(parsed.netloc.endswith(tld) for tld in suspicious_tlds):
            suspicious_points.append('TLD suspeito (comum em phishing)')
        
        # Verifica domínio muito curto ou com padrão aleatório
        domain_parts = parsed.netloc.split('.')
        if len(domain_parts) >= 2:
            main_domain = domain_parts[-2]
            if len(main_domain) <= 4 and not main_domain.isalpha():
                suspicious_points.append('Domínio muito curto ou com padrão suspeito')
        
        # Verifica subdomínio aleatório (muitas consoantes seguidas)
        if len(domain_parts) >= 3:
            subdomain = domain_parts[0]
            if len(subdomain) > 6:
                # Conta consoantes seguidas (padrão aleatório como 'snxpyhjdf')
                consonants_streak = 0
                max_streak = 0
                for char in subdomain.lower():
                    if char not in 'aeiou0123456789-':
                        consonants_streak += 1
                        max_streak = max(max_streak, consonants_streak)
                    else:
                        consonants_streak = 0
                if max_streak >= 4:
                    suspicious_points.append(f'Subdomínio com padrão aleatório: {subdomain}')
        
        # Verifica padrão de phishing: hífen seguido de muitos números (ex: allegro.pl-1231414.icu)
        if re.search(r'-\d{5,}', parsed.netloc):
            suspicious_points.append('Hífen seguido de muitos números (padrão comum em phishing)')
        
        # Verifica palavras comuns em phishing
        phishing_keywords = ['secure', 'account', 'update', 'login', 'verify', 'confirm', 'banking', 'paypal', 'apple', 'microsoft']
        domain_lower = parsed.netloc.lower()
        found_keywords = [kw for kw in phishing_keywords if kw in domain_lower]
        if found_keywords:
            suspicious_points.append(f'Palavras suspeitas: {", ".join(found_keywords)}')
        
        # Verifica uso de HTTPS
        if parsed.scheme != 'https':
            suspicious_points.append('Não usa HTTPS (conexão insegura)')
        
        if suspicious_points:
            return {
                'status': 'FAIL', 
                'details': f'⚠️ {len(suspicious_points)} problema(s): {"; ".join(suspicious_points)}'
            }
        
        return {'status': 'OK', 'details': '✓ URL parece legítima - nenhum sinal suspeito encontrado'}
