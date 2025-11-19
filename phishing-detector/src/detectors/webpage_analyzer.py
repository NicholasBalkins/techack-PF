import requests
from bs4 import BeautifulSoup
import re

class WebpageAnalyzer:
    def analyze(self, url):
        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
            
            # Tenta acessar a página
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(url, timeout=5, headers=headers, verify=False)
            
            suspicious_points = []
            
            # Verifica redirecionamentos suspeitos
            if len(response.history) > 2:
                suspicious_points.append(f'Múltiplos redirecionamentos ({len(response.history)})')
            
            # Analisa o conteúdo HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Detecta páginas vazias/minimalistas que carregam conteúdo via JS (técnica de phishing)
            text_content = soup.get_text().strip()
            html_size = len(response.text)
            links = soup.find_all('a', href=True)
            
            # Se página é muito pequena E quase sem texto visível E sem links = suspeito
            if html_size < 3000 and len(text_content) < 100 and len(links) < 3:
                suspicious_points.append('Página vazia/mínima que carrega conteúdo via JavaScript (técnica de phishing)')
            
            # Verifica presença de formulários de login
            forms = soup.find_all('form')
            password_fields = soup.find_all('input', {'type': 'password'})
            if password_fields:
                suspicious_points.append(f'Formulário de senha detectado ({len(password_fields)} campo(s))')
            
            # Verifica iframes ocultos (técnica comum de phishing)
            iframes = soup.find_all('iframe')
            hidden_iframes = [iframe for iframe in iframes if 'hidden' in str(iframe).lower() or 'display:none' in str(iframe).lower()]
            if hidden_iframes:
                suspicious_points.append(f'iframes ocultos detectados ({len(hidden_iframes)})')
            
            # Verifica JavaScript ofuscado
            scripts = soup.find_all('script')
            # reduzir falsos positivos: requer múltiplos sinais ou bloco inline grande
            obf_count = 0
            for script in scripts:
                script_text = script.string or ''
                if not script_text:
                    continue
                indicators = 0
                if 'eval(' in script_text:
                    indicators += 1
                if 'unescape(' in script_text:
                    indicators += 1
                if 'fromCharCode' in script_text:
                    indicators += 1
                if 'document.write(' in script_text:
                    indicators += 1
                # conta apenas se houver sinais e o bloco for razoavelmente grande
                if indicators >= 1 and len(script_text) > 200:
                    obf_count += 1
                if obf_count >= 2:
                    suspicious_points.append('JavaScript ofuscado/suspeito detectado')
                    break
            
            # Verifica solicitações de informações sensíveis
            text_content = soup.get_text().lower()
            sensitive_keywords = ['social security', 'credit card', 'cvv', 'password', 'pin code', 'account number', 'cpf', 'cartão de crédito']
            found_sensitive = [kw for kw in sensitive_keywords if kw in text_content]
            if found_sensitive:
                suspicious_points.append(f'Solicita informações sensíveis: {", ".join(found_sensitive[:3])}')
            
            # Verifica falta de favicon — só sinaliza em páginas maiores para reduzir falsos positivos
            favicon = soup.find('link', rel=re.compile('icon', re.I))
            page_text = soup.get_text()
            if not favicon and len(page_text) > 2000:
                suspicious_points.append('Sem favicon (sites legítimos geralmente têm)')
            
            # Verifica formulários que enviam para domínio externo
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                method = (form.get('method') or '').upper()
                # Mais rigoroso: se tem formulário POST (ou sem method explícito) e action externa ou vazia, sinaliza
                if method == 'POST' or not method:
                    if action.startswith('http') and parsed_url.netloc not in action:
                        suspicious_points.append('Formulário POST envia dados para domínio externo (suspeito)')
                        break
                    # Formulários sem action definida ou com action vazia são suspeitos
                    if not action or action == '#':
                        suspicious_points.append('Formulário sem destino claro (action vazio ou #)')
                        break
            
            # Verifica links externos suspeitos
            links = soup.find_all('a', href=True)
            external_links = [link for link in links if 'http' in link['href'] and url.split('/')[2] not in link['href']]
            internal_links = [link for link in links if not link['href'].startswith('http') or url.split('/')[2] in link['href']]
            # Se quase todos os links são externos, é suspeito
            if len(links) > 5 and len(external_links) > len(links) * 0.7:
                suspicious_points.append(f'Maioria dos links são externos ({len(external_links)}/{len(links)})')
            # Se não há quase nenhum link interno, é suspeito (página de phishing simples)
            if len(links) > 0 and len(internal_links) < 2:
                suspicious_points.append('Poucos ou nenhum link interno (página isolada)')

            
            if suspicious_points:
                return {
                    'status': 'FAIL',
                    'details': f'⚠️ {len(suspicious_points)} problema(s): {"; ".join(suspicious_points[:3])}'
                }
            
            return {'status': 'OK', 'details': '✓ Conteúdo da página parece legítimo'}
            
        except requests.exceptions.Timeout:
            return {'status': 'FAIL', 'details': '⚠️ Timeout ao acessar a página (servidor lento/suspeito)'}
        except requests.exceptions.SSLError:
            return {'status': 'FAIL', 'details': '⚠️ Erro de certificado SSL (conexão insegura)'}
        except requests.exceptions.ConnectionError:
            return {'status': 'FAIL', 'details': '⚠️ Não foi possível conectar ao servidor'}
        except Exception as e:
            return {'status': 'FAIL', 'details': f'⚠️ Erro ao analisar página: {str(e)[:50]}'}
