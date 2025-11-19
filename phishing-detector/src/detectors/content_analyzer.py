import requests
from bs4 import BeautifulSoup
import re


class ContentAnalyzer:
    def analyze(self, url):
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(url, timeout=6, headers=headers, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            suspicious_points = []
            
            text_content = soup.get_text().strip()
            html_size = len(response.text)
            
            # Detecta páginas suspeitas que parecem vazias (carregamento via JS)
            if html_size < 3000 and len(text_content) < 100:
                # Verifica se há scripts que podem estar carregando conteúdo malicioso
                scripts = soup.find_all('script', src=True)
                if len(scripts) > 0:
                    suspicious_points.append('Página quase vazia com scripts externos (possível phishing via JS)')

            # Verifica presença de formulários de login / campos de senha
            password_fields = soup.find_all('input', {'type': 'password'})
            if password_fields:
                suspicious_points.append(f'Formulário de login detectado ({len(password_fields)} campo(s) de senha)')

            # Verifica solicitações de informações sensíveis no texto
            text_content = soup.get_text().lower()
            sensitive_keywords = [
                'social security', 'credit card', 'cvv', 'password', 'pin code',
                'account number', 'cpf', 'cartão de crédito', 'número do cartão',
                'código de segurança', 'senha', 'ssn'
            ]
            found_sensitive = [kw for kw in sensitive_keywords if kw in text_content]
            if found_sensitive:
                suspicious_points.append(f'Solicita informações sensíveis: {", ".join(found_sensitive[:3])}')
            
            # Detecta títulos suspeitos (CAPTCHA falso, verificações falsas)
            title = soup.find('title')
            if title and title.string:
                title_text = title.string.lower()
                fake_verification_keywords = ['robot', 'captcha', 'verification', 'verify', 'human', 'ロボット', '認証', 'verificação']
                if any(kw in title_text for kw in fake_verification_keywords):
                    # Se tem título de verificação MAS não é de domínios legítimos (google.com/recaptcha)
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    if 'google.com' not in parsed.netloc and 'recaptcha' not in parsed.netloc:
                        suspicious_points.append('Título sugere verificação/CAPTCHA suspeito (possível phishing)')

            # Verifica logos de marcas conhecidas (possível clonagem)
            images = soup.find_all('img')
            brand_logos = ['paypal', 'apple', 'microsoft', 'google', 'amazon', 'facebook', 'instagram', 'netflix', 'itau', 'bradesco', 'santander', 'nubank']
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain_lower = parsed.netloc.lower()
            logo_flag = False
            for img in images:
                src = (img.get('src') or '').lower()
                alt = (img.get('alt') or '').lower()
                for brand in brand_logos:
                    if (brand in src or brand in alt) and brand not in domain_lower:
                        logo_flag = True
                        break
                if logo_flag:
                    break
            if logo_flag:
                suspicious_points.append('Usa logo de marca conhecida mas não é o site oficial')

            # Verifica linguagem de urgência
            urgency_words = ['urgent', 'immediately', 'suspended', 'locked', 'verify now', 'act now', 'urgente', 'imediatamente', 'suspenso', 'bloqueado', 'verificar agora', 'conta suspensa']
            found_urgency = sum(1 for word in urgency_words if word in text_content)
            if found_urgency >= 2:
                suspicious_points.append(f'Linguagem de urgência detectada ({found_urgency} ocorrências)')

            # Verifica formulários que enviam para domínio externo
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                if action.startswith('http') and parsed.netloc not in action:
                    suspicious_points.append('Formulário envia dados para domínio externo')
                    break

            # Verifica iframes ocultos
            iframes = soup.find_all('iframe')
            hidden_iframes = [iframe for iframe in iframes if 'hidden' in str(iframe).lower() or 'display:none' in str(iframe).lower() or 'visibility:hidden' in str(iframe).lower()]
            if hidden_iframes:
                suspicious_points.append(f'iframes ocultos detectados ({len(hidden_iframes)})')

            # JS ofuscado: requer blocos maiores e mais de um sinal
            scripts = soup.find_all('script')
            obf = 0
            for script in scripts:
                script_text = script.string or ''
                if not script_text or len(script_text) < 200:
                    continue
                if any(k in script_text for k in ['eval(', 'unescape(', 'fromCharCode', 'document.write(']):
                    obf += 1
                if obf >= 2:
                    suspicious_points.append('JavaScript ofuscado/suspeito detectado')
                    break

            # Falta de informações de contato/políticas
            contact_indicators = ['contact', 'about', 'privacy', 'terms', 'contato', 'sobre', 'privacidade', 'termos']
            has_contact = any(indicator in text_content for indicator in contact_indicators)
            if not has_contact and len(text_content) > 800:
                suspicious_points.append('Falta informações de contato/políticas (site extenso sem referências)')

            if suspicious_points:
                return {'status': 'FAIL', 'details': f'⚠️ {len(suspicious_points)} problema(s): {"; ".join(suspicious_points[:4])}'}

            return {'status': 'OK', 'details': '✓ Conteúdo da página parece legítimo'}

        except Exception as e:
            return {'status': 'FAIL', 'details': f'⚠️ Erro ao analisar conteúdo: {str(e)[:80]}'}