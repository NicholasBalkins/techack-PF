import socket
import ssl
import ipaddress
from datetime import datetime
from urllib.parse import urlparse
import subprocess
try:
    import whois as pywhois
except Exception:
    pywhois = None
import tldextract
import re


class TechnicalEvaluator:
    def evaluate(self, url):
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0]
        suspicious_points = []

        # WHOIS / idade do domínio (subprocess fallback)
        try:
            ext = tldextract.extract(domain)
            registrable = ext.registered_domain
            if registrable:
                whois_text = ''
                try:
                    if pywhois:
                        w = pywhois.whois(registrable)
                        whois_text = str(w)
                    else:
                        p = subprocess.run(['whois', registrable], capture_output=True, text=True, timeout=6)
                        whois_text = p.stdout.lower()
                    # Tenta reconhecer várias datas comuns
                    m = re.search(r'creation date:\s*([0-9T:\- ]{8,25})', whois_text)
                    if not m:
                        m = re.search(r'created on:\s*([0-9T:\- ]{8,25})', whois_text)
                    if not m:
                        m = re.search(r'domain created:\s*([0-9T:\- ]{8,25})', whois_text)
                    if m:
                        date_raw = m.group(1).strip()
                        # tenta vários formatos
                        for fmt in ('%Y-%m-%d', '%Y-%m-%d %H:%M:%S', '%d-%b-%Y', '%Y.%m.%d', '%d.%m.%Y'):
                            try:
                                creation = datetime.strptime(date_raw.split('T')[0], fmt)
                                age_days = (datetime.now() - creation).days
                                if age_days < 365:
                                    suspicious_points.append(f'Domínio jovem ({age_days} dias)')
                                break
                            except Exception:
                                continue
                    # Verifica nomes comuns de DNS dinâmico no registrable
                    dyn_providers = ['no-ip', 'dyndns', 'duckdns', 'freedns', 'ddns']
                    if any(p in (registrable or '').lower() for p in dyn_providers):
                        suspicious_points.append('Usa provedor de DNS dinâmico (ex: no-ip/dyndns)')
                except Exception:
                    pass
        except Exception:
            pass

        # Verifica certificado SSL
        if parsed.scheme == 'https':
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        not_after_str = cert.get('notAfter')
                        if not_after_str:
                            try:
                                not_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                                days_until_expiry = (not_after - datetime.now()).days
                                if days_until_expiry < 30:
                                    suspicious_points.append(f'Certificado expira em breve ({days_until_expiry} dias)')
                            except Exception:
                                pass

                        subject = cert.get('subject', ())
                        try:
                            subject_dict = dict(x[0] for x in subject)
                            issued_to = subject_dict.get('commonName', '')
                        except Exception:
                            issued_to = ''
                        if issued_to and (issued_to not in domain and not issued_to.startswith('*.')):
                            suspicious_points.append('Certificado não corresponde ao domínio')
                        # issuer
                        issuer = cert.get('issuer', ())
                        try:
                            issuer_dict = dict(x[0] for x in issuer)
                            issued_by = issuer_dict.get('organizationName', issuer_dict.get('commonName', ''))
                            if issued_by and 'let\'s encrypt' in str(issued_by).lower():
                                # Let's Encrypt é comum, não é automaticamente suspeito
                                pass
                        except Exception:
                            issued_by = ''
            except Exception:
                suspicious_points.append('Erro ao verificar SSL')
        else:
            suspicious_points.append('Site não usa HTTPS (conexão insegura)')

        # DNS
        try:
            ip_address = socket.gethostbyname(domain)
            try:
                ip_obj = ipaddress.ip_address(ip_address)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                    suspicious_points.append(f'IP privado ou localhost ({ip_address})')
            except Exception:
                # se não conseguiu interpretar o IP, não marca como privado
                pass
        except Exception:
            suspicious_points.append('Domínio não resolvível (DNS)')

        if suspicious_points:
            return {'status': 'FAIL', 'details': f'⚠️ {len(suspicious_points)} problema(s): {"; ".join(suspicious_points[:3])}'}
        return {'status': 'OK', 'details': '✓ Verificações técnicas OK'}
