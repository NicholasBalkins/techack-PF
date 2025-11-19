# Phishing Detector

Sistema de detecção de phishing usando análise heurística em tempo real com integração ao PhishTank.

## Como Usar

### 1. Instalar dependências
```bash
pip install flask requests beautifulsoup4 dnspython tldextract python-whois
```

### 2. (Opcional) Configurar API do PhishTank
Para consultas em tempo real ao PhishTank:
1. Registre-se em: https://www.phishtank.com/register.php
2. Acesse https://www.phishtank.com/api_info.php e solicite uma API key
3. Configure a variável de ambiente:
```bash
export PHISHTANK_API_KEY='sua_chave_aqui'
```

**Observação**: O sistema funciona normalmente sem API key. A API do PhishTank tem proteção Cloudflare que pode bloquear requisições não autenticadas, mas isso não afeta o funcionamento geral do sistema. Os detectores heurísticos (análise de TLD, padrões numéricos, typosquatting, etc.) continuam funcionando normalmente e são bastante eficazes na identificação de phishing

### 3. Iniciar o servidor
```bash
cd src
python main.py
```

### 4. Acessar o sistema
Abra seu navegador e acesse: http://127.0.0.1:5000

### 5. Analisar URLs
- Cole a URL que deseja verificar no campo de texto
- Clique em "Analisar URL"
- Veja os resultados detalhados de cada verificação
- Acesse a página `/history` para consultar o histórico de análises

## Funcionalidades

### Detecção de Phishing
- Consulta ao feed público do OpenPhish (sem necessidade de API key, ~300 URLs atualizadas por hora)
- Consulta em tempo real à API do PhishTank (opcional, requer API key)
- Base de dados local configurável (arquivo CSV)
- Análise de URL: detecção de TLDs suspeitos, subdomínios com padrões aleatórios, uso de endereços IP
- Verificação de conteúdo HTML: formulários suspeitos, campos de senha, iframes ocultos
- Análise técnica: verificação WHOIS (idade do domínio), certificados SSL, resolução DNS
- Detecção de typosquatting usando distância de Levenshtein

### Interface
- Dashboard interativo com resultados detalhados
- Histórico de análises com opção de exportação em CSV
- Gráficos mostrando estatísticas das detecções
- Explicações sobre cada tipo de verificação
