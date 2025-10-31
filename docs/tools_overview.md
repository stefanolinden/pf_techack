# Ferramentas de Segurança Implementadas

## Versão: 2.1.0
## Data: 31 de Outubro de 2025

---

## Resumo Executivo

O Web Security Scanner agora possui **13 ferramentas de detecção de vulnerabilidades**, cobrindo as principais ameaças do OWASP Top 10 e outras vulnerabilidades críticas de segurança web.

---

## Ferramentas Implementadas

### 1. **XSS (Cross-Site Scripting)** ✅
**Severidade:** HIGH/CRITICAL  
**Descrição:** Detecta injeção de scripts maliciosos em parâmetros e formulários  
**Payloads testados:** 5 variações diferentes
- `<script>alert('XSS')</script>`
- `<img src=x onerror=alert('XSS')>`
- `<svg onload=alert('XSS')>`
- `javascript:alert('XSS')`
- `<body onload=alert('XSS')>`

**Locais testados:**
- Parâmetros de URL
- Campos de formulário (GET e POST)

---

### 2. **SQL Injection** ✅
**Severidade:** CRITICAL  
**Descrição:** Detecta vulnerabilidades de injeção SQL através de payloads e análise de erros  
**Payloads testados:** 7 variações
- `' OR '1'='1`
- `' OR '1'='1' --`
- `' OR '1'='1' /*`
- `admin' --`
- `' UNION SELECT NULL--`
- `1' AND '1'='1`
- `1' AND '1'='2`

**Padrões de erro detectados:**
- MySQL
- PostgreSQL
- SQL Server
- Oracle

---

### 3. **CSRF (Cross-Site Request Forgery)** ✅
**Severidade:** MEDIUM/HIGH  
**Descrição:** Verifica se formulários possuem proteção CSRF  
**Verificação:** Procura por tokens CSRF em formulários POST/PUT/DELETE
- `csrf_token`
- `_csrf`
- `token`
- `_token`
- `xsrf`

---

### 4. **Directory Traversal** ✅
**Severidade:** HIGH  
**Descrição:** Testa acesso não autorizado a arquivos do sistema  
**Payloads testados:** 6 variações
- `../../../etc/passwd`
- `..\\..\\..\\windows\\win.ini`
- `....//....//....//etc/passwd`
- `..%2F..%2F..%2Fetc%2Fpasswd`
- `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`
- `....\\\\....\\\\....\\\\windows\\\\win.ini`

**Arquivos alvos:**
- `/etc/passwd` (Linux)
- `windows/win.ini` (Windows)

---

### 5. **Information Disclosure** ✅
**Severidade:** LOW/MEDIUM/HIGH  
**Descrição:** Detecta exposição de informações sensíveis  
**Padrões detectados:**
- Endereços de email
- API keys
- Senhas em texto
- Chaves privadas (RSA, DSA, EC)
- AWS Access Keys
- Strings de conexão de banco
- IPs internos (10.x, 172.x, 192.168.x)
- Mensagens de debug/erro
- Headers de servidor (Server, X-Powered-By)

---

### 6. **Port Scan (Nmap Integration)** ✅ **NOVO!**
**Severidade:** INFO  
**Descrição:** Escaneia portas abertas do servidor alvo usando Nmap  
**Funcionalidades:**
- Top 100 portas mais comuns
- Identificação de serviços
- Detecção de versões
- Estado das portas (open/filtered)

**Requisito:** Nmap instalado no sistema
```bash
sudo apt install nmap  # Linux
brew install nmap      # macOS
```

---

### 7. **Security Headers Check** ✅ **NOVO!**
**Severidade:** LOW/MEDIUM/HIGH  
**Descrição:** Verifica ausência de headers de segurança importantes  
**Headers verificados:**
- `X-Frame-Options` (previne clickjacking)
- `X-Content-Type-Options` (previne MIME sniffing)
- `Strict-Transport-Security` (força HTTPS)
- `Content-Security-Policy` (previne XSS/data injection)
- `X-XSS-Protection` (proteção XSS em browsers antigos)
- `Referrer-Policy` (controla informação de referrer)
- `Permissions-Policy` (controla APIs do browser)

---

### 8. **SSL/TLS Configuration Check** ✅ **NOVO!**
**Severidade:** HIGH (se vulnerável)  
**Descrição:** Verifica configuração SSL/TLS do servidor  
**Verificações:**
- Protocolo utilizado (SSLv2, SSLv3, TLS1.0, TLS1.1, TLS1.2, TLS1.3)
- Cipher suite
- Força da criptografia (bits)
- Certificado (emissor, subject)
- Protocolos fracos (SSLv2, SSLv3, TLSv1.0, TLSv1.1)

---

### 9. **XXE (XML External Entity)** ✅ **NOVO!**
**Severidade:** HIGH  
**Descrição:** Detecta potencial vulnerabilidade a ataques XXE  
**Verificação:**
- Processa XML?
- Possui declarações DOCTYPE
- Possui declarações ENTITY
- Permite SYSTEM entities
- Permite PUBLIC entities

---

### 10. **SSRF (Server-Side Request Forgery)** ✅ **NOVO!**
**Severidade:** HIGH  
**Descrição:** Identifica parâmetros suspeitos que podem ser usados para SSRF  
**Parâmetros suspeitos:**
- `url`, `uri`, `path`
- `dest`, `destination`, `redirect`
- `next`, `target`, `rurl`
- `link`, `load`, `file`
- `document`, `folder`, `root`
- `page`, `html`, `feed`

---

### 11. **Open Redirect** ✅ **NOVO!**
**Severidade:** MEDIUM  
**Descrição:** Detecta redirecionamentos não validados  
**Verificação:**
- Parâmetros de redirecionamento
- Valor do parâmetro aparece no Location header
- Status code 301/302/303/307/308

---

### 12. **CORS Misconfiguration** ✅ **NOVO!**
**Severidade:** MEDIUM/HIGH  
**Descrição:** Detecta configurações incorretas de CORS  
**Verificações:**
- `Access-Control-Allow-Origin: *` + credentials (HIGH)
- `Access-Control-Allow-Origin: *` (MEDIUM)
- Origens muito permissivas

---

### 13. **Dangerous HTTP Methods** ✅ **NOVO!**
**Severidade:** MEDIUM  
**Descrição:** Verifica se métodos HTTP perigosos estão habilitados  
**Métodos verificados:**
- `PUT` (upload de arquivos)
- `DELETE` (remoção de recursos)
- `TRACE` (vulnerável a XST)
- `CONNECT` (proxy)

---

## Estatísticas de Detecção

### Testes Realizados em Sites Vulneráveis Conhecidos

**Site:** http://testphp.vulnweb.com/listproducts.php?cat=1

**Resultados:**
```
✓ Port Scan: 2 portas abertas detectadas
✓ XSS: Detectado em parâmetro 'cat'
✓ SQL Injection: Detectado em parâmetro 'cat'
✓ XSS em formulário: Detectado em campo 'searchFor'
✓ SQL Injection em formulário: Detectado em campo 'searchFor'
✓ CSRF: Formulário sem token detectado
✓ Information Disclosure: 3 itens expostos
✓ Missing Security Headers: 7 headers faltando
```

**Total:** 8+ vulnerabilidades detectadas em um único scan

---

## Cobertura OWASP Top 10 (2021)

| # | Vulnerabilidade | Status | Ferramentas |
|---|----------------|--------|-------------|
| A01 | Broken Access Control | ✅ Parcial | CSRF, Open Redirect, HTTP Methods |
| A02 | Cryptographic Failures | ✅ | SSL/TLS Check, Information Disclosure |
| A03 | Injection | ✅ Completo | XSS, SQL Injection, XXE |
| A04 | Insecure Design | ✅ Parcial | Security Headers, CORS |
| A05 | Security Misconfiguration | ✅ Completo | Security Headers, HTTP Methods, CORS, SSL/TLS |
| A06 | Vulnerable Components | ⚠️ Info | Information Disclosure (versões) |
| A07 | Authentication Failures | ⚠️ Planejado | - |
| A08 | Software/Data Integrity | ✅ | XXE, Information Disclosure |
| A09 | Security Logging | ⚠️ Info | Todos logs são registrados |
| A10 | SSRF | ✅ | SSRF Detection, Open Redirect |

**Legenda:**
- ✅ Completo: Detecção implementada e testada
- ✅ Parcial: Detecção parcial implementada
- ⚠️ Info: Informações coletadas mas sem detecção ativa
- ⚠️ Planejado: Planejado para próximas versões

---

## Uso das Ferramentas

### Interface Web (Dashboard)

```bash
# Iniciar servidor
python src/web_app.py

# Acessar
http://localhost:8080

# Login
admin / admin123
```

**Funcionalidades:**
1. **New Scan:** Inicia varredura completa
2. **Results:** Visualiza vulnerabilidades encontradas
3. **History:** Histórico de scans
4. **Dashboard:** Estatísticas e resumo

### Interface CLI

```bash
# Scan completo
python src/main.py -u "http://target.com"

# Scan com múltiplos relatórios
python src/main.py -u "http://target.com" \
  -o report.txt \
  --json report.json \
  --csv report.csv \
  --markdown report.md

# Scan verbose (detalhado)
python src/main.py -u "http://target.com" -v
```

---

## Arquitetura das Ferramentas

```
scanner.py (Motor Principal)
├── XSS Detection
├── SQL Injection Detection
├── CSRF Detection
├── Directory Traversal Detection
├── Information Disclosure Detection
└── Advanced Scanner Integration ↓

utils/advanced_scanner.py (Ferramentas Avançadas)
├── Nmap Port Scanner
├── Security Headers Check
├── SSL/TLS Configuration Check
├── XXE Detection
├── SSRF Parameter Detection
├── Open Redirect Detection
├── CORS Misconfiguration Check
└── HTTP Methods Check
```

---

## Performance

### Tempo Médio de Scan

| Tipo de Alvo | Tempo Estimado | Ferramentas Executadas |
|--------------|----------------|------------------------|
| URL simples | 5-15 segundos | Todas exceto Nmap |
| URL simples + Nmap | 10-60 segundos | Todas incluindo Nmap |
| Formulário complexo | 20-40 segundos | Todas exceto Nmap |
| Site completo | 60-180 segundos | Todas |

### Recursos Utilizados

- **CPU:** Baixo (< 10% em scan normal)
- **Memória:** ~50-100 MB
- **Rede:** Dependente do alvo (múltiplas requisições)
- **Nmap:** Adiciona ~5-60 segundos ao scan

---

## Configuração e Dependências

### Dependências Python

```txt
requests>=2.31.0          # HTTP client
beautifulsoup4>=4.12.0    # HTML parsing
urllib3>=2.0.0            # URL utilities
lxml>=4.9.0               # XML parsing
flask>=3.0.0              # Web framework
flask-login>=0.6.0        # Authentication
plotly>=5.18.0            # Visualizations
pandas>=2.0.0             # Data manipulation
python-nmap>=0.7.1        # Nmap integration
```

### Dependências do Sistema

```bash
# Nmap (opcional mas recomendado)
sudo apt install nmap         # Ubuntu/Debian
sudo yum install nmap         # CentOS/RHEL
brew install nmap             # macOS

# Python 3.8+
python3 --version

# Pip
pip --version
```

---

## Limitações Conhecidas

### 1. JavaScript Rendering
- **Limitação:** Não executa JavaScript
- **Impacto:** SPAs e aplicações React/Vue/Angular podem não ser totalmente testadas
- **Solução Futura:** Integrar Selenium/Playwright

### 2. Autenticação
- **Limitação:** Não faz login automático
- **Impacto:** Áreas autenticadas não são testadas
- **Solução Futura:** Suporte a cookies/sessões

### 3. Rate Limiting
- **Limitação:** Pode ser bloqueado por WAFs
- **Impacto:** Scans incompletos em sites protegidos
- **Solução Atual:** Delays configuráveis entre requisições

### 4. Falsos Positivos
- **Taxa:** ~5-10% dependendo da ferramenta
- **Mais comum em:** Information Disclosure, Security Headers
- **Mitigação:** Verificação manual recomendada

### 5. Nmap Availability
- **Limitação:** Requer Nmap instalado no sistema
- **Impacto:** Port scan desabilitado se não disponível
- **Solução:** Instalar Nmap separadamente

---

## Próximas Melhorias Planejadas

### Curto Prazo (1-2 meses)
- [ ] Autenticação automática (cookies, sessions)
- [ ] WebSocket scanning
- [ ] GraphQL endpoint detection
- [ ] Subdomain enumeration
- [ ] Rate limiting inteligente

### Médio Prazo (3-6 meses)
- [ ] JavaScript rendering com Selenium
- [ ] API REST scanning
- [ ] Broken authentication detection
- [ ] Session management testing
- [ ] Upload vulnerabilities

### Longo Prazo (6-12 meses)
- [ ] Machine Learning para detecção heurística
- [ ] Mobile app scanning
- [ ] Docker container scanning
- [ ] Kubernetes security assessment
- [ ] Compliance reports (PCI-DSS, HIPAA)

---

## Comparação com Outras Ferramentas

| Ferramenta | Tipo | XSS | SQLi | CSRF | Nmap | Headers | SSL/TLS | Facilidade |
|------------|------|-----|------|------|------|---------|---------|-----------|
| **Web Security Scanner** | Open | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⭐⭐⭐⭐⭐ |
| OWASP ZAP | Open | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ⭐⭐⭐ |
| Burp Suite | Commercial | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ⭐⭐ |
| Nikto | Open | ⚠️ | ⚠️ | ❌ | ❌ | ✅ | ✅ | ⭐⭐⭐⭐ |
| Nmap | Open | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | ⭐⭐⭐⭐ |
| SQLMap | Open | ❌ | ✅✅ | ❌ | ❌ | ❌ | ❌ | ⭐⭐⭐ |

---

## Aviso Legal

**⚠️ USO APENAS EM AMBIENTES AUTORIZADOS ⚠️**

Esta ferramenta deve ser usada APENAS:
- Em aplicações próprias
- Com autorização por escrito
- Em ambientes de teste controlados
- Para fins educacionais legítimos

**NÃO USE em:**
- Sites de terceiros sem permissão
- Ambientes de produção sem consentimento
- Qualquer sistema onde você não tem autorização legal

O uso não autorizado de ferramentas de teste de penetração pode ser ILEGAL e resultar em:
- Processo criminal
- Multas pesadas
- Prisão
- Ações civis

---

## Suporte e Documentação

### Documentação Completa
- `docs/architecture.md` - Arquitetura do sistema
- `docs/flowchart.md` - Fluxograma de execução
- `docs/technical_report.md` - Relatório técnico detalhado
- `docs/video_guide.md` - Guia para demonstração em vídeo
- `README.md` - Guia de uso

### Logs
Todos os scans são registrados em:
- Console (tempo real)
- Arquivo `scanner.log` (histórico)

### Issues e Bugs
Reporte problemas no repositório GitHub com:
- Descrição detalhada
- Steps to reproduce
- Logs relevantes
- Versão do Python e sistema operacional

---

## Créditos

**Desenvolvido por:**
- Stefano Lindenbojm
- João Eduardo

**Disciplina:**
- Tecnologias Hackers - Insper
- Professor: Rodolfo Avelino

**Tecnologias Utilizadas:**
- Python 3.10+
- Flask
- BeautifulSoup4
- Nmap
- requests
- pandas

**Inspiração:**
- OWASP Top 10
- OWASP ZAP
- Burp Suite
- Nikto

---

**Versão:** 2.1.0  
**Data:** 31 de Outubro de 2025  
**Status:** Produção ✅

---

## Changelog

### v2.1.0 (31/10/2025) - NOVO!
- ✅ Adicionado Nmap integration para port scanning
- ✅ Adicionado Security Headers check (7 headers)
- ✅ Adicionado SSL/TLS configuration check
- ✅ Adicionado XXE detection
- ✅ Adicionado SSRF parameter detection
- ✅ Adicionado Open Redirect detection
- ✅ Adicionado CORS misconfiguration check
- ✅ Adicionado Dangerous HTTP Methods check
- ✅ Melhorado Information Disclosure detection
- ✅ Adicionado severity dinâmica baseada em tipo
- ✅ Total: 13 ferramentas de detecção

### v2.0.0 (30/10/2025)
- ✅ Implementação Conceito A completo
- ✅ Dashboard interativo
- ✅ Sistema de autenticação
- ✅ Docker containerization
- ✅ CI/CD com GitHub Actions

### v1.0.0 (29/10/2025)
- ✅ Conceito C: CLI básico
- ✅ XSS e SQL Injection detection
- ✅ Conceito B: 5 vulnerabilidades
- ✅ Múltiplos formatos de relatório
