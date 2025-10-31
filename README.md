# Web Security Scanner

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/flask-3.0+-green.svg)
![Docker](https://img.shields.io/badge/docker-ready-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

Uma ferramenta automatizada completa para avaliação de segurança em aplicações web, com interface web interativa e suporte a múltiplas vulnerabilidades do OWASP Top 10.

## Descrição

Esta ferramenta realiza varreduras automatizadas em aplicações web para identificar vulnerabilidades de segurança, incluindo:

- **XSS (Cross-Site Scripting)** - Detecção de injeção de scripts maliciosos
- **SQL Injection** - Identificação de vulnerabilidades de injeção SQL
- **CSRF (Cross-Site Request Forgery)** - Verificação de proteção contra CSRF
- **Directory Traversal** - Detecção de acesso não autorizado a arquivos
- **Information Disclosure** - Identificação de exposição de informações sensíveis

## Características

### Conceito C - Básico
-  Varredura simples de URLs e parâmetros
-  Detecção de XSS e SQL Injection
-  Interface de linha de comando (CLI)
-  Relatórios em formato texto e JSON
-  Logs detalhados de execução

### Conceito B - Automação e Integração
-  Detecção de múltiplas vulnerabilidades (5 tipos OWASP Top 10)
-  Interface web simples com Flask
-  Relatórios em JSON, CSV e Markdown
-  Automação completa via CLI e Web

### Conceito A - Análise Avançada e Dashboard
-  Análise heurística com score de risco (0-100)
-  Priorização de vulnerabilidades por severidade
-  Dashboard interativo com estatísticas
-  Recomendações detalhadas de mitigação
-  Sistema de autenticação (multi-usuário)
-  Containerização com Docker
-  Histórico de scans por usuário

## Instalação

### Pré-requisitos

- Python 3.8 ou superior
- pip (gerenciador de pacotes Python)
- Docker (opcional, para execução em container)

### Passos de Instalação

1. Clone o repositório:
```bash
git clone https://github.com/stefanolinden/pf_techack.git
cd pf_techack
```

2. Crie e ative o ambiente virtual:
```bash
# Criar ambiente virtual
python3 -m venv venv

# Ativar ambiente virtual (Linux/Mac)
source venv/bin/activate

# Ativar ambiente virtual (Windows)
# venv\Scripts\activate
```

3. Instale as dependências:
```bash
pip install -r src/requirements.txt
```

## Uso

### Interface Web (Recomendado)

1. Iniciar o servidor web:
```bash
python src/web_app.py
```

2. Acesse: http://localhost:8080

3. Credenciais padrão:
   - **Admin**: admin / admin123
   - **Demo**: demo / demo123

### Interface CLI

Escanear uma URL (certifique-se de que o ambiente virtual está ativado):
```bash
python src/main.py -u http://example.com
```

### Opções Disponíveis (CLI)

```bash
python src/main.py -u <URL> [opções]

Opções:
  -u, --url URL         URL alvo para escanear (obrigatório)
  -o, --output FILE     Arquivo de saída para relatório texto
  --json FILE           Arquivo de saída para relatório JSON
  --csv FILE            Arquivo de saída para relatório CSV
  --markdown FILE       Arquivo de saída para relatório Markdown
  -v, --verbose         Ativar logging detalhado
  --version             Mostrar versão do programa
  -h, --help            Mostrar mensagem de ajuda
```

### Exemplos CLI

1. Escanear e exibir resultado no console:
```bash
python src/main.py -u http://testphp.vulnweb.com
```

2. Gerar múltiplos formatos de relatório:
```bash
python src/main.py -u http://example.com -o report.txt --json report.json --csv report.csv --markdown report.md
```

3. Modo verbose (detalhado):
```bash
python src/main.py -u http://example.com -v
```

## Uso com Docker

### Build e Run

```bash
# Build da imagem
docker build -t web-security-scanner .

# Executar interface web
docker run -p 8080:8080 web-security-scanner

# Executar CLI
docker run web-security-scanner python main.py -u http://example.com
```

### Docker Compose

```bash
# Iniciar serviços
docker-compose up -d

# Acessar: http://localhost:8080

# Parar serviços
docker-compose down
```

## Formato dos Relatórios

### Relatório Texto

O relatório texto inclui:
- URL alvo e data do scan
- Total de vulnerabilidades encontradas
- Sumário por severidade (CRITICAL, HIGH, MEDIUM, LOW)
- Detalhes de cada vulnerabilidade:
  - Tipo
  - Severidade
  - URL afetada
  - Parâmetro vulnerável
  - Payload usado
  - Descrição
  - Evidência

### Relatório JSON

Formato estruturado com:
```json
{
  "target_url": "http://example.com",
  "scan_date": "2025-10-31T10:30:00",
  "total_vulnerabilities": 2,
  "vulnerabilities": [
    {
      "type": "XSS (Cross-Site Scripting)",
      "severity": "HIGH",
      "url": "http://example.com/search?q=test",
      "parameter": "q",
      "payload": "<script>alert('XSS')</script>",
      "description": "XSS vulnerability detected...",
      "evidence": "..."
    }
  ]
}
```

## Estrutura do Projeto

```
pf_techack/
├── src/
│   ├── scanner.py              # Motor de varredura (5 tipos de vulnerabilidades)
│   ├── report_generator.py     # Gerador de relatórios (TXT, JSON, CSV, MD)
│   ├── main.py                 # Interface CLI
│   ├── web_app.py              # Interface Web com Flask
│   ├── requirements.txt        # Dependências Python
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── http_client.py      # Cliente HTTP e parsing
│   │   ├── logger.py           # Sistema de logging
│   │   └── analysis.py         # Análise heurística e scoring
│   ├── templates/              # Templates HTML para web interface
│   │   ├── base.html
│   │   ├── login.html
│   │   ├── dashboard.html
│   │   ├── scan.html
│   │   ├── results.html
│   │   └── history.html
│   └── tests/
│       ├── __init__.py
│       └── test_scanner.py     # Testes unitários
├── docs/
│   ├── installation_guide.md   # Guia de instalação
│   ├── technical_report.md     # Documentação técnica
│   └── docker_guide.md         # Guia Docker
├── .github/
│   └── workflows/              # CI/CD (futuro)
├── Dockerfile                  # Containerização
├── docker-compose.yml          # Orquestração Docker
├── .gitignore
├── README.md
└── venv/                       # Ambiente virtual Python
```




## Testando a Ferramenta

Para testar a ferramenta, recomendamos usar aplicações web intencionalmente vulneráveis:

- [DVWA (Damn Vulnerable Web Application)](http://www.dvwa.co.uk/)
- [WebGoat](https://owasp.org/www-project-webgoat/)
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
- [testphp.vulnweb.com](http://testphp.vulnweb.com)

## Tecnologias Utilizadas

### Backend
- **Python 3.8+**
- **Flask 3.0+** - Framework web
- **Flask-Login** - Sistema de autenticação
- **requests** - Requisições HTTP
- **BeautifulSoup4** - Parsing HTML
- **urllib3** - Manipulação de URLs

### Frontend
- **Bootstrap 5** - Framework CSS
- **Font Awesome** - Ícones
- **Plotly** - Gráficos (futuro)

### DevOps
- **Docker** - Containerização
- **Docker Compose** - Orquestração

## Autores

- Stefano Lindenbojm

## Licença

Este projeto é desenvolvido para fins educacionais como parte da disciplina Tecnologias Hackers do Insper.

## Status de Implementação

### Conceito C - COMPLETO
-  Varredura simples sobre URLs e parâmetros
-  Detecção de XSS e SQL Injection
-  Interface CLI
-  Relatórios básicos (TXT, JSON)

### Conceito B - COMPLETO
-  Detecção de 5 vulnerabilidades OWASP Top 10
-  Interface web com Flask
-  Relatórios em CSV e Markdown
-  Automação completa

### Conceito A - COMPLETO
-  Análise heurística com score de risco
-  Dashboard interativo
-  Recomendações de mitigação
-  Sistema de autenticação
-  Containerização Docker
-  Histórico de scans

## Suporte

Para dúvidas ou problemas, abra uma issue no GitHub.

---

**Desenvolvido para aprendizado em segurança da informação**
