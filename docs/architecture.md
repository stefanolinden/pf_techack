# Arquitetura do Sistema - Web Security Scanner

## Visão Geral

```
┌─────────────────────────────────────────────────────────────────────┐
│                          USUÁRIO                                     │
└────────────────┬───────────────────────┬────────────────────────────┘
                 │                       │
                 │ CLI                   │ Web Browser
                 │                       │
        ┌────────▼────────┐    ┌────────▼──────────┐
        │   main.py       │    │   web_app.py      │
        │   (CLI)         │    │   (Flask)         │
        └────────┬────────┘    └────────┬──────────┘
                 │                      │
                 │                      │ Flask-Login
                 │                      │ Authentication
                 │                      │
                 └──────────┬───────────┘
                            │
                   ┌────────▼──────────┐
                   │   scanner.py      │
                   │ VulnerabilityScanner│
                   └────────┬──────────┘
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
    ┌─────▼─────┐  ┌───────▼────────┐  ┌────▼─────┐
    │HTTP Client│  │  Detection      │  │Analysis  │
    │(requests) │  │  Engines        │  │(scoring) │
    └─────┬─────┘  └───────┬────────┘  └────┬─────┘
          │                │                 │
          │        ┌───────┴────────┐        │
          │        │  • XSS         │        │
          │        │  • SQLi        │        │
          │        │  • CSRF        │        │
          │        │  • Dir Trav.   │        │
          │        │  • Info Disc.  │        │
          │        └───────┬────────┘        │
          │                │                 │
          └────────────────┼─────────────────┘
                           │
                  ┌────────▼──────────┐
                  │ Report Generator  │
                  │  • TXT            │
                  │  • JSON           │
                  │  • CSV            │
                  │  • Markdown       │
                  └────────┬──────────┘
                           │
                  ┌────────▼──────────┐
                  │   OUTPUT          │
                  │ • Console         │
                  │ • Files           │
                  │ • Dashboard       │
                  └───────────────────┘
```

## Componentes Principais

### 1. Interface Layer
- **CLI (main.py)**: Interface de linha de comando
- **Web (web_app.py)**: Interface web Flask com dashboard

### 2. Core Scanner (scanner.py)
- **VulnerabilityScanner**: Motor principal de varredura
- Detecta 5 tipos de vulnerabilidades OWASP Top 10

### 3. Detection Engines
- **XSS Detection**: 5 payloads diferentes
- **SQL Injection**: 7 payloads + padrões de erro
- **CSRF Detection**: Verificação de tokens
- **Directory Traversal**: 6 payloads
- **Information Disclosure**: 7 tipos de dados

### 4. Utils Layer
- **http_client.py**: Cliente HTTP e parsing
- **logger.py**: Sistema de logging
- **analysis.py**: Análise heurística e scoring

### 5. Report Layer
- **report_generator.py**: Geração de relatórios multi-formato

## Fluxo de Execução

### Fluxo CLI:
```
1. Usuário executa: python main.py -u URL
2. Main.py inicializa VulnerabilityScanner
3. Scanner faz requisição HTTP ao alvo
4. Para cada parâmetro/formulário:
   a. Injeta payloads de teste
   b. Analisa resposta
   c. Identifica vulnerabilidades
5. Gera relatório nos formatos solicitados
6. Exibe resultado no console
```

### Fluxo Web:
```
1. Usuário acessa http://localhost:8080
2. Sistema exige autenticação (Flask-Login)
3. Após login, acessa dashboard
4. Usuário inicia novo scan
5. Scanner executa em background
6. Resultados são armazenados no histórico
7. Dashboard exibe:
   - Score de risco
   - Lista de vulnerabilidades
   - Recomendações de mitigação
8. Usuário pode baixar relatórios
```

## Tecnologias Utilizadas

### Backend
- Python 3.10+
- Flask 3.0+ (Web Framework)
- Flask-Login (Autenticação)
- Requests (HTTP Client)
- BeautifulSoup4 (HTML Parsing)

### Frontend
- Bootstrap 5 (CSS Framework)
- Font Awesome (Ícones)
- Jinja2 (Template Engine)

### DevOps
- Docker (Containerização)
- Docker Compose (Orquestração)
- GitHub Actions (CI/CD)

## Segurança

### Princípios Implementados:
1. **Autenticação**: Sistema de login multi-usuário
2. **Isolamento**: Cada scan armazenado por usuário
3. **Validação**: Validação de URLs antes de scan
4. **Logging**: Registro completo de atividades
5. **Containerização**: Isolamento via Docker

## Escalabilidade

### Melhorias Futuras:
- Banco de dados real (PostgreSQL/MongoDB)
- Fila de processamento (Celery/RabbitMQ)
- Cache (Redis)
- Load balancing
- Integração com APIs externas (OWASP ZAP)

## Performance

### Otimizações Implementadas:
- Validação de URLs antes de scan
- Limite de payloads por vulnerabilidade
- Timeout configurável em requisições
- Cache de URLs já escaneadas

## Deployment

### Opções de Deploy:
1. **Local**: `python src/web_app.py`
2. **Docker**: `docker-compose up -d`
3. **Cloud**: Heroku, AWS, GCP, Azure
