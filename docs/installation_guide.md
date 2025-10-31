# Guia de Instalação e Uso - Web Security Scanner

## Instalação

### Requisitos do Sistema
- Python 3.8 ou superior
- pip (gerenciador de pacotes Python)
- Conexão com internet
- Sistema operacional: Linux, macOS ou Windows

### Passo a Passo

#### 1. Clone o repositório
```bash
git clone https://github.com/stefanolinden/pf_techack.git
cd pf_techack
```

#### 2. Crie e ative o ambiente virtual (recomendado)
```bash
# Criar ambiente virtual
python3 -m venv venv

# Ativar ambiente virtual (Linux/Mac)
source venv/bin/activate

# Ativar ambiente virtual (Windows)
# venv\Scripts\activate
```

#### 3. Instale as dependências
```bash
pip install -r src/requirements.txt
```

#### 4. Verifique a instalação
```bash
python src/main.py --version
```

Você deve ver:
```
Web Security Scanner 1.0.0
```

#### 5. Execute os testes (opcional)
```bash
python src/tests/test_scanner.py
```

## Uso Básico

### Sintaxe Geral
```bash
python src/main.py -u <URL> [opções]
```

### Opções Disponíveis

| Opção | Descrição |
|-------|-----------|
| `-u, --url URL` | URL alvo para escanear (obrigatório) |
| `-o, --output FILE` | Salvar relatório texto em arquivo |
| `--json FILE` | Salvar relatório JSON em arquivo |
| `-v, --verbose` | Modo detalhado (verbose) |
| `--version` | Mostrar versão |
| `-h, --help` | Mostrar ajuda |

## Exemplos Práticos

### Exemplo 1: Scan Simples
```bash
python3 main.py -u http://example.com
```

**Saída esperada**:
```
================================================================================
WEB SECURITY SCANNER v1.0.0
================================================================================
Target: http://example.com
Started: 2025-10-31 14:30:00
================================================================================

Scanning for vulnerabilities...
Testing for: XSS, SQL Injection

...
```

### Exemplo 2: Testar Página com Parâmetros
```bash
python3 main.py -u "http://example.com/search.php?q=test&id=1"
```

### Exemplo 3: Salvar Relatório
```bash
python3 main.py -u http://example.com -o relatorio.txt
```

### Exemplo 4: Gerar JSON
```bash
python3 main.py -u http://example.com --json resultado.json
```

### Exemplo 5: Modo Verbose
```bash
python3 main.py -u http://example.com -v
```

### Exemplo 6: Relatório Completo
```bash
python3 main.py -u http://example.com -o relatorio.txt --json dados.json -v
```

## Interpretando os Resultados

### Níveis de Severidade

| Nível | Descrição | Ação Recomendada |
|-------|-----------|------------------|
| **CRITICAL** | SQL Injection | Corrigir imediatamente |
| **HIGH** | XSS | Corrigir com alta prioridade |
| **MEDIUM** | Exposição de informações | Avaliar e corrigir |
| **LOW** | Problemas menores | Corrigir quando possível |

### Estrutura do Relatório Texto

```
================================================================================
WEB SECURITY SCANNER - VULNERABILITY REPORT
================================================================================
Target URL: http://example.com
Scan Date: 2025-10-31 14:30:00
Total Vulnerabilities Found: 2
================================================================================

SUMMARY BY SEVERITY:
  CRITICAL: 1
  HIGH:     1
  MEDIUM:   0
  LOW:      0

--------------------------------------------------------------------------------

VULNERABILITY #1
Type:        SQL Injection
Severity:    CRITICAL
URL:         http://example.com/page?id=1' OR '1'='1
Parameter:   id
Payload:     ' OR '1'='1
Description: SQL Injection vulnerability detected in parameter "id"...
...
```

### Estrutura do Relatório JSON

```json
{
  "target_url": "http://example.com",
  "scan_date": "2025-10-31T14:30:00",
  "total_vulnerabilities": 2,
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "severity": "CRITICAL",
      "url": "http://example.com/page?id=1",
      "parameter": "id",
      "payload": "' OR '1'='1",
      "description": "...",
      "evidence": "..."
    }
  ]
}
```

## Sites de Teste Recomendados

### Sites Online (Legais para Teste)
1. **testphp.vulnweb.com** - Site intencionalmente vulnerável
   ```bash
   python3 main.py -u "http://testphp.vulnweb.com/listproducts.php?cat=1"
   ```

### Ambientes Locais (Docker)

#### DVWA (Damn Vulnerable Web Application)
```bash
docker run --rm -it -p 80:80 vulnerables/web-dvwa
python3 main.py -u "http://localhost/?id=1"
```

#### OWASP Juice Shop
```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop
python3 main.py -u "http://localhost:3000"
```

## Troubleshooting

### Erro: "No module named 'requests'"
**Solução**: Instale as dependências
```bash
pip install -r requirements.txt
```

### Erro: "Invalid URL"
**Solução**: Certifique-se de incluir http:// ou https://
```bash
# Errado:
python3 main.py -u example.com

# Correto:
python3 main.py -u http://example.com
```

### Erro: SSL Certificate
**Solução**: O scanner desabilita verificação SSL por padrão. Se houver problemas:
```bash
pip install --upgrade urllib3 requests
```

### Scan muito lento
**Solução**: 
- Use modo não-verbose
- Teste URLs específicas ao invés de páginas complexas
- Verifique sua conexão de internet

## Próximos Passos

Após dominar o uso básico, explore:

1. Testar diferentes tipos de formulários
2. Analisar relatórios JSON com ferramentas como `jq`
3. Integrar com pipelines CI/CD
4. Contribuir com melhorias no código

## Suporte

Para dúvidas ou problemas:
1. Verifique a documentação em `/docs`
2. Execute os testes: `python3 tests/test_scanner.py`
3. Abra uma issue no GitHub
4. Consulte os logs com `-v` para debug

---

**Importante**: Esta ferramenta é para fins educacionais. Use apenas em sistemas onde você tem autorização explícita.
