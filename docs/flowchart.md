# Fluxograma - Processo de Varredura de Vulnerabilidades

## Fluxo Principal de Scan

```
                              ┌──────────┐
                              │  INÍCIO  │
                              └────┬─────┘
                                   │
                              ┌────▼────┐
                              │ Recebe  │
                              │   URL   │
                              └────┬────┘
                                   │
                              ┌────▼────────┐
                              │  Valida URL │
                              │  (formato)  │
                              └────┬────────┘
                                   │
                        ┌──────────▼──────────┐
                        │   URL Válida?       │
                        └──────┬──────┬───────┘
                               │      │
                           SIM │      │ NÃO
                               │      │
                               │      └──────────────┐
                               │                     │
                     ┌─────────▼─────────┐    ┌─────▼──────┐
                     │ Faz Requisição    │    │   ERRO:    │
                     │ HTTP GET ao Alvo  │    │ URL Inválida│
                     └─────────┬─────────┘    └─────┬──────┘
                               │                     │
                     ┌─────────▼──────────┐          │
                     │ Conexão Sucesso?   │          │
                     └─────┬──────┬───────┘          │
                           │      │                  │
                       SIM │      │ NÃO              │
                           │      │                  │
                           │      └───────┐          │
                           │              │          │
                ┌──────────▼──────────┐   │          │
                │ Extrai Parâmetros  │   │          │
                │ - Query Params     │   │          │
                │ - Formulários      │   │          │
                └──────────┬─────────┘   │          │
                           │             │          │
                ┌──────────▼─────────┐   │          │
                │ Tem Parâmetros?    │   │          │
                └──────┬──────┬──────┘   │          │
                       │      │          │          │
                   SIM │      │ NÃO      │          │
                       │      │          │          │
                       │      └────┐     │          │
                       │           │     │          │
    ┌──────────────────▼──┐        │     │          │
    │ TESTES DE           │        │     │          │
    │ VULNERABILIDADES    │        │     │          │
    │                     │        │     │          │
    │ ┌─────────────────┐ │        │     │          │
    │ │  1. XSS         │ │        │     │          │
    │ │  - 5 payloads   │ │        │     │          │
    │ └────────┬────────┘ │        │     │          │
    │          │           │        │     │          │
    │ ┌────────▼────────┐ │        │     │          │
    │ │  2. SQLi        │ │        │     │          │
    │ │  - 7 payloads   │ │        │     │          │
    │ └────────┬────────┘ │        │     │          │
    │          │           │        │     │          │
    │ ┌────────▼────────┐ │        │     │          │
    │ │  3. CSRF        │ │        │     │          │
    │ │  - Token check  │ │        │     │          │
    │ └────────┬────────┘ │        │     │          │
    │          │           │        │     │          │
    │ ┌────────▼────────┐ │        │     │          │
    │ │  4. Dir Trav    │ │        │     │          │
    │ │  - 6 payloads   │ │        │     │          │
    │ └────────┬────────┘ │        │     │          │
    │          │           │        │     │          │
    │ ┌────────▼────────┐ │        │     │          │
    │ │  5. Info Disc   │ │        │     │          │
    │ │  - 7 patterns   │ │        │     │          │
    │ └────────┬────────┘ │        │     │          │
    └──────────┬──────────┘        │     │          │
               │                   │     │          │
               └─────────┬─────────┘     │          │
                         │               │          │
                    ┌────▼───────────────▼────┐     │
                    │ Coleta Resultados       │     │
                    │ - Vulnerabilidades      │     │
                    │ - Severidades           │     │
                    │ - Evidências            │     │
                    └────┬────────────────────┘     │
                         │                          │
                    ┌────▼──────────────────────┐   │
                    │ Análise Heurística        │   │
                    │ - Calcula Risk Score      │   │
                    │ - Prioriza Vulnerabs      │   │
                    │ - Gera Recomendações      │   │
                    └────┬──────────────────────┘   │
                         │                          │
                    ┌────▼────────────────────────┐ │
                    │ Geração de Relatórios       │ │
                    │ - TXT (Console/File)        │ │
                    │ - JSON (Estruturado)        │ │
                    │ - CSV (Tabular)             │ │
                    │ - Markdown (Documentação)   │ │
                    └────┬────────────────────────┘ │
                         │                          │
                    ┌────▼─────────────┐            │
                    │ Armazena no      │            │
                    │ Histórico        │            │
                    │ (se web mode)    │            │
                    └────┬─────────────┘            │
                         │                          │
                    ┌────▼────────────┐             │
                    │ Exibe Resultados│             │
                    │ - CLI: Console  │             │
                    │ - Web: Dashboard│             │
                    └────┬────────────┘             │
                         │                          │
                    ┌────▼──────┐                   │
                    │    FIM    │◄──────────────────┘
                    └───────────┘
```

## Detalhamento dos Testes de Vulnerabilidades

### 1. XSS (Cross-Site Scripting)
```
Para cada parâmetro:
  ├─ Injeta payload: <script>alert('XSS')</script>
  ├─ Injeta payload: <img src=x onerror=alert('XSS')>
  ├─ Injeta payload: <svg onload=alert('XSS')>
  ├─ Injeta payload: "><script>alert('XSS')</script>
  └─ Injeta payload: javascript:alert('XSS')
       │
       ├─ Faz requisição
       ├─ Verifica se payload está na resposta
       └─ Se SIM → Vulnerabilidade CRÍTICA
```

### 2. SQL Injection
```
Para cada parâmetro:
  ├─ Injeta: ' OR '1'='1
  ├─ Injeta: ' OR 1=1--
  ├─ Injeta: admin'--
  ├─ Injeta: ' UNION SELECT NULL--
  ├─ Injeta: 1' AND '1'='1
  ├─ Injeta: 1 OR 1=1
  └─ Injeta: '; DROP TABLE users--
       │
       ├─ Faz requisição
       ├─ Verifica erros SQL na resposta:
       │  - SQL syntax error
       │  - MySQL error
       │  - PostgreSQL error
       │  - Oracle error
       └─ Se encontrado → Vulnerabilidade CRÍTICA
```

### 3. CSRF (Cross-Site Request Forgery)
```
Para cada formulário encontrado:
  ├─ Extrai campos do formulário
  ├─ Procura por campo de token CSRF:
  │  - csrf_token
  │  - _csrf
  │  - authenticity_token
  └─ Se NÃO encontrado → Vulnerabilidade ALTA
```

### 4. Directory Traversal
```
Para cada parâmetro:
  ├─ Injeta: ../../../etc/passwd
  ├─ Injeta: ..\\..\\..\\windows\\win.ini
  ├─ Injeta: ....//....//....//etc/passwd
  ├─ Injeta: %2e%2e%2f%2e%2e%2f%2e%2e%2f
  ├─ Injeta: ..%252f..%252f..%252fetc/passwd
  └─ Injeta: file:///etc/passwd
       │
       ├─ Faz requisição
       ├─ Verifica indicadores na resposta:
       │  - root:x:0:0
       │  - for 16-bit app support
       │  - [extensions]
       └─ Se encontrado → Vulnerabilidade ALTA
```

### 5. Information Disclosure
```
Analisa conteúdo da resposta HTTP:
  ├─ Busca padrão: emails (@domain.com)
  ├─ Busca padrão: API keys (api_key=...)
  ├─ Busca padrão: AWS keys (AKIA...)
  ├─ Busca padrão: Private keys (-----BEGIN)
  ├─ Busca padrão: Database strings (jdbc:)
  ├─ Busca padrão: Internal IPs (192.168.x.x)
  └─ Busca padrão: Stack traces
       │
       └─ Para cada padrão encontrado → Vulnerabilidade MÉDIA
```

## Cálculo de Risk Score

```
┌─────────────────────┐
│ Vulnerabilidades    │
│ Detectadas          │
└──────────┬──────────┘
           │
    ┌──────▼──────┐
    │ Contagem:   │
    │ - CRITICAL  │
    │ - HIGH      │
    │ - MEDIUM    │
    │ - LOW       │
    └──────┬──────┘
           │
    ┌──────▼──────────────┐
    │ Peso por Severidade:│
    │ CRITICAL: 40 pontos │
    │ HIGH: 25 pontos     │
    │ MEDIUM: 15 pontos   │
    │ LOW: 10 pontos      │
    └──────┬──────────────┘
           │
    ┌──────▼──────────────┐
    │ Score = Σ (count × peso)
    │ Máximo: 100 pontos  │
    └──────┬──────────────┘
           │
    ┌──────▼────────────┐
    │ Classificação:    │
    │ 80-100: Crítico   │
    │ 50-79: Alto       │
    │ 20-49: Médio      │
    │ 0-19: Baixo       │
    └───────────────────┘
```

## Geração de Relatórios

```
┌───────────────────┐
│ Resultados +      │
│ Risk Score        │
└─────────┬─────────┘
          │
    ┌─────▼──────┐
    │ Formato?   │
    └─┬──┬──┬──┬─┘
      │  │  │  │
  TXT │  │  │  │ MD
      │  │  │  │
      │  │  │  └──────────┐
      │  │  │             │
      │  │  └───────┐     │
      │  │          │     │
      │  └────┐     │     │
      │       │     │     │
      ▼       ▼     ▼     ▼
   ┌────┐ ┌────┐ ┌───┐ ┌───┐
   │File│ │JSON│ │CSV│ │MD │
   │.txt│ │.json│.csv│ │.md│
   └────┘ └────┘ └───┘ └───┘
```

## Fluxo de Decisão - Interface

```
┌────────────────┐
│ Modo de Uso?   │
└───┬────────┬───┘
    │        │
  CLI│        │Web
    │        │
    ▼        ▼
┌────────┐ ┌──────────┐
│Console │ │Dashboard │
│Output  │ │Interface │
└────────┘ └────┬─────┘
              │
         ┌────▼────┐
         │Login?   │
         └──┬───┬──┘
            │   │
        SIM │   │ NÃO
            │   │
            │   └──────────┐
            │              │
      ┌─────▼─────┐   ┌────▼────┐
      │Dashboard  │   │Redirect │
      │Autorizado │   │to Login │
      └───────────┘   └─────────┘
```
