# Guia de Demonstração em Vídeo - Web Security Scanner

**Duração: 7 minutos (máximo)**

## Estrutura do Vídeo

### 1. INTRODUÇÃO (1 minuto)

**Cena 1 - Apresentação**
- Mostrar tela inicial do projeto
- Apresentar: "Web Security Scanner - Ferramenta de Avaliação de Segurança para Aplicações Web"
- Autores: Stefano Lindenbojm e João Eduardo
- Disciplina: Tecnologias Hackers - Insper

**Pontos a mencionar:**
- Objetivo: Detectar vulnerabilidades OWASP Top 10 em aplicações web
- 5 tipos de vulnerabilidades detectadas
- Interfaces CLI e Web Dashboard
- Containerização com Docker

---

### 2. DEMO CLI - Interface de Linha de Comando (1.5 minutos)

**Cena 2 - Terminal**

**Comandos a executar:**

```bash
# Mostrar help
python src/main.py --help

# Executar scan básico
python src/main.py -u http://testphp.vulnweb.com/listproducts.php?cat=1

# Gerar múltiplos relatórios
python src/main.py -u http://testphp.vulnweb.com/listproducts.php?cat=1 \
  -o report.txt --json report.json --csv report.csv --markdown report.md
```

**Pontos a mencionar:**
- Modo verbose (-v) para debugging
- Múltiplos formatos de saída
- Exit code indica presença de vulnerabilidades
- Logging detalhado de cada teste

**Mostrar arquivos gerados:**
- Abrir report.txt no editor
- Mostrar estrutura do report.json
- Visualizar tabela CSV
- Preview do Markdown

---

### 3. DEMO WEB - Dashboard Interativo (2.5 minutos)

**Cena 3 - Interface Web**

**Passo 1: Login**
```
http://localhost:8080
```
- Fazer login com: admin / admin123
- Explicar sistema de autenticação multi-usuário

**Passo 2: Dashboard**
- Mostrar cards de estatísticas:
  - Total de scans realizados
  - Total de vulnerabilidades encontradas
- Mostrar tabela de scans recentes
- Explicar risk levels (CRITICAL, HIGH, MEDIUM, LOW)

**Passo 3: Novo Scan**
- Clicar em "New Scan"
- Inserir URL: `http://testphp.vulnweb.com/listproducts.php?cat=1`
- Clicar em "Start Scan"
- Aguardar processamento (mostrar loading)

**Passo 4: Resultados**
- Visualizar página de resultados
- Destacar:
  - Risk Score (0-100)
  - Lista de vulnerabilidades por severidade
  - Detalhes de cada vulnerabilidade:
    - Tipo
    - URL afetada
    - Parâmetro vulnerável
    - Payload usado
    - Evidência
  - Recomendações de mitigação

**Passo 5: Histórico**
- Acessar "History"
- Mostrar lista de todos os scans
- Filtrar por data/severidade
- Comparar scans diferentes

---

### 4. DEMO DOCKER - Containerização (1 minuto)

**Cena 4 - Docker**

**Comandos a executar:**

```bash
# Build da imagem
docker build -t web-security-scanner .

# Executar container
docker-compose up -d

# Verificar container rodando
docker ps

# Acessar logs
docker logs pf_techack-web-scanner-1

# Acessar aplicação
# Abrir browser em http://localhost:8080
```

**Pontos a mencionar:**
- Portabilidade (funciona em qualquer ambiente)
- Isolamento de dependências
- Facilidade de deployment
- Configuração via docker-compose.yml

---

### 5. DEMONSTRAÇÃO DE VULNERABILIDADES REAIS (1 minuto)

**Cena 5 - Análise de Vulnerabilidades**

**Sites de teste recomendados:**
- http://testphp.vulnweb.com
- http://testphp.vulnweb.com/listproducts.php?cat=1 (SQL Injection)
- http://testphp.vulnweb.com/artists.php?artist=1 (XSS)

**Mostrar exemplos de cada tipo:**

1. **XSS (Cross-Site Scripting)**
   - Payload detectado no HTML de resposta
   - Severidade: CRITICAL

2. **SQL Injection**
   - Erro de sintaxe SQL na resposta
   - Severidade: CRITICAL

3. **CSRF (Cross-Site Request Forgery)**
   - Formulário sem token de proteção
   - Severidade: HIGH

4. **Directory Traversal**
   - Acesso a arquivos do sistema
   - Severidade: HIGH

5. **Information Disclosure**
   - Exposição de emails, API keys
   - Severidade: MEDIUM

---

### 6. ANÁLISE TÉCNICA (30 segundos)

**Cena 6 - Código Fonte**

**Mostrar rapidamente:**
- Estrutura do projeto (src/, docs/, tests/)
- scanner.py - Motor de detecção
- report_generator.py - Geração de relatórios
- utils/analysis.py - Análise heurística

**Destacar:**
- Arquitetura modular
- Testes unitários (9 testes, 100% passing)
- Documentação completa
- CI/CD com GitHub Actions

---

### 7. CONCLUSÃO (30 segundos)

**Cena 7 - Recapitulação**

**Resumir implementação:**

✓ **Conceito C:**
- CLI funcional
- Detecção XSS e SQLi
- Relatórios TXT e JSON

✓ **Conceito B:**
- 5 vulnerabilidades OWASP Top 10
- Interface Web com Flask
- 4 formatos de relatório

✓ **Conceito A:**
- Análise heurística com risk scoring
- Dashboard autenticado
- Recomendações de mitigação
- Docker containerizado
- CI/CD pipeline

**Mensagem final:**
- Ferramenta educacional para aprendizado em segurança
- Uso apenas em ambientes autorizados
- Código disponível no GitHub

---

## DICAS DE GRAVAÇÃO

### Preparação:
1. **Teste todos os comandos antes de gravar**
2. **Prepare o ambiente:**
   - Terminal limpo
   - Browser com abas preparadas
   - Arquivos de teste prontos
3. **Tenha um roteiro impresso**
4. **Faça um ensaio geral**

### Durante a gravação:
1. **Fale claramente e pausadamente**
2. **Use Zoom para destacar elementos importantes**
3. **Grave em resolução mínima 1080p**
4. **Use microfone de qualidade**
5. **Evite barulhos de fundo**

### Edição:
1. **Corte pausas longas**
2. **Adicione legendas com comandos executados**
3. **Use transições suaves entre cenas**
4. **Adicione música de fundo (opcional, baixa)**
5. **Verifique duração final (≤ 7 minutos)**

### Ferramentas recomendadas:
- **Gravação de tela:** OBS Studio, SimpleScreenRecorder
- **Edição:** DaVinci Resolve, Shotcut, OpenShot
- **Áudio:** Audacity
- **Conversão:** HandBrake

---

## CHECKLIST PRÉ-GRAVAÇÃO

### Ambiente:
- [ ] Servidor web rodando (python src/web_app.py)
- [ ] Docker instalado e funcionando
- [ ] Sites de teste acessíveis (testphp.vulnweb.com)
- [ ] Venv ativado
- [ ] Terminal com fonte legível (tamanho 14+)

### Arquivos:
- [ ] Código fonte atualizado
- [ ] Relatórios de exemplo gerados
- [ ] Screenshots preparados
- [ ] README.md atualizado

### Browser:
- [ ] Abas preparadas com URLs de teste
- [ ] Extensões desnecessárias desabilitadas
- [ ] Zoom em 100%
- [ ] Modo escuro (opcional, para contraste)

### Conteúdo:
- [ ] Roteiro revisado
- [ ] Comandos testados
- [ ] Tempo cronometrado (≤ 7 min)
- [ ] Transições planejadas

---

## EXEMPLO DE SCRIPT NARRADO

### INTRODUÇÃO
> "Olá, este é o Web Security Scanner, uma ferramenta desenvolvida para a disciplina Tecnologias Hackers do Insper. Sou Stefano Lindenbojm, junto com João Eduardo, e vamos demonstrar uma ferramenta que detecta automaticamente vulnerabilidades em aplicações web, focando no OWASP Top 10."

### CLI
> "Primeiro, vamos ver a interface de linha de comando. Executando o help, podemos ver todas as opções disponíveis. Agora vamos fazer um scan real em uma aplicação vulnerável de teste. Como podem ver, a ferramenta detectou várias vulnerabilidades, incluindo SQL Injection e XSS. Podemos gerar relatórios em múltiplos formatos simultaneamente."

### WEB
> "Agora a interface web. Após fazer login, temos um dashboard completo com estatísticas de todos os scans. Vamos iniciar um novo scan... A ferramenta está analisando a URL em busca de vulnerabilidades... E aqui está o resultado! Temos um risk score de 85, considerado crítico, com várias vulnerabilidades detectadas. Cada vulnerabilidade tem detalhes completos incluindo o payload usado e recomendações de mitigação."

### DOCKER
> "Para facilitar o deployment, a ferramenta está containerizada com Docker. Com um simples docker-compose up, toda a aplicação está rodando em um ambiente isolado."

### CONCLUSÃO
> "Esta ferramenta implementa todos os requisitos do Conceito A, incluindo análise heurística, dashboard autenticado, e containerização. Importante lembrar: use apenas em ambientes autorizados para fins educacionais. Obrigado!"

---

## TIMESTAMPS SUGERIDOS

- 00:00 - Introdução e apresentação
- 01:00 - Demo CLI
- 02:30 - Demo Web Dashboard
- 05:00 - Demo Docker
- 06:00 - Vulnerabilidades detectadas
- 06:30 - Análise técnica
- 07:00 - Conclusão

---

## RECURSOS VISUAIS RECOMENDADOS

### Overlays de texto:
- Nome da ferramenta no início
- Comandos executados
- URLs acessadas
- Resultados importantes (risk score, vulnerabilidades)

### Highlights:
- Círculo vermelho para destacar vulnerabilidades críticas
- Setas para indicar campos importantes
- Zoom em áreas de interesse

### Transições:
- Fade entre cenas
- Swipe para mudança de contexto
- Sem efeitos exagerados

---

**BOA SORTE COM A GRAVAÇÃO!**
