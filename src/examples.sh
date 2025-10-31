#!/bin/bash
# Script de exemplo para testar o Web Security Scanner

# Ativar ambiente virtual se não estiver ativo
if [[ "$VIRTUAL_ENV" == "" ]]; then
    echo "Ativando ambiente virtual..."
    cd /home/dt/Documents/pf_techack
    source venv/bin/activate
    cd src
fi

echo "=============================================="
echo "Web Security Scanner - Examples"
echo "=============================================="
echo ""

# Cores para output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}AVISO: Use apenas em aplicações para as quais você tem autorização!${NC}"
echo ""

# Exemplo 1: Site de teste público
echo -e "${GREEN}Exemplo 1: Testando site vulnerável público${NC}"
echo "Comando: python3 main.py -u http://testphp.vulnweb.com/listproducts.php?cat=1"
echo ""
read -p "Pressione ENTER para executar ou Ctrl+C para cancelar..."
python3 main.py -u "http://testphp.vulnweb.com/listproducts.php?cat=1"
echo ""

# Exemplo 2: Com saída em arquivo
echo -e "${GREEN}Exemplo 2: Gerando relatório em arquivo${NC}"
echo "Comando: python3 main.py -u http://testphp.vulnweb.com/artists.php?artist=1 -o report_exemplo.txt"
echo ""
read -p "Pressione ENTER para executar ou Ctrl+C para cancelar..."
python3 main.py -u "http://testphp.vulnweb.com/artists.php?artist=1" -o report_exemplo.txt
echo ""

# Exemplo 3: Com JSON
echo -e "${GREEN}Exemplo 3: Gerando relatório JSON${NC}"
echo "Comando: python3 main.py -u http://testphp.vulnweb.com/search.php?test=query --json report_exemplo.json"
echo ""
read -p "Pressione ENTER para executar ou Ctrl+C para cancelar..."
python3 main.py -u "http://testphp.vulnweb.com/search.php?test=query" --json report_exemplo.json
echo ""

echo "=============================================="
echo "Exemplos concluídos!"
echo "=============================================="
echo ""
echo "Sites de teste recomendados para prática:"
echo "  - http://testphp.vulnweb.com (online)"
echo "  - DVWA (local - docker)"
echo "  - OWASP Juice Shop (local - docker)"
echo "  - WebGoat (local - docker)"
