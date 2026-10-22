#!/bin/sh
set -eu
BASE_URL="https://raw.githubusercontent.com/vinihss/iphone-vpn-api/main"
fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$BASE_URL/$1" -o "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$1" "$BASE_URL/$1"
  else
    echo "Erro: curl ou wget é necessário."; exit 1
  fi
}
fetch api.py
fetch commands.sh
chmod +x commands.sh 2>/dev/null || true
if command -v python3 >/dev/null 2>&1; then PY=python3; else PY=python; fi
$PY api.py init
$PY api.py rotate-token
echo "Inicializado. Guarde a credencial mostrada acima."
echo "Ajuda do modo CLI: $PY api.py --help  (ou ./commands.sh)"
