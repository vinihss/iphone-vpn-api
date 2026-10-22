#!/bin/sh
set -eu
BASE_URL="https://raw.githubusercontent.com/vinihss/iphone-vpn-api/main"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$BASE_URL/api.py" -o api.py
elif command -v wget >/dev/null 2>&1; then
  wget -qO api.py "$BASE_URL/api.py"
else
  echo "Erro: curl ou wget é necessário."; exit 1
fi
if command -v python3 >/dev/null 2>&1; then PY=python3; else PY=python; fi
$PY api.py init
$PY api.py rotate-token
echo "Inicializado. Guarde a credencial mostrada acima."
