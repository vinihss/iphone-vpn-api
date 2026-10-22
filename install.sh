#!/bin/sh
set -eu
python3 api.py init
python3 api.py rotate-token
echo "Inicializado. Guarde a credencial mostrada acima."
