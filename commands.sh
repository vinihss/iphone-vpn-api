#!/bin/sh
set -eu
case "${1:-}" in
  init) python3 api.py init ;;
  token|rotate-token) python3 api.py rotate-token ;;
  serve) shift; python3 api.py serve "$@" ;;
  *) echo "Uso: $0 {init|rotate-token|serve [--host HOST] [--port PORT]}"; exit 2 ;;
esac
