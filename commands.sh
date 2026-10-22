#!/bin/sh
set -eu
if command -v python3 >/dev/null 2>&1; then PY=python3; else PY=python; fi
case "${1:-}" in
  "") exec "$PY" api.py --help ;;
  test) sh tests/cli.sh ;;
  test-http) sh tests/integration.sh ;;
  token) shift; exec "$PY" api.py rotate-token "$@" ;;
  *) exec "$PY" api.py "$@" ;;
esac
