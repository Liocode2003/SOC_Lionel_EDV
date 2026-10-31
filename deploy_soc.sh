#!/usr/bin/env bash
# SOC neuf : pas d'export, pas de restauration, pas d'ancienne VM.
set -euo pipefail
SOC_AUTO_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${1:-}" == '--tests' ]]; then
    exec python3 -m unittest discover -s "$SOC_AUTO_DIR/tests" -v
fi
exec python3 "$SOC_AUTO_DIR/autonome.py" "$@"
