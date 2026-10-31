#!/usr/bin/env bash
set -euo pipefail
SOC_MIRROR_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SOC_MIRROR_DIR/miroir_soc.py" exporter "$@"
