#!/usr/bin/env bash
# Installer sur Ubuntu 24.04 neuf, isolé du réseau de production/source.
set -euo pipefail
SOC_MIRROR_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${1:-}" == '--help' || "$#" -eq 0 ]]; then
    echo 'Usage : sudo bash installer_soc.sh --dossier /chemin/sauvegarde --vm-isolee'
    echo 'Réservé à Ubuntu 24.04 neuf. Installer les dépendances, puis restaurer sans démarrer le SOC.'
    exit 0
fi
[[ "$EUID" -eq 0 ]] || { echo 'Lancer avec sudo.' >&2; exit 1; }
[[ -f /etc/os-release ]] || exit 1
. /etc/os-release
[[ "$ID" == ubuntu && "$VERSION_ID" == 24.04 ]] || { echo 'Ubuntu 24.04 requis.' >&2; exit 1; }
# Valider la demande et l’archive avant toute installation APT.
python3 - "$SOC_MIRROR_DIR" "$@" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from miroir_soc import check_bundle
args=sys.argv[2:]
if '--vm-isolee' not in args or '--dossier' not in args:
    raise SystemExit('Préciser --dossier et --vm-isolee. Aucune installation effectuée.')
i=args.index('--dossier')
if i+1>=len(args): raise SystemExit('Dossier absent.')
m=check_bundle(Path(args[i+1]).resolve())
print('Sauvegarde vérifiée. Installation des dépendances sur la destination.')
PY
if command -v docker >/dev/null 2>&1; then
    [[ -z "$(docker ps -aq)" && -z "$(docker volume ls -q)" ]] || { echo 'VM non vierge : arrêt.' >&2; exit 1; }
fi
apt-get update
apt-get install -y ca-certificates curl python3
if ! command -v docker >/dev/null 2>&1; then
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    cat > /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: noble
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker
printf 'vm.max_map_count=262144\n' > /etc/sysctl.d/99-soc-miroir.conf
sysctl -w vm.max_map_count=262144
# Installer les dépendances hôte connues avec démarrage différé (Suricata notamment).
SOC_POLICY_CREATED=0
if [[ ! -e /usr/sbin/policy-rc.d ]]; then
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
    chmod 0755 /usr/sbin/policy-rc.d
    SOC_POLICY_CREATED=1
fi
cleanup_soc_policy() { if [[ "$SOC_POLICY_CREATED" == 1 ]]; then rm -f /usr/sbin/policy-rc.d; fi; }
trap cleanup_soc_policy EXIT
SOC_PACKAGES="$(python3 - "$SOC_MIRROR_DIR" "$@" <<'PY'
import json,sys
from pathlib import Path
args=sys.argv[2:];folder=Path(args[args.index('--dossier')+1])
m=json.loads((folder/'manifest.json').read_text())
allowed={'suricata','suricata-update','python3-requests','python3-yaml','python3-pip'}
print(' '.join(sorted(allowed & set(m.get('paquets_hote',{})))))
PY
)"
if [[ -n "$SOC_PACKAGES" ]]; then
    read -r -a SOC_PACKAGE_ARRAY <<< "$SOC_PACKAGES"
    apt-get install -y "${SOC_PACKAGE_ARRAY[@]}"
fi
# Ubuntu fournit /etc/suricata après installation : conserver cette copie avant restitution.
if [[ -d /etc/suricata ]]; then
    systemctl stop suricata.service || true
    systemctl disable suricata.service || true
    mv /etc/suricata "/etc/suricata.installation-$(date +%s)"
fi
if [[ -d /var/log/suricata ]]; then
    mv /var/log/suricata "/var/log/suricata.installation-$(date +%s)"
fi
if [[ -d /var/lib/suricata ]]; then
    mv /var/lib/suricata "/var/lib/suricata.installation-$(date +%s)"
fi
cleanup_soc_policy
trap - EXIT
python3 "$SOC_MIRROR_DIR/miroir_soc.py" restaurer "$@"
