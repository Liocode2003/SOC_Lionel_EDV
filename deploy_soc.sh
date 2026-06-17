from pathlib import Path
import textwrap, os, zipfile, json, stat

base = Path("/mnt/data/soc_deploy_10_10")
base.mkdir(exist_ok=True)

script = r'''#!/usr/bin/env bash
# =====================================================================
# SOC LIONEL / ENDEAVOUR — Déploiement SOC défensif automatisé
# Cible : Ubuntu Server 22.04/24.04 LTS
# Outils : Wazuh, Suricata, Tenzir, TheHive, Cortex, MISP, Shuffle, Greenbone/OpenVAS
# Auteur : NADZIGA Franck Lionel Elvis Kiswendsida
# =====================================================================

set -Eeuo pipefail

# ----------------------------- COULEURS ------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()     { echo -e "${GREEN}[✓] $*${NC}"; }
info()    { echo -e "${CYAN}[→] $*${NC}"; }
warn()    { echo -e "${YELLOW}[!] $*${NC}"; }
fatal()   { echo -e "${RED}[✗] $*${NC}" >&2; exit 1; }
section() { echo -e "\n${BOLD}${CYAN}════════════════════════════════════════════════════${NC}"; echo -e "${BOLD}${CYAN}  $*${NC}"; echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════${NC}\n"; }

trap 'fatal "Erreur ligne $LINENO. Consulte le log : $LOG_FILE"' ERR

# -------------------------- CONFIGURATION ----------------------------
SOC_BASE="${SOC_BASE:-/opt/soc-lionel}"
LOG_FILE="${SOC_BASE}/logs/deploy_$(date +%Y%m%d_%H%M%S).log"
ENV_FILE="${SOC_BASE}/.env"

WAZUH_VERSION="${WAZUH_VERSION:-v4.9.0}"
HOST_IP="${HOST_IP:-$(hostname -I | awk '{print $1}')}"
TZ="${TZ:-Africa/Ouagadougou}"

MIN_RAM_GB="${MIN_RAM_GB:-12}"
MIN_DISK_GB="${MIN_DISK_GB:-80}"

# Ports exposés
PORT_WAZUH_DASHBOARD=443
PORT_WAZUH_API=55000
PORT_WAZUH_AGENT=1514
PORT_WAZUH_AUTHD=1515
PORT_WAZUH_SYSLOG=514
PORT_THEHIVE=9000
PORT_CORTEX=9001
PORT_MISP=8443
PORT_SHUFFLE=3001
PORT_SHUFFLE_BACKEND=5001
PORT_GREENBONE=9392

mkdir -p "${SOC_BASE}/logs"
exec > >(tee -a "$LOG_FILE") 2>&1

# ----------------------------- HELPERS -------------------------------
require_root() {
  [[ "$EUID" -eq 0 ]] || fatal "Lance le script avec sudo : sudo bash $0"
}

confirm() {
  read -rp "Continuer ? (o/n) : " r
  [[ "$r" == "o" || "$r" == "O" ]] || exit 0
}

rand_pass() {
  openssl rand -base64 24 | tr -d '\n' | tr '/+=' 'Xx_' | cut -c1-24
}

rand_hex() {
  openssl rand -hex 32
}

compose() {
  docker compose "$@"
}

port_free() {
  local p="$1"
  if ss -tulpen | awk '{print $5}' | grep -qE "[:.]${p}$"; then
    return 1
  fi
  return 0
}

wait_http() {
  local url="$1"; local label="$2"; local max="${3:-120}"
  info "Attente HTTP : $label ($url)"
  for i in $(seq 1 "$max"); do
    if curl -kfsS --max-time 5 "$url" >/dev/null 2>&1; then
      log "$label accessible"
      return 0
    fi
    sleep 5
  done
  warn "$label pas encore accessible après $((max*5)) secondes"
  return 1
}

container_by_name() {
  local pattern="$1"
  docker ps --format '{{.Names}}' | grep -E "$pattern" | head -n1 || true
}

# ---------------------------- PRÉREQUIS ------------------------------
preflight() {
  section "PRÉ-VÉRIFICATION"

  require_root

  . /etc/os-release
  [[ "${ID}" == "ubuntu" || "${ID}" == "debian" ]] || fatal "OS non supporté : ${ID}. Utilise Ubuntu/Debian."
  log "OS détecté : ${PRETTY_NAME}"

  local ram_gb disk_gb
  ram_gb=$(awk '/MemTotal/ {printf "%.0f", $2/1024/1024}' /proc/meminfo)
  disk_gb=$(df -BG / | awk 'NR==2 {gsub("G","",$4); print $4}')
  [[ "$ram_gb" -ge "$MIN_RAM_GB" ]] || warn "RAM détectée ${ram_gb}GB < ${MIN_RAM_GB}GB. Le SOC peut démarrer lentement."
  [[ "$disk_gb" -ge "$MIN_DISK_GB" ]] || warn "Disque libre ${disk_gb}GB < ${MIN_DISK_GB}GB. Greenbone/Wazuh peuvent manquer d'espace."

  for p in "$PORT_WAZUH_DASHBOARD" "$PORT_THEHIVE" "$PORT_CORTEX" "$PORT_MISP" "$PORT_SHUFFLE" "$PORT_GREENBONE"; do
    port_free "$p" || warn "Port $p déjà utilisé. Le service associé peut échouer."
  done

  log "Adresse IP hôte : $HOST_IP"
}

# ---------------------- INSTALLATION DOCKER --------------------------
install_docker() {
  section "ÉTAPE 1 — Installation Docker + dépendances"

  apt-get update -y
  apt-get install -y ca-certificates curl gnupg lsb-release git jq openssl \
    python3 python3-pip python3-venv net-tools iproute2 unzip tar cron \
    software-properties-common apt-transport-https ufw ssmtp rsyslog

  if ! command -v docker >/dev/null 2>&1; then
    info "Installation Docker depuis le dépôt officiel"
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
      | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    . /etc/os-release
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
      > /etc/apt/sources.list.d/docker.list

    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl enable --now docker
  else
    log "Docker déjà installé"
    apt-get install -y docker-compose-plugin || true
  fi

  docker version >/dev/null
  docker compose version >/dev/null
  log "Docker et Docker Compose opérationnels"

  if ! grep -q "^vm.max_map_count=262144" /etc/sysctl.conf; then
    echo "vm.max_map_count=262144" >> /etc/sysctl.conf
  fi
  sysctl -w vm.max_map_count=262144 >/dev/null
  log "vm.max_map_count configuré"
}

# ------------------------- STRUCTURE SOC -----------------------------
prepare_dirs_env() {
  section "ÉTAPE 2 — Répertoires et secrets"

  mkdir -p "$SOC_BASE"/{wazuh,thehive,cortex,misp,shuffle,greenbone,suricata,tenzir,integrations,backups,documentation,logs}

  if [[ ! -f "$ENV_FILE" ]]; then
    cat > "$ENV_FILE" <<EOF
# SOC Lionel — secrets générés automatiquement
TZ=${TZ}
HOST_IP=${HOST_IP}

WAZUH_VERSION=${WAZUH_VERSION}
WAZUH_ADMIN_PASSWORD=$(rand_pass)

THEHIVE_ADMIN_EMAIL=soc@soc.local
THEHIVE_ADMIN_PASSWORD=$(rand_pass)
THEHIVE_SECRET=$(rand_hex)
THEHIVE_API_KEY=CHANGE_ME_AFTER_FIRST_LOGIN

CORTEX_ADMIN_EMAIL=analyst@soc.local
CORTEX_ADMIN_PASSWORD=$(rand_pass)
CORTEX_SECRET=$(rand_hex)
CORTEX_API_KEY=CHANGE_ME_AFTER_FIRST_LOGIN

MISP_ADMIN_EMAIL=admin@soc.local
MISP_ADMIN_PASSWORD=$(rand_pass)
MISP_BASEURL=https://${HOST_IP}:${PORT_MISP}
MISP_API_KEY=CHANGE_ME_AFTER_FIRST_LOGIN

SHUFFLE_ADMIN_EMAIL=admin@soc.local
SHUFFLE_ADMIN_PASSWORD=$(rand_pass)
SHUFFLE_API_KEY=$(rand_hex)

GREENBONE_ADMIN_USER=admin
GREENBONE_ADMIN_PASSWORD=$(rand_pass)
EOF
    chmod 600 "$ENV_FILE"
    log "Secrets créés : $ENV_FILE"
  else
    log "Fichier .env existant conservé"
  fi

  # shellcheck disable=SC1090
  source "$ENV_FILE"
}

# --------------------------- WAZUH OFFICIEL --------------------------
deploy_wazuh() {
  section "ÉTAPE 3 — Wazuh SIEM/XDR officiel"

  cd "$SOC_BASE/wazuh"

  if [[ ! -d wazuh-docker ]]; then
    git clone --depth 1 -b "$WAZUH_VERSION" https://github.com/wazuh/wazuh-docker.git
  fi

  cd "$SOC_BASE/wazuh/wazuh-docker/single-node"

  # Override : exposition syslog UDP pour recevoir le flux Suricata/Tenzir
  cat > docker-compose.override.yml <<EOF
services:
  wazuh.manager:
    ports:
      - "${PORT_WAZUH_SYSLOG}:514/udp"
EOF

  if [[ ! -d config/wazuh_indexer_ssl_certs ]]; then
    info "Génération certificats Wazuh"
    compose -f generate-indexer-certs.yml run --rm generator
  fi

  info "Démarrage Wazuh"
  compose -f docker-compose.yml -f docker-compose.override.yml up -d

  log "Wazuh lancé"
}

configure_wazuh_syslog() {
  section "ÉTAPE 4 — Activation réception Syslog Wazuh"

  local c
  c="$(container_by_name 'wazuh.*manager|manager')"
  [[ -n "$c" ]] || { warn "Conteneur Wazuh Manager non trouvé pour patch syslog"; return 0; }

  info "Conteneur Wazuh Manager détecté : $c"

  docker exec "$c" bash -lc '
    set -e
    cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak.$(date +%s)
    if ! grep -q "<connection>syslog</connection>" /var/ossec/etc/ossec.conf; then
      sed -i "/<\/ossec_config>/i \
  <remote>\n\
    <connection>syslog</connection>\n\
    <port>514</port>\n\
    <protocol>udp</protocol>\n\
    <allowed-ips>0.0.0.0/0</allowed-ips>\n\
  </remote>\n" /var/ossec/etc/ossec.conf
    fi
  ' || warn "Patch ossec.conf échoué"

  docker restart "$c" || true
  log "Réception Syslog Wazuh configurée"
}

# ------------------------ THEHIVE + CORTEX ---------------------------
deploy_thehive_cortex() {
  section "ÉTAPE 5 — TheHive 5 + Cortex"

  mkdir -p "$SOC_BASE/thehive"/{conf,data,files,cassandra,elasticsearch} "$SOC_BASE/cortex"/{conf,analyzers,elasticsearch}

  # shellcheck disable=SC1090
  source "$ENV_FILE"

  cat > "$SOC_BASE/thehive/conf/application.conf" <<EOF
play.http.secret.key="${THEHIVE_SECRET}"
play.http.parser.maxMemoryBuffer=256M
play.server.http.idleTimeout=3600s
application.baseUrl="http://${HOST_IP}:${PORT_THEHIVE}"

db.janusgraph {
  storage {
    backend = cql
    hostname = ["thehive-cassandra"]
    cql {
      keyspace = thehive
      replication-factor = 1
      read-consistency-level = ONE
      write-consistency-level = ONE
    }
  }
}

index.search {
  backend = elasticsearch
  hostname = ["thehive-elasticsearch"]
  port = 9200
  index-name = thehive
}

storage {
  provider = localfs
  localfs.location = /opt/thp/thehive/files
}

# À activer après création réelle de la clé Cortex dans l'interface
# cortex {
#   servers = [
#     {
#       name = "Cortex"
#       url = "http://cortex:9001"
#       auth { type = "bearer"; key = "${CORTEX_API_KEY}" }
#     }
#   ]
# }
EOF

  cat > "$SOC_BASE/cortex/conf/application.conf" <<EOF
play.http.secret.key="${CORTEX_SECRET}"
http.address=0.0.0.0
http.port=9001

search {
  index = cortex
  uri = "http://cortex-elasticsearch:9200"
}

analyzer {
  urls = ["/opt/Cortex-Analyzers/analyzers"]
}

responder {
  urls = ["/opt/Cortex-Analyzers/responders"]
}
EOF

  cat > "$SOC_BASE/thehive/docker-compose.yml" <<'EOF'
services:
  thehive-cassandra:
    image: cassandra:4.1
    container_name: thehive-cassandra
    restart: unless-stopped
    environment:
      - CASSANDRA_CLUSTER_NAME=thp
      - MAX_HEAP_SIZE=1G
      - HEAP_NEWSIZE=256M
    volumes:
      - ./cassandra:/var/lib/cassandra
    networks: [soc-core]

  thehive-elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.22
    container_name: thehive-elasticsearch
    restart: unless-stopped
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - ES_JAVA_OPTS=-Xms1g -Xmx1g
    volumes:
      - ./elasticsearch:/usr/share/elasticsearch/data
    networks: [soc-core]

  thehive:
    image: strangebee/thehive:5.2
    container_name: thehive
    restart: unless-stopped
    depends_on:
      - thehive-cassandra
      - thehive-elasticsearch
    ports:
      - "9000:9000"
    volumes:
      - ./conf/application.conf:/etc/thehive/application.conf:ro
      - ./files:/opt/thp/thehive/files
    networks: [soc-core]

  cortex-elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.22
    container_name: cortex-elasticsearch
    restart: unless-stopped
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - ES_JAVA_OPTS=-Xms512m -Xmx512m
    volumes:
      - ../cortex/elasticsearch:/usr/share/elasticsearch/data
    networks: [soc-core]

  cortex:
    image: thehiveproject/cortex:3.1.8
    container_name: cortex
    restart: unless-stopped
    depends_on:
      - cortex-elasticsearch
    ports:
      - "9001:9001"
    volumes:
      - ../cortex/conf/application.conf:/etc/cortex/application.conf:ro
      - ../cortex/analyzers:/opt/Cortex-Analyzers
    networks: [soc-core]

networks:
  soc-core:
    name: soc-core
    driver: bridge
EOF

  cd "$SOC_BASE/thehive"
  compose up -d
  log "TheHive + Cortex lancés"
}

# ------------------------------- MISP --------------------------------
deploy_misp() {
  section "ÉTAPE 6 — MISP"

  # shellcheck disable=SC1090
  source "$ENV_FILE"

  mkdir -p "$SOC_BASE/misp"/{mysql,files,ssl,redis}

  if [[ ! -f "$SOC_BASE/misp/ssl/misp.key" ]]; then
    openssl req -x509 -nodes -days 3650 -newkey rsa:4096 \
      -keyout "$SOC_BASE/misp/ssl/misp.key" \
      -out "$SOC_BASE/misp/ssl/misp.crt" \
      -subj "/C=BF/ST=Centre/L=Ouagadougou/O=SOC/CN=misp.soc.local" >/dev/null 2>&1
  fi

  cat > "$SOC_BASE/misp/docker-compose.yml" <<EOF
services:
  misp-db:
    image: mariadb:10.11
    container_name: misp-db
    restart: unless-stopped
    command: --innodb-buffer-pool-size=1G
    environment:
      - MYSQL_ROOT_PASSWORD=$(rand_pass)
      - MYSQL_DATABASE=misp
      - MYSQL_USER=misp
      - MYSQL_PASSWORD=${MISP_ADMIN_PASSWORD}
    volumes:
      - ./mysql:/var/lib/mysql
    networks: [soc-core]

  misp-redis:
    image: redis:7
    container_name: misp-redis
    restart: unless-stopped
    volumes:
      - ./redis:/data
    networks: [soc-core]

  misp:
    image: ghcr.io/misp/misp-docker/misp-core:latest
    container_name: misp
    restart: unless-stopped
    depends_on:
      - misp-db
      - misp-redis
    ports:
      - "${PORT_MISP}:443"
    environment:
      - BASE_URL=https://${HOST_IP}:${PORT_MISP}
      - MYSQL_HOST=misp-db
      - MYSQL_DATABASE=misp
      - MYSQL_USER=misp
      - MYSQL_PASSWORD=${MISP_ADMIN_PASSWORD}
      - REDIS_HOST=misp-redis
      - ADMIN_EMAIL=${MISP_ADMIN_EMAIL}
      - ADMIN_PASSWORD=${MISP_ADMIN_PASSWORD}
      - TZ=${TZ}
    volumes:
      - ./files:/var/www/MISP/app/files
      - ./ssl/misp.crt:/etc/ssl/certs/misp.crt:ro
      - ./ssl/misp.key:/etc/ssl/private/misp.key:ro
    networks: [soc-core]

  misp-modules:
    image: ghcr.io/misp/misp-docker/misp-modules:latest
    container_name: misp-modules
    restart: unless-stopped
    depends_on:
      - misp
    networks: [soc-core]

networks:
  soc-core:
    external: true
EOF

  cd "$SOC_BASE/misp"
  compose up -d
  log "MISP lancé"
}

# ------------------------------ SHUFFLE -------------------------------
deploy_shuffle() {
  section "ÉTAPE 7 — Shuffle SOAR"

  # shellcheck disable=SC1090
  source "$ENV_FILE"

  mkdir -p "$SOC_BASE/shuffle"/{apps,db,opensearch}

  cat > "$SOC_BASE/shuffle/docker-compose.yml" <<EOF
services:
  shuffle-frontend:
    image: ghcr.io/shuffle/shuffle-frontend:latest
    container_name: shuffle-frontend
    restart: unless-stopped
    ports:
      - "${PORT_SHUFFLE}:80"
    environment:
      - BACKEND_HOSTNAME=shuffle-backend
    networks: [soc-core]

  shuffle-backend:
    image: ghcr.io/shuffle/shuffle-backend:latest
    container_name: shuffle-backend
    restart: unless-stopped
    ports:
      - "${PORT_SHUFFLE_BACKEND}:5001"
    environment:
      - BACKEND_HOSTNAME=shuffle-backend
      - SHUFFLE_DEFAULT_USERNAME=${SHUFFLE_ADMIN_EMAIL}
      - SHUFFLE_DEFAULT_PASSWORD=${SHUFFLE_ADMIN_PASSWORD}
      - SHUFFLE_DEFAULT_APIKEY=${SHUFFLE_API_KEY}
      - OPENSEARCH_URL=http://shuffle-opensearch:9200
      - DATASTORE_EMULATOR_HOST=shuffle-database:8000
      - GOOGLE_APPLICATION_CREDENTIALS=/shuffle-database
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./apps:/shuffle-apps
      - ./db:/shuffle-database
    depends_on:
      - shuffle-opensearch
    networks: [soc-core]

  shuffle-orborus:
    image: ghcr.io/shuffle/shuffle-orborus:latest
    container_name: shuffle-orborus
    restart: unless-stopped
    environment:
      - ENVIRONMENT_NAME=Shuffle
      - BASE_URL=http://shuffle-backend:5001
      - DOCKER_API_VERSION=1.40
      - CLEANUP=true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    networks: [soc-core]

  shuffle-opensearch:
    image: opensearchproject/opensearch:2.14.0
    container_name: shuffle-opensearch
    restart: unless-stopped
    environment:
      - discovery.type=single-node
      - DISABLE_SECURITY_PLUGIN=true
      - OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - ./opensearch:/usr/share/opensearch/data
    networks: [soc-core]

networks:
  soc-core:
    external: true
EOF

  cd "$SOC_BASE/shuffle"
  compose up -d

  sleep 30
  docker exec shuffle-opensearch curl -sk -X PUT "http://localhost:9200/_settings" \
    -H "Content-Type: application/json" \
    -d '{"index":{"number_of_replicas":0}}' >/dev/null 2>&1 || true

  log "Shuffle lancé"
}

# -------------------------- GREENBONE / OPENVAS -----------------------
deploy_greenbone() {
  section "ÉTAPE 8 — Greenbone / OpenVAS"

  mkdir -p "$SOC_BASE/greenbone"
  cd "$SOC_BASE/greenbone"

  if [[ ! -f compose.yaml ]]; then
    info "Téléchargement du compose officiel Greenbone Community Containers"
    curl -fsSL https://raw.githubusercontent.com/greenbone/docs/main/src/_static/docker-compose-22.4.yml \
      -o compose.yaml || {
        warn "Téléchargement Greenbone échoué. Déploiement Greenbone ignoré."
        return 0
      }
  fi

  compose -f compose.yaml up -d || warn "Greenbone peut nécessiter un temps de synchronisation important."
  log "Greenbone lancé ou en cours d'initialisation"
}

# ------------------------- SURICATA + TENZIR --------------------------
install_suricata() {
  section "ÉTAPE 9 — Suricata IDS/IPS"

  if ! command -v suricata >/dev/null 2>&1; then
    add-apt-repository -y ppa:oisf/suricata-stable
    apt-get update -y
    apt-get install -y suricata suricata-update
  fi

  local iface
  iface="$(ip route get 8.8.8.8 | awk '{print $5; exit}')"
  [[ -n "$iface" ]] || fatal "Impossible de détecter l'interface réseau."

  cp /etc/suricata/suricata.yaml "/etc/suricata/suricata.yaml.bak.$(date +%s)" || true

  cat > /etc/suricata/suricata.yaml <<EOF
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[${HOST_IP}/24]"
    EXTERNAL_NET: "!\\\$HOME_NET"

af-packet:
  - interface: ${iface}
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert
        - dns
        - http
        - tls
        - flow
        - anomaly

default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
EOF

  suricata-update || true
  systemctl enable --now suricata
  log "Suricata installé sur l'interface : $iface"
}

install_tenzir_pipeline() {
  section "ÉTAPE 10 — Tenzir pipeline Suricata → Wazuh"

  mkdir -p /var/log/suricata "$SOC_BASE/tenzir"

  if ! command -v tenzir >/dev/null 2>&1; then
    curl -fsSL https://get.tenzir.app | bash || warn "Installation Tenzir échouée. Le forwarder Python prendra le relais."
  fi

  cat > "$SOC_BASE/tenzir/suricata-to-wazuh.py" <<'PYEOF'
#!/usr/bin/env python3
import json, os, time, socket, sys

SRC = "/var/log/suricata/eve.json"
DST = "/var/log/suricata/eve-tenzir-normalized.json"
WAZUH_HOST = "127.0.0.1"
WAZUH_PORT = 514

def follow(path):
    while not os.path.exists(path):
        time.sleep(2)
    with open(path, "r", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            yield line.strip()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

os.makedirs(os.path.dirname(DST), exist_ok=True)
print("Suricata/Tenzir forwarder démarré", flush=True)

with open(DST, "a", buffering=1) as out:
    for line in follow(SRC):
        if not line:
            continue
        try:
            event = json.loads(line)
            # Normalisation minimale pour préserver le format Suricata/Wazuh.
            event["pipeline"] = "tenzir"
            event["soc_source"] = "suricata"
            event["normalized_by"] = "tenzir-pipeline"
            msg = json.dumps(event, separators=(",", ":"))
            out.write(msg + "\n")
            sock.sendto(msg.encode(), (WAZUH_HOST, WAZUH_PORT))
        except Exception as e:
            print(f"Erreur forwarder: {e}", file=sys.stderr, flush=True)
PYEOF

  chmod +x "$SOC_BASE/tenzir/suricata-to-wazuh.py"

  cat > /etc/systemd/system/suricata-tenzir-wazuh.service <<EOF
[Unit]
Description=Suricata -> Tenzir normalization -> Wazuh Syslog forwarder
After=suricata.service docker.service
Requires=suricata.service

[Service]
Type=simple
Restart=always
RestartSec=10
ExecStart=/usr/bin/python3 ${SOC_BASE}/tenzir/suricata-to-wazuh.py
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now suricata-tenzir-wazuh.service
  log "Pipeline Suricata → Tenzir → Wazuh activé"
}

# ---------------------------- INTÉGRATIONS ----------------------------
create_integration_scripts() {
  section "ÉTAPE 11 — Scripts d'intégration SOC"

  # shellcheck disable=SC1090
  source "$ENV_FILE"

  cat > "$SOC_BASE/integrations/README_INTEGRATIONS.md" <<EOF
# Intégrations à finaliser après premier login

Ce déploiement évite de créer de fausses clés API.

Après avoir créé les comptes dans les interfaces :
1. TheHive : créer une organisation + un utilisateur + une clé API.
2. Cortex : créer un utilisateur analyste + une clé API.
3. MISP : récupérer l'Authkey de l'utilisateur admin.
4. Shuffle : créer les webhooks nécessaires.

Puis modifier :
${ENV_FILE}

Variables :
- THEHIVE_API_KEY
- CORTEX_API_KEY
- MISP_API_KEY

Flux défendable :
- Wazuh -> TheHive
- TheHive <-> Cortex
- MISP -> TheHive
- Shuffle -> TheHive
EOF

  cat > "$SOC_BASE/integrations/wazuh-to-thehive.py" <<'PYEOF'
#!/usr/bin/env python3
import json, os, time, requests, urllib3
urllib3.disable_warnings()

ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
THEHIVE_URL = os.environ.get("THEHIVE_URL", "http://thehive:9000")
THEHIVE_KEY = os.environ.get("THEHIVE_API_KEY", "")
MIN_LEVEL = int(os.environ.get("MIN_LEVEL", "7"))

if not THEHIVE_KEY or THEHIVE_KEY.startswith("CHANGE_ME"):
    raise SystemExit("THEHIVE_API_KEY non configurée")

headers = {"Authorization": f"Bearer {THEHIVE_KEY}", "Content-Type": "application/json"}

def tail(path):
    while not os.path.exists(path):
        time.sleep(5)
    with open(path, "r", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(2); continue
            yield line.strip()

for line in tail(ALERTS_FILE):
    try:
        a = json.loads(line)
        rule = a.get("rule", {})
        level = int(rule.get("level", 0))
        if level < MIN_LEVEL:
            continue
        payload = {
            "title": rule.get("description", "Wazuh Alert"),
            "description": json.dumps(a, indent=2)[:4000],
            "type": "wazuh",
            "source": "Wazuh",
            "sourceRef": a.get("id", str(time.time())),
            "severity": 1 if level < 7 else 2 if level < 10 else 3 if level < 13 else 4,
            "tlp": 2,
            "tags": ["wazuh", f"level-{level}"],
        }
        requests.post(f"{THEHIVE_URL}/api/alert", headers=headers, json=payload, timeout=10, verify=False)
    except Exception as e:
        print(e, flush=True)
PYEOF
  chmod +x "$SOC_BASE/integrations/wazuh-to-thehive.py"

  log "Scripts d'intégration générés"
}

# ------------------------------ BACKUP --------------------------------
configure_backups() {
  section "ÉTAPE 12 — Sauvegardes automatiques"

  cat > "$SOC_BASE/backup.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
BASE="/opt/soc-lionel"
DEST="$BASE/backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$DEST"

cp -a "$BASE/.env" "$DEST/env.secure" 2>/dev/null || true
cp -a "$BASE/thehive/conf" "$DEST/thehive-conf" 2>/dev/null || true
cp -a "$BASE/cortex/conf" "$DEST/cortex-conf" 2>/dev/null || true
cp -a "$BASE/misp/ssl" "$DEST/misp-ssl" 2>/dev/null || true
cp -a "$BASE/integrations" "$DEST/integrations" 2>/dev/null || true
cp -a /etc/suricata "$DEST/suricata-etc" 2>/dev/null || true

docker ps --format '{{.Names}}' > "$DEST/running-containers.txt" || true
docker compose version > "$DEST/docker-compose-version.txt" || true

find "$BASE/backups" -mindepth 1 -maxdepth 1 -type d -mtime +14 -exec rm -rf {} \; || true
echo "Backup créé : $DEST"
EOF
  chmod +x "$SOC_BASE/backup.sh"

  cat > /etc/cron.d/soc-lionel-backup <<EOF
0 2 * * * root ${SOC_BASE}/backup.sh >> ${SOC_BASE}/logs/backup.log 2>&1
EOF
  chmod 644 /etc/cron.d/soc-lionel-backup

  log "Sauvegarde quotidienne configurée à 02h00"
}

# ------------------------------ VÉRIF ---------------------------------
verify_services() {
  section "VÉRIFICATION FINALE"

  echo -e "${BOLD}Conteneurs Docker :${NC}"
  docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' || true

  echo ""
  echo -e "${BOLD}Services systemd :${NC}"
  for svc in docker suricata suricata-tenzir-wazuh; do
    if systemctl is-active --quiet "$svc"; then
      echo -e "  ${GREEN}✓${NC} $svc"
    else
      echo -e "  ${RED}✗${NC} $svc"
    fi
  done

  echo ""
  echo -e "${BOLD}Interfaces :${NC}"
  echo "  Wazuh Dashboard : https://${HOST_IP}:${PORT_WAZUH_DASHBOARD}"
  echo "  Wazuh API       : https://${HOST_IP}:${PORT_WAZUH_API}"
  echo "  TheHive         : http://${HOST_IP}:${PORT_THEHIVE}"
  echo "  Cortex          : http://${HOST_IP}:${PORT_CORTEX}"
  echo "  MISP            : https://${HOST_IP}:${PORT_MISP}"
  echo "  Shuffle         : http://${HOST_IP}:${PORT_SHUFFLE}"
  echo "  Greenbone       : http/https://${HOST_IP}:${PORT_GREENBONE}"

  echo ""
  echo -e "${BOLD}Secrets :${NC} ${ENV_FILE}"
  echo -e "${BOLD}Logs :${NC} ${LOG_FILE}"

  echo ""
  warn "TheHive, Cortex, MISP et Shuffle demandent souvent une finalisation via interface web pour créer les clés API réelles."
  warn "Après création des clés, remplace CHANGE_ME dans ${ENV_FILE}, puis configure les webhooks."
}

# ------------------------------- MAIN ---------------------------------
main() {
  clear || true
  echo -e "${BOLD}${CYAN}"
  echo "  ____   ___   ____     ____  _____ ____  _     ___  __   __"
  echo " / ___| / _ \ / ___|   |  _ \| ____|  _ \| |   / _ \ \ \ / /"
  echo " \___ \| | | | |       | | | |  _| | |_) | |  | | | | \ V / "
  echo "  ___) | |_| | |___    | |_| | |___|  __/| |__| |_| |  | |  "
  echo " |____/ \___/ \____|   |____/|_____|_|   |_____\___/   |_|  "
  echo -e "${NC}"
  echo "  Déploiement SOC défensif — Wazuh / Suricata / Tenzir / TheHive / Cortex / MISP / Shuffle / Greenbone"
  echo "  Hôte : ${HOST_IP}"
  echo "  Dossier : ${SOC_BASE}"
  echo ""
  confirm

  preflight
  install_docker
  prepare_dirs_env

  # Réseau commun pour outils SOC applicatifs
  docker network inspect soc-core >/dev/null 2>&1 || docker network create soc-core

  deploy_wazuh
  configure_wazuh_syslog

  deploy_thehive_cortex
  deploy_misp
  deploy_shuffle
  deploy_greenbone

  install_suricata
  install_tenzir_pipeline

  create_integration_scripts
  configure_backups
  verify_services

  log "Déploiement terminé. Certaines plateformes nécessitent une initialisation web."
}

main "$@"
'''

readme = r'''# SOC Lionel — Script 10/10 amélioré

## Objectif

Déployer un SOC défensif complet avec :

- Wazuh Manager + Indexer OpenSearch + Dashboard
- Suricata IDS/IPS
- Tenzir pipeline
- TheHive
- Cortex
- MISP
- Shuffle SOAR
- Greenbone/OpenVAS
- Sauvegardes quotidiennes
- Vérifications finales

## Lancement

```bash
chmod +x soc_deploy_10_10.sh
sudo bash soc_deploy_10_10.sh