#!/bin/bash
# ============================================================
# SOC ENDEAVOUR MINING — Script de déploiement complet
# Ubuntu 24.04 LTS
# Auteur : NADZIGA Franck Lionel Elvis Kiswendsida
# ============================================================

set -e

# ── COULEURS ─────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()     { echo -e "${GREEN}[✓] $1${NC}"; }
info()    { echo -e "${CYAN}[→] $1${NC}"; }
warn()    { echo -e "${YELLOW}[!] $1${NC}"; }
error()   { echo -e "${RED}[✗] $1${NC}"; exit 1; }
section() { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${NC}"; echo -e "${BOLD}${CYAN}  $1${NC}"; echo -e "${BOLD}${CYAN}══════════════════════════════════════════${NC}\n"; }

# ── VÉRIFICATION ROOT ─────────────────────────────────────────
[ "$EUID" -ne 0 ] && error "Ce script doit être exécuté en tant que root (sudo)"

# ── CONFIGURATION ─────────────────────────────────────────────
SOC_DIR="/opt/soc"
THP_DIR="/opt/thp"
BACKUP_DIR="/opt/soc/backups"

WAZUH_PASS="MyS3cr37P450r.*-"
THEHIVE_USER="soc@soc.local"
THEHIVE_PASS="SOC\@Endeavour2025!"
CORTEX_USER="analyst@soc.local"
CORTEX_PASS="SOC\@Endeavour2025!"
MISP_PASS="SOC\@Endeavour2025!"
SHUFFLE_PASS="SOC\@Endeavour2025!"

THEHIVE_API_KEY="/NVt7GQctThy6TUoldBg0MwmCgOasnUk"
MISP_API_KEY="tO1UlFvNhz4Dm7p4dMJanJHuBqDRjJOm5R3pC483"
CORTEX_API_KEY="MHV6/BzTNeNrvor2VwFC9qtTSyPkNtWq"

SOC_IP=$(hostname -I | awk '{print $1}')

echo -e "${BOLD}${CYAN}"
echo "  ____  ___   ____   _____           _                                  "
echo " / ___|/ _ \ / ___| | ____|_ __   __| | ___  __ ___   _____  _   _ _ __ "
echo " \___ \ | | | |     |  _| | '_ \ / _\` |/ _ \/ _\` \ \ / / _ \| | | | '__|"
echo "  ___) | |_| | |___  | |___| | | | (_| |  __/ (_| |\ V / (_) | |_| | |   "
echo " |____/ \___/ \____| |_____|_| |_|\__,_|\___|\__,_| \_/ \___/ \__,_|_|   "
echo -e "${NC}"
echo -e "${BOLD}         SOC Endeavour Mining — Déploiement automatique${NC}"
echo -e "         IP détectée : ${CYAN}$SOC_IP${NC}\n"

read -p "Continuer le déploiement ? (o/n) : " confirm
[ "$confirm" != "o" ] && exit 0

# ════════════════════════════════════════════════════════════
section "ÉTAPE 1 — Prérequis système"
# ════════════════════════════════════════════════════════════

info "Mise à jour du système..."
apt-get update -qq && apt-get upgrade -y -qq
log "Système mis à jour"

info "Installation des dépendances..."
apt-get install -y -qq \
  curl wget git vim jq python3 python3-pip \
  apt-transport-https ca-certificates gnupg \
  lsb-release software-properties-common \
  openssl net-tools cron
log "Dépendances installées"

# ── DOCKER ────────────────────────────────────────────────────
info "Installation de Docker..."
if ! command -v docker &> /dev/null; then
  curl -fsSL https://get.docker.com | bash -s
  systemctl enable docker
  systemctl start docker
  log "Docker installé"
else
  log "Docker déjà installé"
fi

# ── DOCKER COMPOSE ────────────────────────────────────────────
info "Installation de Docker Compose..."
if ! command -v docker-compose &> /dev/null; then
  curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
    -o /usr/local/bin/docker-compose
  chmod +x /usr/local/bin/docker-compose
  log "Docker Compose installé"
else
  log "Docker Compose déjà installé"
fi

# ── RÉPERTOIRES ───────────────────────────────────────────────
info "Création des répertoires..."
mkdir -p $SOC_DIR/{wazuh,thehive,cortex,misp,shuffle,gvm,backups,documentation}
mkdir -p $THP_DIR/{thehive/{config,db,files},cortex/config}
mkdir -p $SOC_DIR/misp/certs
log "Répertoires créés"

# ── SYSCTL ────────────────────────────────────────────────────
info "Configuration système (vm.max_map_count)..."
sysctl -w vm.max_map_count=262144 > /dev/null
echo "vm.max_map_count=262144" >> /etc/sysctl.conf
log "Paramètres système configurés"

# ════════════════════════════════════════════════════════════
section "ÉTAPE 2 — Déploiement Wazuh SIEM/XDR"
# ════════════════════════════════════════════════════════════

info "Génération des certificats Wazuh..."
curl -sO https://packages.wazuh.com/4.9/wazuh-certs-tool.sh
curl -sO https://packages.wazuh.com/4.9/config.yml

cat > config.yml << EOF
nodes:
  indexer:
    - name: wazuh-indexer
      ip: "127.0.0.1"
  server:
    - name: wazuh-manager
      ip: "127.0.0.1"
  dashboard:
    - name: wazuh-dashboard
      ip: "127.0.0.1"
EOF

bash ./wazuh-certs-tool.sh -A
log "Certificats générés"

info "Création du docker-compose Wazuh..."
cat > $SOC_DIR/wazuh/docker-compose.yml << EOF
version: '3.7'

services:
  wazuh-manager:
    image: wazuh/wazuh-manager:4.9.0
    container_name: wazuh-wazuh-manager-1
    restart: always
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 655360
        hard: 655360
    ports:
      - "1514:1514"
      - "1515:1515"
      - "514:514/udp"
      - "55000:55000"
    environment:
      - INDEXER_URL=https://wazuh-indexer:9200
      - INDEXER_USERNAME=admin
      - INDEXER_PASSWORD=${WAZUH_PASS}
      - FILEBEAT_SSL_VERIFICATION_MODE=full
      - SSL_CERTIFICATE_AUTHORITIES=/etc/ssl/root-ca.pem
      - SSL_CERTIFICATE=/etc/ssl/filebeat.pem
      - SSL_KEY=/etc/ssl/filebeat.key
      - API_USERNAME=wazuh
      - API_PASSWORD=${WAZUH_PASS}
    volumes:
      - wazuh_api_configuration:/var/ossec/api/configuration
      - wazuh_etc:/var/ossec/etc
      - wazuh_logs:/var/ossec/logs
      - wazuh_queue:/var/ossec/queue
      - wazuh_var_multigroups:/var/ossec/var/multigroups
      - wazuh_integrations:/var/ossec/integrations
      - wazuh_active_response:/var/ossec/active-response/bin
      - wazuh_agentless:/var/ossec/agentless
      - wazuh_wodles:/var/ossec/wodles
      - filebeat_etc:/etc/filebeat
      - filebeat_var:/var/lib/filebeat
      - ./config/wazuh_indexer_ssl_certs/root-ca-manager.pem:/etc/ssl/root-ca.pem
      - ./config/wazuh_indexer_ssl_certs/wazuh.manager.pem:/etc/ssl/filebeat.pem
      - ./config/wazuh_indexer_ssl_certs/wazuh.manager-key.pem:/etc/ssl/filebeat.key
      - $SOC_DIR/wazuh/ossec.conf:/wazuh-config-mount/etc/ossec.conf

  wazuh-indexer:
    image: wazuh/wazuh-indexer:4.9.0
    container_name: wazuh-wazuh-indexer-1
    restart: always
    ports:
      - "9200:9200"
    environment:
      - "OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g"
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536
        hard: 65536
    volumes:
      - wazuh-indexer-data:/var/lib/wazuh-indexer
      - ./config/wazuh_indexer_ssl_certs/root-ca.pem:/usr/share/wazuh-indexer/certs/root-ca.pem
      - ./config/wazuh_indexer_ssl_certs/wazuh.indexer-key.pem:/usr/share/wazuh-indexer/certs/wazuh.indexer.key
      - ./config/wazuh_indexer_ssl_certs/wazuh.indexer.pem:/usr/share/wazuh-indexer/certs/wazuh.indexer.pem
      - ./config/wazuh_indexer_ssl_certs/admin.pem:/usr/share/wazuh-indexer/certs/admin.pem
      - ./config/wazuh_indexer_ssl_certs/admin-key.pem:/usr/share/wazuh-indexer/certs/admin.key
      - ./config/wazuh.indexer.yml:/usr/share/wazuh-indexer/opensearch.yml
      - ./config/internal_users.yml:/usr/share/wazuh-indexer/opensearch-security/internal_users.yml

  wazuh-dashboard:
    image: wazuh/wazuh-dashboard:4.9.0
    container_name: wazuh-wazuh-dashboard-1
    restart: always
    ports:
      - "443:5601"
    environment:
      - INDEXER_USERNAME=admin
      - INDEXER_PASSWORD=${WAZUH_PASS}
      - WAZUH_API_URL=https://wazuh-manager
      - DASHBOARD_USERNAME=kibanaserver
      - DASHBOARD_PASSWORD=${WAZUH_PASS}
      - API_USERNAME=wazuh
      - API_PASSWORD=${WAZUH_PASS}
    volumes:
      - ./config/wazuh_indexer_ssl_certs/wazuh.dashboard.pem:/usr/share/wazuh-dashboard/certs/wazuh-dashboard.pem
      - ./config/wazuh_indexer_ssl_certs/wazuh.dashboard-key.pem:/usr/share/wazuh-dashboard/certs/wazuh-dashboard-key.pem
      - ./config/wazuh_indexer_ssl_certs/root-ca.pem:/usr/share/wazuh-dashboard/certs/root-ca.pem
      - ./config/opensearch_dashboards.yml:/usr/share/wazuh-dashboard/config/opensearch_dashboards.yml
      - ./config/wazuh.yml:/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
    depends_on:
      - wazuh-indexer
    links:
      - wazuh-indexer:wazuh-indexer
      - wazuh-manager:wazuh-manager

volumes:
  wazuh_api_configuration:
  wazuh_etc:
  wazuh_logs:
  wazuh_queue:
  wazuh_var_multigroups:
  wazuh_integrations:
  wazuh_active_response:
  wazuh_agentless:
  wazuh_wodles:
  filebeat_etc:
  filebeat_var:
  wazuh-indexer-data:
EOF

info "Démarrage de Wazuh..."
cd $SOC_DIR/wazuh && docker-compose up -d
log "Wazuh déployé"

# ── OSSEC.CONF ────────────────────────────────────────────────
info "Configuration ossec.conf..."
cat > $SOC_DIR/wazuh/ossec.conf << EOF
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>smtp.example.wazuh.com</smtp_server>
    <email_from>wazuh@example.wazuh.com</email_from>
    <email_to>recipient@example.wazuh.com</email_to>
    <email_maxperhour>12</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
    <agents_disconnection_time>10m</agents_disconnection_time>
    <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
    <update_check>yes</update_check>
  </global>

  <integration>
    <name>custom-misp</name>
    <level>10</level>
    <hook_url>https://$SOC_IP:8443</hook_url>
    <api_key>$MISP_API_KEY</api_key>
    <alert_format>json</alert_format>
  </integration>

  <integration>
    <name>shuffle</name>
    <hook_url>http://172.18.0.12:5001/api/v1/hooks/webhook_a5676122-43af-42ba-a624-ae391f0ca50f</hook_url>
    <level>7</level>
    <alert_format>json</alert_format>
  </integration>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <logging>
    <log_format>plain</log_format>
  </logging>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>

  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>43200</frequency>
    <rootkit_files>etc/rootcheck/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>etc/rootcheck/rootkit_trojans.txt</rootkit_trojans>
    <skip_nfs>yes</skip_nfs>
  </rootcheck>

  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
    <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>
  </syscheck>

  <vulnerability-detection>
    <enabled>yes</enabled>
    <index-status>yes</index-status>
    <feed-update-interval>60m</feed-update-interval>
  </vulnerability-detection>
</ossec_config>
EOF
log "ossec.conf configuré"

# ════════════════════════════════════════════════════════════
section "ÉTAPE 3 — Déploiement TheHive + Cortex"
# ════════════════════════════════════════════════════════════

info "Configuration TheHive application.conf..."
cat > $THP_DIR/thehive/config/application.conf << EOF
play.http.secret.key = "$(openssl rand -base64 32)"

db.janusgraph {
  storage.backend = berkeleyje
  storage.directory = /opt/thp/thehive/db
  berkeleyje.freeDisk = 200
}

storage {
  provider = localfs
  localfs.location = /opt/thp/thehive/files
}

play.http.parser.maxMemoryBuffer = 256M
play.server.http.idleTimeout = 3600s

cortex {
  servers = [
    {
      name = Cortex
      url = "http://cortex:9001"
      auth {
        type = "bearer"
        key = "$CORTEX_API_KEY"
      }
    }
  ]
}
EOF

info "Création docker-compose TheHive + Cortex..."
cat > $SOC_DIR/thehive/docker-compose.yml << EOF
version: '3.7'

services:
  thehive:
    image: strangebee/thehive:5.2
    container_name: thehive
    restart: always
    ports:
      - "9000:9000"
    environment:
      - JVM_OPTS=-Xms512m -Xmx1g
    volumes:
      - $THP_DIR/thehive/config/application.conf:/etc/thehive/application.conf
      - $THP_DIR/thehive/db:/opt/thp/thehive/db
      - $THP_DIR/thehive/files:/opt/thp/thehive/files
    networks:
      - soc-network

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.22
    container_name: elasticsearch
    restart: always
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - elasticsearch-data:/usr/share/elasticsearch/data
    networks:
      - soc-network

  cortex:
    image: thehiveproject/cortex:3.1.8
    container_name: cortex
    restart: always
    ports:
      - "9001:9001"
    volumes:
      - $THP_DIR/cortex/config:/etc/cortex
    depends_on:
      - elasticsearch
    networks:
      - soc-network

volumes:
  elasticsearch-data:

networks:
  soc-network:
    driver: bridge
    name: soc-network
EOF

info "Démarrage TheHive + Cortex..."
cd $SOC_DIR/thehive && docker-compose up -d
log "TheHive + Cortex déployés"

# ════════════════════════════════════════════════════════════
section "ÉTAPE 4 — Déploiement MISP"
# ════════════════════════════════════════════════════════════

info "Génération certificats MISP..."
openssl req -x509 -nodes -days 3650 \
  -newkey rsa:4096 \
  -keyout $SOC_DIR/misp/certs/misp.key \
  -out $SOC_DIR/misp/certs/misp.crt \
  -subj "/C=BF/ST=Centre/L=Ouagadougou/O=Endeavour Mining/CN=misp.soc.local" \
  2>/dev/null
log "Certificats MISP générés"

info "Création docker-compose MISP..."
cat > $SOC_DIR/misp/docker-compose.yml << EOF
version: '3.7'

services:
  misp:
    image: ghcr.io/misp/misp-docker/misp-core:latest
    container_name: misp
    restart: always
    ports:
      - "8443:443"
    environment:
      - MISP_ADMIN_EMAIL=admin@admin.test
      - MISP_ADMIN_PASSPHRASE=$MISP_PASS
      - MISP_BASEURL=https://$SOC_IP:8443
      - MISP_UUID=$(cat /proc/sys/kernel/random/uuid)
      - MYSQL_HOST=misp-db
      - MYSQL_DATABASE=misp
      - MYSQL_USER=misp
      - MYSQL_PASSWORD=misp_password
    volumes:
      - $SOC_DIR/misp/certs/misp.crt:/etc/ssl/certs/misp.crt
      - $SOC_DIR/misp/certs/misp.key:/etc/ssl/private/misp.key
      - misp-data:/var/www/MISP/app/files
    depends_on:
      - misp-db
      - redis
    networks:
      - soc-network

  misp-db:
    image: mysql:8.0
    container_name: misp-db
    restart: always
    environment:
      - MYSQL_DATABASE=misp
      - MYSQL_USER=misp
      - MYSQL_PASSWORD=misp_password
      - MYSQL_ROOT_PASSWORD=misp_root_password
    volumes:
      - misp-db-data:/var/lib/mysql
    networks:
      - soc-network

  redis:
    image: redis:7
    container_name: misp-redis
    restart: always
    networks:
      - soc-network

volumes:
  misp-data:
  misp-db-data:

networks:
  soc-network:
    external: true
EOF

info "Démarrage MISP..."
cd $SOC_DIR/misp && docker-compose up -d
log "MISP déployé"

# ════════════════════════════════════════════════════════════
section "ÉTAPE 5 — Déploiement Shuffle (SOAR)"
# ════════════════════════════════════════════════════════════

info "Création docker-compose Shuffle..."
cat > $SOC_DIR/shuffle/docker-compose.yml << EOF
version: '3.7'

services:
  shuffle-frontend:
    image: ghcr.io/shuffle/shuffle-frontend:latest
    container_name: shuffle-frontend
    restart: always
    ports:
      - "3001:80"
      - "3443:443"
    environment:
      - BACKEND_HOSTNAME=shuffle-backend
    networks:
      - soc-network

  shuffle-backend:
    image: ghcr.io/shuffle/shuffle-backend:latest
    container_name: shuffle-backend
    restart: always
    ports:
      - "5001:5001"
    environment:
      - DATASTORE_EMULATOR_HOST=shuffle-database:8000
      - GOOGLE_APPLICATION_CREDENTIALS=/shuffle-database
      - BACKEND_HOSTNAME=shuffle-backend
      - SHUFFLE_DEFAULT_USERNAME=admin@soc.local
      - SHUFFLE_DEFAULT_PASSWORD=$SHUFFLE_PASS
      - SHUFFLE_DEFAULT_APIKEY=3314f6ff-6c00-4d82-b1a2-98ae9725a8ff
      - OPENSEARCH_URL=http://shuffle-opensearch:9200
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - shuffle-apps:/shuffle-apps
      - shuffle-db:/shuffle-database
    depends_on:
      - shuffle-opensearch
    networks:
      - soc-network

  shuffle-orborus:
    image: ghcr.io/shuffle/shuffle-orborus:latest
    container_name: shuffle-orborus
    restart: always
    environment:
      - ENVIRONMENT_NAME=Shuffle
      - BASE_URL=http://shuffle-backend:5001
      - DOCKER_API_VERSION=1.40
      - CLEANUP=true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    networks:
      - soc-network

  shuffle-opensearch:
    image: opensearchproject/opensearch:2.14.0
    container_name: shuffle-opensearch
    restart: always
    environment:
      - discovery.type=single-node
      - DISABLE_SECURITY_PLUGIN=true
      - "OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g"
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - shuffle-opensearch-data:/usr/share/opensearch/data
    networks:
      - soc-network

volumes:
  shuffle-apps:
  shuffle-db:
  shuffle-opensearch-data:

networks:
  soc-network:
    external: true
EOF

info "Démarrage Shuffle..."
cd $SOC_DIR/shuffle && docker-compose up -d
log "Shuffle déployé"

# Fix OpenSearch cluster green
info "Configuration OpenSearch cluster green..."
sleep 30
docker exec shuffle-opensearch curl -sk -X PUT \
  "http://localhost:9200/_settings" \
  -H "Content-Type: application/json" \
  -d '{"index":{"number_of_replicas":0}}' > /dev/null 2>&1
docker exec shuffle-opensearch curl -sk -X PUT \
  "http://localhost:9200/_template/default" \
  -H "Content-Type: application/json" \
  -d '{"index_patterns":["*"],"settings":{"number_of_replicas":0}}' > /dev/null 2>&1
log "OpenSearch cluster green configuré"

# ════════════════════════════════════════════════════════════
section "ÉTAPE 6 — Déploiement OpenVAS/Greenbone"
# ════════════════════════════════════════════════════════════

info "Création docker-compose OpenVAS..."
cat > $SOC_DIR/gvm/docker-compose.yml << EOF
version: '3.7'

services:
  gvm:
    image: greenbone/community-edition
    container_name: openvas
    restart: always
    ports:
      - "9392:9392"
    volumes:
      - gvm-data:/var/lib/gvm
      - gvm-scap-data:/var/lib/gvm/scap-data
      - gvm-cert-data:/var/lib/gvm/cert-data
      - gvm-data:/opt/gvm
    networks:
      - soc-network

volumes:
  gvm-data:
  gvm-scap-data:
  gvm-cert-data:

networks:
  soc-network:
    external: true
EOF

info "Démarrage OpenVAS..."
cd $SOC_DIR/gvm && docker-compose up -d
log "OpenVAS déployé"

# ════════════════════════════════════════════════════════════
section "ÉTAPE 7 — Déploiement Suricata + Tenzir"
# ════════════════════════════════════════════════════════════

info "Installation Suricata..."
add-apt-repository -y ppa:oisf/suricata-stable > /dev/null 2>&1
apt-get update -qq
apt-get install -y -qq suricata

info "Configuration Suricata..."
IFACE=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
cat > /etc/suricata/suricata.yaml << EOF
vars:
  address-groups:
    HOME_NET: "[$SOC_IP/24]"
    EXTERNAL_NET: "!\$HOME_NET"

af-packet:
  - interface: $IFACE

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

rule-files:
  - suricata.rules

default-rule-path: /var/lib/suricata/rules
EOF

suricata-update > /dev/null 2>&1
systemctl enable suricata
systemctl start suricata
log "Suricata configuré et démarré"

info "Installation Tenzir..."
curl -fsSL https://get.tenzir.app | bash > /dev/null 2>&1 || warn "Tenzir : installation manuelle requise"

# ════════════════════════════════════════════════════════════
section "ÉTAPE 8 — Intégration Wazuh → TheHive"
# ════════════════════════════════════════════════════════════

info "Création alert-forwarder.py..."
cat > $SOC_DIR/wazuh/alert-forwarder.py << 'PYEOF'
#!/usr/bin/env python3
"""
Alert Forwarder — Wazuh → TheHive
Transmet les alertes Wazuh vers TheHive via l'API REST
"""
import json, time, os, requests, urllib3
urllib3.disable_warnings()

ALERTS_FILE  = "/var/ossec/logs/alerts/alerts.json"
CURSOR_FILE  = "/tmp/alert_cursor"
THEHIVE_URL  = "http://172.18.0.3:9000"
THEHIVE_KEY  = "/NVt7GQctThy6TUoldBg0MwmCgOasnUk"
MIN_LEVEL    = 3
SLEEP        = 60

HEADERS = {
    "Authorization": f"Bearer {THEHIVE_KEY}",
    "Content-Type":  "application/json"
}

SEVERITY_MAP = {3:1, 4:1, 5:1, 6:1, 7:2, 8:2, 9:2, 10:3, 11:3, 12:4, 13:4, 14:4, 15:4}
MITRE_MAP = {
    "T1046":"Discovery","T1110":"Credential Access","T1087":"Discovery",
    "T1021":"Lateral Movement","T1078":"Initial Access","T1055":"Defense Evasion",
    "T1059":"Execution","T1005":"Collection","T1071":"Command and Control"
}

def load_cursor():
    try:
        return int(open(CURSOR_FILE).read().strip())
    except:
        return 0

def save_cursor(pos):
    open(CURSOR_FILE,"w").write(str(pos))

def send(alert):
    level = alert.get("rule",{}).get("level",0)
    if level < MIN_LEVEL:
        return
    rule   = alert.get("rule",{})
    agent  = alert.get("agent",{})
    mitre  = rule.get("mitre",{}).get("id",[])
    sev    = SEVERITY_MAP.get(level, 2)
    tags   = [f"wazuh","level-{level}",f"agent-{agent.get('name','unknown')}"]
    if mitre:
        tags += [f"MITRE-{m}" for m in mitre]
    payload = {
        "title":       rule.get("description","Wazuh Alert"),
        "description": (
            f"**Agent:** {agent.get('name','?')} ({agent.get('ip','?')})\n"
            f"**Niveau:** {level}\n"
            f"**Règle:** {rule.get('id','?')}\n"
            f"**MITRE:** {', '.join(mitre) if mitre else 'N/A'}\n"
            f"**Timestamp:** {alert.get('timestamp','?')}\n\n"
            f"```json\n{json.dumps(alert,indent=2)[:2000]}\n```"
        ),
        "type":     "wazuh",
        "source":   "Wazuh SIEM",
        "severity": sev,
        "tags":     tags,
        "tlp":      2,
        "status":   "New"
    }
    try:
        r = requests.post(f"{THEHIVE_URL}/api/alert", headers=HEADERS, json=payload, verify=False, timeout=10)
        if r.status_code in (200,201):
            return True
    except Exception as e:
        print(f"Erreur TheHive : {e}")
    return False

def main():
    print("🚀 Wazuh Alert Forwarder démarré")
    while True:
        try:
            cursor = load_cursor()
            if not os.path.exists(ALERTS_FILE):
                time.sleep(SLEEP); continue
            fsize = os.path.getsize(ALERTS_FILE)
            if fsize < cursor:
                cursor = 0
            if fsize == cursor:
                time.sleep(SLEEP); continue
            with open(ALERTS_FILE,"r") as f:
                f.seek(cursor)
                sent = 0
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        alert = json.loads(line)
                        if send(alert):
                            sent += 1
                            print(f"🔀 TheHive: {alert.get('rule',{}).get('description','?')[:60]}")
                    except:
                        pass
                save_cursor(f.tell())
                if sent:
                    print(f"✅ {sent} alerte(s) transmise(s)")
        except Exception as e:
            print(f"Erreur : {e}")
        time.sleep(SLEEP)

if __name__ == "__main__":
    main()
PYEOF

info "Installation des dépendances Python..."
pip3 install requests --break-system-packages -q

info "Copie dans le conteneur Wazuh..."
sleep 10
docker cp $SOC_DIR/wazuh/alert-forwarder.py \
  wazuh-wazuh-manager-1:/var/ossec/integrations/alert-forwarder.py 2>/dev/null || \
  warn "Wazuh pas encore prêt — copie manuelle requise"

info "Création service systemd alert-forwarder..."
cat > /etc/systemd/system/wazuh-alert-forwarder.service << EOF
[Unit]
Description=Wazuh Alert Forwarder to TheHive
After=docker.service
Requires=docker.service

[Service]
Type=simple
Restart=always
RestartSec=30
ExecStart=/usr/bin/docker exec wazuh-wazuh-manager-1 \
  /var/ossec/framework/python/bin/python3 \
  /var/ossec/integrations/alert-forwarder.py
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/wazuh-alert-forwarder.timer << EOF
[Unit]
Description=Run Wazuh Alert Forwarder every minute
Requires=wazuh-alert-forwarder.service

[Timer]
OnBootSec=120
OnUnitActiveSec=60s

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable wazuh-alert-forwarder.timer
systemctl start wazuh-alert-forwarder.timer 2>/dev/null || true
log "Alert-forwarder configuré"

# ════════════════════════════════════════════════════════════
section "ÉTAPE 9 — Intégration MISP → TheHive (sync)"
# ════════════════════════════════════════════════════════════

info "Création script misp-thehive-sync..."
cat > $SOC_DIR/wazuh/misp-thehive-sync.py << 'PYEOF'
#!/usr/bin/env python3
"""
MISP → TheHive Sync
Synchronise les events MISP vers TheHive toutes les 5 minutes
"""
import json, time, requests, urllib3
urllib3.disable_warnings()

MISP_URL    = "https://172.18.0.11"
MISP_KEY    = "tO1UlFvNhz4Dm7p4dMJanJHuBqDRjJOm5R3pC483"
THEHIVE_URL = "http://172.18.0.3:9000"
THEHIVE_KEY = "/NVt7GQctThy6TUoldBg0MwmCgOasnUk"
SLEEP       = 300
SEEN_FILE   = "/tmp/misp_seen.json"

MISP_HEADERS    = {"Authorization": MISP_KEY, "Accept": "application/json", "Content-Type": "application/json"}
THEHIVE_HEADERS = {"Authorization": f"Bearer {THEHIVE_KEY}", "Content-Type": "application/json"}

def load_seen():
    try:
        return set(json.load(open(SEEN_FILE)))
    except:
        return set()

def save_seen(seen):
    json.dump(list(seen), open(SEEN_FILE,"w"))

def get_misp_events():
    try:
        r = requests.get(f"{MISP_URL}/events/index", headers=MISP_HEADERS, verify=False, timeout=15)
        return r.json() if r.ok else []
    except:
        return []

def create_thehive_alert(event):
    payload = {
        "title":       f"MISP Event: {event.get('info','Unknown')}",
        "description": (
            f"**Source:** MISP Threat Intelligence\n"
            f"**Event ID:** {event.get('id','?')}\n"
            f"**Date:** {event.get('date','?')}\n"
            f"**Threat Level:** {event.get('threat_level_id','?')}\n"
            f"**Tags:** {', '.join([t.get('name','') for t in event.get('Tag',[])])}"
        ),
        "type":     "misp",
        "source":   "MISP",
        "severity": int(event.get("threat_level_id","2")),
        "tags":     ["misp","threat-intel"] + [t.get("name","") for t in event.get("Tag",[])],
        "tlp":      2,
        "status":   "New"
    }
    try:
        r = requests.post(f"{THEHIVE_URL}/api/alert", headers=THEHIVE_HEADERS, json=payload, verify=False, timeout=10)
        return r.status_code in (200,201)
    except:
        return False

def main():
    print("🔄 MISP → TheHive Sync démarré")
    while True:
        seen = load_seen()
        events = get_misp_events()
        new = 0
        for event in events:
            eid = str(event.get("id",""))
            if eid and eid not in seen:
                if create_thehive_alert(event):
                    seen.add(eid)
                    new += 1
                    print(f"📡 MISP→TheHive: {event.get('info','?')[:50]}")
        if new:
            save_seen(seen)
            print(f"✅ {new} event(s) MISP synchronisé(s)")
        time.sleep(SLEEP)

if __name__ == "__main__":
    main()
PYEOF

info "Création service misp-thehive-sync..."
cat > /etc/systemd/system/misp-thehive-sync.service << EOF
[Unit]
Description=MISP to TheHive Sync Service
After=docker.service
Requires=docker.service

[Service]
Type=simple
Restart=always
RestartSec=60
ExecStart=/usr/bin/python3 $SOC_DIR/wazuh/misp-thehive-sync.py
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable misp-thehive-sync.service
systemctl start misp-thehive-sync.service 2>/dev/null || true
log "MISP → TheHive sync configuré"

# ════════════════════════════════════════════════════════════
section "ÉTAPE 10 — Fix OpenSearch permanent"
# ════════════════════════════════════════════════════════════

cat > $SOC_DIR/fix-opensearch.sh << 'EOF'
#!/bin/bash
for i in {1..20}; do
  code=$(docker exec shuffle-opensearch curl -sk -o /dev/null -w "%{http_code}" "http://localhost:9200" 2>/dev/null)
  [ "$code" = "200" ] && break
  sleep 10
done
docker exec shuffle-opensearch curl -sk -X PUT "http://localhost:9200/_settings" \
  -H "Content-Type: application/json" \
  -d '{"index":{"number_of_replicas":0}}' > /dev/null
docker exec shuffle-opensearch curl -sk -X PUT "http://localhost:9200/_template/default" \
  -H "Content-Type: application/json" \
  -d '{"index_patterns":["*"],"settings":{"number_of_replicas":0}}' > /dev/null
echo "✅ OpenSearch cluster green"
EOF
chmod +x $SOC_DIR/fix-opensearch.sh

cat > /etc/systemd/system/fix-opensearch.service << EOF
[Unit]
Description=Fix OpenSearch cluster green
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=$SOC_DIR/fix-opensearch.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable fix-opensearch.service
log "Fix OpenSearch permanent configuré"

# ════════════════════════════════════════════════════════════
section "ÉTAPE 11 — Sauvegarde automatique"
# ════════════════════════════════════════════════════════════

cat > $SOC_DIR/backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/opt/soc/backups"
DATE=$(date +%Y%m%d_%H%M%S)
DEST="$BACKUP_DIR/$DATE"
mkdir -p "$DEST"

# Configs
cp -r /opt/soc/wazuh/ossec.conf "$DEST/" 2>/dev/null
cp -r /opt/soc/wazuh/alert-forwarder.py "$DEST/" 2>/dev/null
cp -r /opt/thp/thehive/config "$DEST/thehive-config" 2>/dev/null
cp -r /opt/thp/cortex/config "$DEST/cortex-config" 2>/dev/null
cp -r /opt/soc/misp/certs "$DEST/misp-certs" 2>/dev/null

# TheHive DB
cp -r /opt/thp/thehive/db "$DEST/thehive-db" 2>/dev/null

# Credentials
cat > "$DEST/credentials.txt" << CREDS
Wazuh Dashboard : https://$(hostname -I | awk '{print $1}'):443
  admin / MyS3cr37P450r.*-

TheHive : http://$(hostname -I | awk '{print $1}'):9000
  soc@soc.local / SOC@Endeavour2025!

Cortex : http://$(hostname -I | awk '{print $1}'):9001
  analyst@soc.local / SOC@Endeavour2025!

MISP : https://$(hostname -I | awk '{print $1}'):8443
  admin@admin.test / SOC@Endeavour2025!

Shuffle : http://$(hostname -I | awk '{print $1}'):3001
  admin@soc.local / SOC@Endeavour2025!

OpenVAS : https://$(hostname -I | awk '{print $1}'):9392
  admin / Admin@GVM2025
CREDS

echo "✅ Backup créé dans $DEST"
EOF
chmod +x $SOC_DIR/backup.sh

echo "0 2 * * * root $SOC_DIR/backup.sh >> /var/log/soc-backup.log 2>&1" > /etc/cron.d/soc-backup
chmod 644 /etc/cron.d/soc-backup
log "Sauvegarde automatique configurée (2h00 quotidien)"

# ════════════════════════════════════════════════════════════
section "ÉTAPE 12 — Sauvegarde des credentials"
# ════════════════════════════════════════════════════════════

cat > $SOC_DIR/credentials.txt << EOF
═══════════════════════════════════════════
    SOC ENDEAVOUR MINING — CREDENTIALS
═══════════════════════════════════════════

Wazuh Dashboard : https://$SOC_IP:443
  Login    : admin
  Password : $WAZUH_PASS

TheHive : http://$SOC_IP:9000
  Login    : $THEHIVE_USER
  Password : $THEHIVE_PASS
  API Key  : $THEHIVE_API_KEY

Cortex : http://$SOC_IP:9001
  Login    : $CORTEX_USER
  Password : $CORTEX_PASS
  API Key  : $CORTEX_API_KEY

MISP : https://$SOC_IP:8443
  Login    : admin@admin.test
  Password : $MISP_PASS
  API Key  : $MISP_API_KEY

Shuffle : http://$SOC_IP:3001
  Login    : admin@soc.local
  Password : $SHUFFLE_PASS

OpenVAS : https://$SOC_IP:9392
  Login    : admin
  Password : Admin@GVM2025
EOF
chmod 600 $SOC_DIR/credentials.txt
log "Credentials sauvegardés dans $SOC_DIR/credentials.txt"

# Backup initial
$SOC_DIR/backup.sh

# ════════════════════════════════════════════════════════════
section "VÉRIFICATION FINALE"
# ════════════════════════════════════════════════════════════

info "Attente démarrage des services (60s)..."
sleep 60

echo ""
echo -e "${BOLD}État des services :${NC}"
services=("wazuh-wazuh-manager-1" "wazuh-wazuh-indexer-1" "wazuh-wazuh-dashboard-1"
          "thehive" "cortex" "elasticsearch"
          "misp" "misp-db"
          "shuffle-backend" "shuffle-frontend" "shuffle-opensearch"
          "openvas")

for svc in "${services[@]}"; do
  status=$(docker inspect --format='{{.State.Status}}' "$svc" 2>/dev/null)
  if [ "$status" = "running" ]; then
    echo -e "  ${GREEN}✓${NC} $svc"
  else
    echo -e "  ${RED}✗${NC} $svc (status: ${status:-non trouvé})"
  fi
done

echo ""
echo -e "${BOLD}Timers systemd :${NC}"
systemctl is-active wazuh-alert-forwarder.timer > /dev/null && \
  echo -e "  ${GREEN}✓${NC} wazuh-alert-forwarder.timer" || \
  echo -e "  ${RED}✗${NC} wazuh-alert-forwarder.timer"

systemctl is-active misp-thehive-sync.service > /dev/null && \
  echo -e "  ${GREEN}✓${NC} misp-thehive-sync.service" || \
  echo -e "  ${RED}✗${NC} misp-thehive-sync.service"

systemctl is-active suricata > /dev/null && \
  echo -e "  ${GREEN}✓${NC} suricata" || \
  echo -e "  ${RED}✗${NC} suricata"

echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  SOC Endeavour Mining — Déploiement OK !  ${NC}"
echo -e "${BOLD}${GREEN}══════════════════════════════════════════${NC}"
echo ""
echo -e "  ${CYAN}Wazuh Dashboard${NC}  : https://$SOC_IP:443"
echo -e "  ${CYAN}TheHive${NC}          : http://$SOC_IP:9000"
echo -e "  ${CYAN}Cortex${NC}           : http://$SOC_IP:9001"
echo -e "  ${CYAN}MISP${NC}             : https://$SOC_IP:8443"
echo -e "  ${CYAN}Shuffle${NC}          : http://$SOC_IP:3001"
echo -e "  ${CYAN}OpenVAS${NC}          : https://$SOC_IP:9392"
echo ""
echo -e "  Credentials : ${YELLOW}$SOC_DIR/credentials.txt${NC}"
echo ""

