#!/usr/bin/env bash
# ============================================================
# SOC ENDEAVOUR MINING — SCRIPT DE SIMULATION / DÉMONSTRATION
# Ce script n'installe rien réellement.
# Il affiche un déploiement simulé pour captures pédagogiques.
# ============================================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SOC_IP="192.168.152.50"
LOG_FILE="deploy_soc_simulation.log"

log()  { echo -e "${GREEN}[✓] $1${NC}" | tee -a "$LOG_FILE"; }
info() { echo -e "${CYAN}[→] $1${NC}" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[!] $1${NC}" | tee -a "$LOG_FILE"; }

section() {
  echo -e "\n${BOLD}${CYAN}════════════════════════════════════════════════════${NC}" | tee -a "$LOG_FILE"
  echo -e "${BOLD}${CYAN}  $1${NC}" | tee -a "$LOG_FILE"
  echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════${NC}\n" | tee -a "$LOG_FILE"
}

progress() {
  info "$1"
  sleep 0.4
  echo "   Progression : 25%"
  sleep 0.3
  echo "   Progression : 50%"
  sleep 0.3
  echo "   Progression : 75%"
  sleep 0.3
  echo "   Progression : 100%"
  sleep 0.3
  log "$1 terminé"
}

clear
echo -e "${BOLD}${CYAN}"
echo "  ____   ___   ____     _____           _"
echo " / ___| / _ \ / ___|   | ____|_ __   __| | ___  __ ___   _____  _   _ _ __"
echo " \___ \| | | | |       |  _| | '_ \ / _\` |/ _ \/ _\` \ \ / / _ \| | | | '__|"
echo "  ___) | |_| | |___    | |___| | | | (_| |  __/ (_| |\ V / (_) | |_| | |"
echo " |____/ \___/ \____|   |_____|_| |_|\__,_|\___|\__,_| \_/ \___/ \__,_|_|"
echo -e "${NC}"
echo -e "${BOLD}       SOC Endeavour Mining — Déploiement automatisé${NC}"
echo -e "       Mode : ${YELLOW}SIMULATION / DÉMONSTRATION${NC}"
echo -e "       IP hôte : ${CYAN}${SOC_IP}${NC}"
echo ""
read -p "Continuer la simulation ? (o/n) : " confirm
if [ "$confirm" != "o" ] && [ "$confirm" != "O" ]; then
  echo "Simulation annulée."
  exit 0
fi

echo "SOC Endeavour Mining — Simulation" > "$LOG_FILE"
echo "Date : $(date)" >> "$LOG_FILE"
echo "Mode : SIMULATION" >> "$LOG_FILE"

section "ÉTAPE 1 — Prérequis système"
progress "Mise à jour Ubuntu 24.04 LTS"
progress "Installation dépendances : curl, git, jq, python3, openssl, cron"
progress "Installation Docker Engine"
progress "Installation Docker Compose"
progress "Configuration vm.max_map_count=262144"

section "ÉTAPE 2 — Préparation de l'environnement SOC"
progress "Création des répertoires /opt/soc et /opt/thp"
progress "Création des volumes persistants"
progress "Préparation des fichiers de configuration"
log "Environnement SOC préparé"

section "ÉTAPE 3 — Wazuh SIEM/XDR"
progress "Déploiement Wazuh Manager"
progress "Déploiement Wazuh Indexer basé sur OpenSearch"
progress "Déploiement Wazuh Dashboard"
progress "Configuration ossec.conf"
progress "Activation réception agents Windows"
log "Wazuh opérationnel : Manager + Indexer + Dashboard"
log "Agents Windows actifs : DC/DNS et File/Odoo"

section "ÉTAPE 4 — TheHive"
progress "Déploiement TheHive Case Management"
progress "Configuration BerkeleyDB"
progress "Création organisation SOC"
progress "Création utilisateur soc@soc.local"
log "TheHive opérationnel sur http://${SOC_IP}:9000"

section "ÉTAPE 5 — Cortex"
progress "Déploiement Cortex"
progress "Configuration Elasticsearch 7.17.22"
progress "Activation VirusTotal_GetReport_3_1"
progress "Activation VirusTotal_Scan_3_1"
progress "Activation AbuseIPDB_2_0"
log "Cortex opérationnel avec 3 analyseurs actifs"

section "ÉTAPE 6 — MISP"
progress "Déploiement MISP"
progress "Déploiement MySQL"
progress "Déploiement Redis"
progress "Génération certificats SSL auto-signés"
progress "Activation des 10 feeds de Threat Intelligence"
log "MISP opérationnel sur https://${SOC_IP}:8443"

section "ÉTAPE 7 — Shuffle SOAR"
progress "Déploiement Shuffle Frontend"
progress "Déploiement Shuffle Backend"
progress "Déploiement Shuffle OpenSearch"
progress "Configuration replicas=0 pour statut green"
progress "Création workflow Wazuh-Alert-to-TheHive"
log "Shuffle opérationnel sur http://${SOC_IP}:3001"

section "ÉTAPE 8 — OpenVAS / Greenbone"
progress "Déploiement Greenbone Community Edition"
progress "Synchronisation des feeds vulnérabilités"
progress "Création cibles DC01 et File/Odoo"
progress "Création scans Full and Fast"
log "OpenVAS opérationnel sur https://${SOC_IP}:9392"

section "ÉTAPE 9 — Suricata IDS/IPS"
progress "Installation Suricata"
progress "Configuration interface réseau"
progress "Activation règles Emerging Threats"
progress "Activation sortie EVE JSON"
log "Suricata actif et opérationnel"

section "ÉTAPE 10 — Tenzir"
progress "Installation Tenzir"
progress "Création pipeline Suricata EVE JSON"
progress "Normalisation des événements réseau"
progress "Transmission vers Wazuh"
log "Pipeline Suricata → Tenzir → Wazuh actif"

section "ÉTAPE 11 — Intégrations SOC"
progress "Wazuh → TheHive via alert-forwarder.py"
progress "Wazuh → Shuffle via webhook"
progress "Wazuh → MISP pour IOCs critiques"
progress "TheHive ↔ Cortex pour enrichissement"
progress "MISP → TheHive toutes les 5 minutes"
progress "Suricata → Tenzir → Wazuh en temps réel"
log "6 intégrations SOC configurées"

section "ÉTAPE 12 — Sauvegardes"
progress "Création script backup.sh"
progress "Planification cron quotidienne à 02h00"
progress "Sauvegarde configurations critiques"
log "Sauvegardes automatiques configurées"

section "ÉTAPE 13 — Tests de validation"
progress "Test Nmap — MITRE T1046"
progress "Test Hydra SMB — MITRE T1110"
progress "Test enum4linux — MITRE T1087"
progress "Test OpenVAS — vulnérabilités Windows"
log "4/4 tests détectés avec succès"

section "VÉRIFICATION FINALE"

echo -e "${BOLD}État des conteneurs :${NC}"
echo -e "  ${GREEN}✓${NC} wazuh-manager              running"
echo -e "  ${GREEN}✓${NC} wazuh-indexer              running"
echo -e "  ${GREEN}✓${NC} wazuh-dashboard            running"
echo -e "  ${GREEN}✓${NC} thehive                    running"
echo -e "  ${GREEN}✓${NC} cortex                     running"
echo -e "  ${GREEN}✓${NC} misp                       running"
echo -e "  ${GREEN}✓${NC} misp-db                    running"
echo -e "  ${GREEN}✓${NC} redis                      running"
echo -e "  ${GREEN}✓${NC} shuffle-frontend           running"
echo -e "  ${GREEN}✓${NC} shuffle-backend            running"
echo -e "  ${GREEN}✓${NC} shuffle-opensearch         running"
echo -e "  ${GREEN}✓${NC} openvas                    running"

echo ""
echo -e "${BOLD}Services système :${NC}"
echo -e "  ${GREEN}✓${NC} docker                     active (running)"
echo -e "  ${GREEN}✓${NC} suricata                   active (running)"
echo -e "  ${GREEN}✓${NC} tenzir-pipeline            active (running)"
echo -e "  ${GREEN}✓${NC} wazuh-alert-forwarder      active (running)"
echo -e "  ${GREEN}✓${NC} misp-thehive-sync          active (running)"

echo ""
echo -e "${BOLD}Interfaces disponibles :${NC}"
echo -e "  ${CYAN}Wazuh Dashboard${NC}  : https://${SOC_IP}:443"
echo -e "  ${CYAN}TheHive${NC}          : http://${SOC_IP}:9000"
echo -e "  ${CYAN}Cortex${NC}           : http://${SOC_IP}:9001"
echo -e "  ${CYAN}MISP${NC}             : https://${SOC_IP}:8443"
echo -e "  ${CYAN}Shuffle${NC}          : http://${SOC_IP}:3001"
echo -e "  ${CYAN}OpenVAS${NC}          : https://${SOC_IP}:9392"

echo ""
echo -e "${BOLD}Résultats simulés :${NC}"
echo -e "  ${GREEN}✓${NC} Alertes Wazuh générées : 4 303"
echo -e "  ${GREEN}✓${NC} Cases TheHive créés : 3 151"
echo -e "  ${GREEN}✓${NC} Events MISP disponibles : 185"
echo -e "  ${GREEN}✓${NC} Exécutions Shuffle : 100"
echo -e "  ${GREEN}✓${NC} Analyseurs Cortex actifs : 3"
echo -e "  ${GREEN}✓${NC} Scans Greenbone réalisés : 2"

echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  SOC Endeavour Mining — Simulation terminée avec succès${NC}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Mode simulation : aucun service réel n'a été installé.${NC}"
echo -e "${YELLOW}Log généré : ${LOG_FILE}${NC}"
