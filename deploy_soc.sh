#!/usr/bin/env bash
# Point d'entrée unique du miroir SOC. Aucun secret ni archive privée dans GitHub.
set -euo pipefail
SOC_DEPLOY_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
usage_soc() {
    cat <<'EOF'
SOC Lionel EDV — export et installation du miroir

Menu interactif : sudo bash deploy_soc.sh
Export source : sudo bash deploy_soc.sh exporter --dossier /root/sauvegarde-soc-01 --arret-confirme
Installation cible : sudo bash deploy_soc.sh installer --dossier /chemin/sauvegarde-soc-01 --vm-isolee
Tests hors ligne : bash deploy_soc.sh tester

L'export copie la configuration et les données existantes ; il arrête temporairement
les services puis les relance. L'installation restaure cet export sur une VM neuve.
Le transfert privé de la sauvegarde entre les deux VM est une étape distincte.
Les conteneurs cibles restent arrêtés jusqu'à la validation décrite dans VALIDATION.md.
EOF
}
if [[ "${1:-}" == '--help' || "${1:-}" == '-h' ]]; then usage_soc; exit 0; fi
for SOC_REQUIRED_FILE in miroir_soc.py exporter_soc.sh installer_soc.sh; do
    [[ -f "$SOC_DEPLOY_DIR/$SOC_REQUIRED_FILE" ]] || {
        echo "Fichier manquant : $SOC_REQUIRED_FILE. Récupérer tout le dépôt avec git clone." >&2
        exit 1
    }
done
if [[ "$#" -gt 0 ]]; then
    SOC_MODE="$1"; shift
    case "$SOC_MODE" in
        exporter) exec bash "$SOC_DEPLOY_DIR/exporter_soc.sh" "$@" ;;
        installer) exec bash "$SOC_DEPLOY_DIR/installer_soc.sh" "$@" ;;
        tester) exec python3 -m unittest discover -s "$SOC_DEPLOY_DIR/tests" -v ;;
        *) usage_soc; exit 2 ;;
    esac
fi
[[ "$EUID" -eq 0 ]] || { echo 'Lancer : sudo bash deploy_soc.sh' >&2; exit 1; }
printf '\nSOC Lionel EDV\n1. Exporter cette VM SOC\n2. Installer/restaurer sur cette VM neuve\n3. Exécuter les tests hors ligne\n0. Quitter\n\n'
read -r -p 'Choix : ' SOC_CHOICE
case "$SOC_CHOICE" in
    1)
        read -r -p 'Dossier privé de sauvegarde [/root/sauvegarde-soc-01] : ' SOC_FOLDER
        SOC_FOLDER="${SOC_FOLDER:-/root/sauvegarde-soc-01}"
        echo 'Les services seront arrêtés pendant la copie puis relancés. Ne pas exporter pendant une démonstration.'
        read -r -p 'Taper EXPORTER pour commencer : ' SOC_CONFIRM
        [[ "$SOC_CONFIRM" == EXPORTER ]] || { echo 'Annulé.'; exit 0; }
        exec bash "$SOC_DEPLOY_DIR/exporter_soc.sh" --dossier "$SOC_FOLDER" --arret-confirme
        ;;
    2)
        read -r -p 'Chemin du dossier privé de sauvegarde transféré sur cette VM : ' SOC_FOLDER
        [[ -n "$SOC_FOLDER" ]] || { echo 'Dossier requis.' >&2; exit 2; }
        echo 'Réservé à Ubuntu 24.04 neuf, isolé du réseau du SOC source.'
        echo 'Les IP et URL de la source seront conservées ; la copie restera arrêtée après restauration.'
        read -r -p 'Taper INSTALLER pour confirmer cette destination : ' SOC_CONFIRM
        [[ "$SOC_CONFIRM" == INSTALLER ]] || { echo 'Annulé.'; exit 0; }
        exec bash "$SOC_DEPLOY_DIR/installer_soc.sh" --dossier "$SOC_FOLDER" --vm-isolee
        ;;
    3) exec python3 -m unittest discover -s "$SOC_DEPLOY_DIR/tests" -v ;;
    0) exit 0 ;;
    *) echo 'Choix invalide.' >&2; exit 2 ;;
esac
