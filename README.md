# SOC Lionel EDV installation autonome

Installation d'un **SOC neuf sur une nouvelle VM Ubuntu 24.04 x86_64**, à partir des sources publiques et de modèles de configuration inclus. Aucun export, aucune base de données, aucune clé et aucun identifiant de l'ancienne VM ne sont nécessaires.

**État : première version de l'automatisation, vérifiée par tests locaux ; le déploiement réel sur une VM neuve n'a pas encore été effectué.** Ne pas annoncer que toute la chaîne est opérationnelle avant le premier essai réel. Les versions et les contrats des APIs amont peuvent nécessiter un ajustement ; le programme arrête l'étape concernée et conserve les données.

## Installation depuis GitHub

Après publication de **tout le contenu de ce dossier à la racine** du dépôt `Liocode2003/SOC_Lionel_EDV` :

```bash
git clone https://github.com/Liocode2003/SOC_Lionel_EDV.git
cd SOC_Lionel_EDV
sudo bash deploy_soc.sh
```

Ce nouveau `deploy_soc.sh` **remplace** le lanceur de miroir. Les scripts `exporter_soc.sh`, `installer_soc.sh` et `miroir_soc.py` de l'ancien paquet ne sont pas utilisés. Remplacer aussi le README, ajouter les modules Python, `templates/`, `tests/`, `.gitignore` et le script Windows. Ne pas publier le dossier `/opt/soc/autonome`.

Le programme demande au départ :

- l'IP réseau de la VM et l'interface de capture ;
- les clés personnelles VirusTotal et AbuseIPDB ;
- le serveur SMTP STARTTLS, le compte, son mot de passe d'application et le destinataire ;
- les éventuelles IP de cibles à préparer dans Greenbone, sans lancer de scans ;
- les IDs des feeds MISP à activer (par défaut 1 et 2 parmi les feeds fournis par MISP).

Il génère les mots de passe locaux et les secrets applicatifs. Ces valeurs sont conservées dans `/opt/soc/autonome/configuration-privee.json` avec des droits privés. **Aucune de ces valeurs ne doit aller dans GitHub ou dans le chat.** Le fichier `/opt/soc/autonome/etat.json` contient également des clés générées : il est privé.

Pour ne faire que la saisie initiale :

```bash
sudo bash deploy_soc.sh --preparer
```

Puis lancer normalement. Une configuration JSON privée peut également être fournie avec `--config /chemin/configuration-privee.json`.

## Ce que le programme automatise

| Étape | Action prévue par le programme |
|---|---|
| Ubuntu et Docker | Dépendances, dépôt Docker officiel, Compose et paramètre noyau des indexeurs |
| Wazuh | Déploiement officiel 4.14.9, certificats locaux, secrets générés, collecte de la sortie Tenzir et règle Suricata 100230 |
| Moteurs de stockage | Wazuh Indexer, OpenSearch de Shuffle, Elasticsearch 7.17.22 de Cortex et composants persistants des autres outils |
| TheHive | Instance TheHive 4 neuve de laboratoire, organisation SOC, utilisateur et clé API |
| Cortex | Version 3.1.8, administrateur, organisation, compte API et activation des analyseurs de consultation VirusTotal/AbuseIPDB |
| MISP | Déploiement officiel, organisation/administrateur/clé initiale, chargement des définitions de feeds et demandes de synchronisation |
| Shuffle | Compte administrateur, Orborus limité à deux exécutions, recherche/activation de Shuffle Tools, deux workflows générés et webhook démarré |
| Greenbone | Community Containers officiels, données de feeds, changement du mot de passe, attente des configurations de scan et création des cibles/tâches demandées |
| Suricata et Tenzir | Capture IDS sur l'interface choisie et pipeline EVE vers le fichier JSON collecté par Wazuh |
| Tests | Test local du décodage Wazuh, puis alerte synthétique d'intégration Shuffle/MISP/Cortex/TheHive/SMTP |
| Transfert continu | Service persistant Wazuh → Shuffle, niveau minimum 7, débit maximum 6/minute, activé après réussite du test d'intégration |

Les analyseurs exécutés dans Cortex utilisent leurs images Docker de catalogue ; aucune installation APT non authentifiée ni ancien Dockerfile personnalisé n'est repris.

TheHive utilise le profil BerkeleyJE/Lucene de laboratoire, ce qui ne correspond pas à un déploiement de production en cluster. Les secrets et identifiants sont nouveaux. Aucun historique d'alerte, ancienne organisation, compte ou exécution de la VM source n'est importé.

Les images tirées sont résolues en digests dans les fichiers `compose.lock.json`. Les dépôts MISP/Shuffle et les catalogues évoluent : les premières installations à des dates différentes ne sont pas garanties identiques. La reprise réutilise les manifests verrouillés déjà présents.

## Capacités de la VM

Ubuntu 24.04 x86_64, accès Internet aux dépôts/registries/APIs, droits sudo, interface existante et ports disponibles. Pour cette concentration de composants, le programme applique une garde de capacité d'environ **32 Go RAM et 150 Gio libres**, sans prétendre à un dimensionnement de production. Il refuse les outils déjà installés pour éviter de les écraser.

L'IP et l'interface doivent appartenir à la nouvelle VM. Aucun ancien réseau `192.168.152.x` n'est imposé. Les feeds Greenbone et les images peuvent être volumineux ; l'installation peut prendre longtemps.

## Reprise après un échec

```bash
sudo bash deploy_soc.sh --reprendre
```

Les étapes validées sont conservées. Les services et données ne sont pas supprimés. Une modification de la configuration privée pendant la reprise est refusée afin de ne pas mélanger des identifiants incohérents.

En cas d'erreur d'API ou d'incompatibilité, examiner l'étape en échec et les journaux privés avant de reprendre. Le mécanisme n'est pas une transaction distribuée : un incident entre création distante et écriture locale peut demander un rapprochement manuel d'un objet déjà créé. Une reprise n'effectue pas de mise à niveau ni de réparation arbitraire d'un outil existant.

## Tests et validation humaine

Le programme utilise un événement synthétique clairement intitulé `TEST INSTALLATION SOC` contenant l'IP publique `1.1.1.1`. Il commence dans Shuffle : **ce test ne prouve pas une détection réseau par Wazuh** et ne qualifie pas cette IP de malveillante.

Il attend les résultats des étapes, la création d'une alerte TheHive et l'acceptation du courriel par le serveur SMTP. Une absence de correspondance MISP est un résultat valide. L'analyste doit encore constater la réception, ouvrir le lien et prendre sa décision. Aucune validation humaine n'est cliquée automatiquement et aucun confinement n'est ajouté.

Le test `wazuh-logtest` vérifie séparément le décodage et la règle 100230. La visibilité du capteur, la collecte effective d'événements réels, l'absence de pertes, les règles des scénarios Windows/Odoo, les performances, la déduplication d'une retransmission et le refus humain restent à valider sur le laboratoire.

Greenbone crée les tâches mais **ne lance pas de scan**. Les synchronisations MISP peuvent continuer en arrière-plan ; leur succès effectif ne se déduit pas de l'acceptation de la demande. L'initialisation Greenbone attend l'apparition de configurations de scan, ce qui ne prouve pas que l'ensemble de tous les feeds est à jour.

## Raccordement des serveurs Windows et Odoo

La VM SOC est indépendante de l'ancienne. Les machines à superviser restent des systèmes distincts. Leur installation nécessite une action sur ces machines ou des accès administrateur qui ne sont pas inventés par le programme.

Sur un Windows neuf, un script d'enrôlement est fourni :

```powershell
.\agent_windows.ps1 -Manager "IP_DU_NOUVEAU_SOC" -AgentName "FILE-ODOO"
```

Le script vérifie la signature du MSI et refuse de réinstaller un agent déjà présent. La collecte des journaux Odoo et la surveillance FIM des répertoires du projet dépendent des chemins réels et ne sont pas configurées par ce script minimal. Configurer ces chemins avant de prétendre à une détection applicative XSS ou à une couverture de la base Odoo.

## Points techniques à connaître

- Des certificats auto-signés locaux sont utilisés par certaines interfaces. Le provisionnement MISP sur boucle locale et le workflow dans le réseau Docker autorisent ces certificats ; ne pas reprendre cette configuration TLS telle quelle pour une exposition externe.
- Le mode SMTP pris en charge est STARTTLS (par défaut 587), avec authentification. Le port SMTPS 465 n'est pas pris en charge par ce modèle.
- Le pipeline Tenzir de laboratoire lit les nouvelles lignes. Il n'offre pas de reprise durable pendant une interruption. La file persistante du transfert concerne les alertes Wazuh déjà collectées.
- L'installation ne configure pas le miroir VMware/TAP : la visibilité réseau doit exister sur l'interface choisie.
- Les sauvegardes cohérentes des bases et leur restauration restent un chantier séparé : les fichiers de configuration ne remplacent pas une sauvegarde complète. Aucun export de l'ancienne VM n'est nécessaire au déploiement.
- Les anciens TheHive 4/Cortex 3.1.8 ont été retenus pour la logique du laboratoire ; cette livraison n'affirme pas leur adéquation à la production ou une couverture de sécurité actuelle.

## Vérifications de préparation

```bash
bash deploy_soc.sh --tests
```

Onze tests locaux couvrent les identifiants des workflows, leurs liaisons, les étapes Python embarquées, l'exclusion des anciennes références, les erreurs d'API, la reprise Cortex et les alias réseau. Ils utilisent des simulations et **ne prouvent pas le bon fonctionnement des images ni l'exécution du programme sur Ubuntu neuf**.

## Références

- https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html
- https://github.com/wazuh/wazuh-docker/tree/v4.14.9/single-node
- https://github.com/TheHive-Project/TheHive
- https://docs.strangebee.com/cortex/api/api-guide/
- https://github.com/MISP/misp-docker
- https://github.com/Shuffle/Shuffle
- https://github.com/Shuffle/shuffle-docs/blob/master/docs/API.md
- https://greenbone.github.io/docs/latest/22.4/container/
- https://docs.suricata.io/en/latest/quickstart.html
- https://tenzir.com/docs/
