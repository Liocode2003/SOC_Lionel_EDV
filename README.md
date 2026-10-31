# SOC Lionel EDV — export et installation du miroir

Ce dépôt contient les scripts lisibles pour exporter puis reproduire **la maquette existante**, avec ses données et configurations. Il ne reconstruit pas les organisations, workflows et clés à partir de zéro : il les reprend depuis un export privé à froid. Ce n'est pas une migration vers des versions plus récentes.

## Périmètre

Les 16 conteneurs identifiés dans l'inventaire : Wazuh 4.9.0 (Manager, Indexer, Dashboard), Shuffle (Frontend, Backend, Orborus, database, OpenSearch 2.14.0), TheHive 4, Cortex personnalisé 3.1.8, Elasticsearch 7.17.22, MISP, MySQL, Redis, OpenVAS/Greenbone et le conteneur Tenzir. Les images réellement présentes sont sauvegardées ; les tags `latest` ne sont pas retéléchargés pour remplacer leur contenu.

Les volumes nommés **et anonymes**, les dossiers montés, `/opt/soc`, `/opt/thp`, `/opt/shuffle`, `/opt/wazuh`, `/opt/Cortex-Analyzers`, les configurations/règles Suricata et le service de transfert sont repris. Les paramètres Docker sont conservés, sauf les redémarrages automatiques volontairement désactivés sur la copie.

## Commande unique depuis GitHub

Après avoir ajouté tous les fichiers de ce projet à la racine du dépôt :

```bash
git clone https://github.com/Liocode2003/SOC_Lionel_EDV.git
cd SOC_Lionel_EDV
sudo bash deploy_soc.sh
```

Le même lanceur propose un menu **Exporter**, **Installer/restaurer**, **Tester**.
Lancer **Exporter** sur la source, transférer la sauvegarde par un canal privé,
puis lancer **Installer/restaurer** sur la destination. Les configurations sont
reprises depuis la sauvegarde ; rien n'est envoyé à GitHub par le script.

Ces opérations concernent deux VM distinctes : un lien GitHub ne transporte pas
les bases privées de la source. Ce programme n'effectue pas de migration SSH
automatique entre les deux hôtes et ne configure pas un SOC neuf sans export.

Le lanceur `deploy_soc.sh` remplace l'ancienne version Base64. Tous les fichiers
doivent être présents à la racine du dépôt ; télécharger ce seul fichier ne suffit pas.

## 1. Sur la VM SOC actuelle — export

Télécharger le dépôt ou extraire son ZIP, puis ouvrir un terminal dans le dossier :

```bash
sudo bash exporter_soc.sh --dossier /root/sauvegarde-soc-01 --arret-confirme
```

Cette commande **arrête temporairement le SOC**, sauvegarde les systèmes de fichiers des conteneurs, les données montées, les configurations et les images locales, puis relance les conteneurs et services qui étaient actifs. Prévoir une fenêtre d'arrêt ; une copie des bases et des images peut durer longtemps et utiliser beaucoup d'espace. Choisir une destination avec suffisamment de place, hors des dossiers SOC. Laisser la commande finir et vérifier le redémarrage de la source.

Les workers/exécutions en cours ne sont pas clonés. Si d'autres conteneurs sont actifs, l'export s'arrête avant l'arrêt des services : attendre leur fin ou examiner ces conteneurs. Les WAITING et les anciennes exécutions restent dans les bases copiées ; elles ne sont pas annulées automatiquement.

Le dossier privé créé contient :

- `manifest.json` : paramètres Docker, services, empreintes et images de référence ;
- `images.tar` : images et instantanés des conteneurs, analyseurs/workers déjà téléchargés ;
- `hote.tar` : configurations et dossiers hôte ;
- `volumes/` : données persistantes.

**Ce dossier contient des mots de passe, clés API, certificats privés, alertes et comptes. Ne pas le joindre au chat ni le publier sur GitHub.** Le transférer par un canal privé vers la VM cible. Les archives ne sont pas chiffrées par le programme ; les protéger comme la VM d'origine. Les empreintes détectent une corruption, pas une modification malveillante du manifeste.

## 2. Sur une VM Ubuntu 24.04 neuve — installation/restauration

Utiliser une VM x86_64 dédiée, avec assez de RAM et d'espace pour les données et une seconde copie des images. Elle doit être **isolée du réseau du SOC source et des serveurs de démonstration**, pour ne pas dupliquer scans, courriels et actions.

```bash
sudo bash installer_soc.sh --dossier /chemin/prive/sauvegarde-soc-01 --vm-isolee
```

Le script vérifie les archives, installe Docker depuis le dépôt Docker officiel si absent, installe les dépendances hôte sélectionnées, recrée les réseaux et volumes, puis restaure les fichiers et les 16 conteneurs. Il refuse d'écraser des conteneurs, volumes, réseaux ou chemins SOC préexistants.

À la fin, les conteneurs sont **créés mais arrêtés**, et les services de transfert/capture sont désactivés. C'est l'état attendu avant validation ; ce message ne signifie pas que les interfaces sont opérationnelles.

**Adresses IP :** le miroir conserve les adresses et références source, dont 192.168.152.50 et le réseau Docker 172.18.0.0/16. Le script ne change ni l'IP Ubuntu ni les URL imbriquées dans les applications. Pour un miroir fidèle, attribuer l'ancienne IP uniquement dans un réseau isolé. Pour une autre IP ou un fonctionnement en parallèle, adapter d'abord certificats, URL, workflows, SMTP et agents.

## 3. Validation et activation

Lire [VALIDATION.md](VALIDATION.md). Ne pas démarrer les scanners ou les notifications avant cette étape.

## Sur GitHub

Déposer uniquement les fichiers de ce projet. Le `.gitignore` exclut les archives usuelles mais ne remplace pas une revue avant publication. Le dossier de sauvegarde doit rester **hors du dépôt**, quel que soit son nom. Aucune publication GitHub n'est effectuée par ces scripts.

## Tests

```bash
python3 -m unittest discover -s tests -v
bash -n installer_soc.sh
bash -n exporter_soc.sh
```

Tests hors ligne : chemins, archives, intégrité, paramètres Docker et relance de la source après un échec simulé. **Aucun export/restauration réel n'a été effectué pendant la préparation** : valider d'abord sur une copie jetable de la VM. Le transfert Wazuh, MISP, Cortex, TheHive, le mail et la décision humaine doivent être vérifiés de bout en bout après restauration.

## Limites précises

- Copie applicative Docker + configurations hôte sélectionnées ; ce n'est pas une image disque Ubuntu.
- Les serveurs Windows, l'AD, leurs fichiers et la base Odoo distante ne sont pas copiés. Leurs agents devront être raccordés au SOC cible ou leurs VM clonées séparément.
- Les clés/licences et comptes externes restent ceux de l'export : vérifier leurs conditions et leur validité ; pas de génération de nouvelles clés d'API tierces.
- Les dépendances Python installées dans les conteneurs sont conservées. Les paquets hôte Ubuntu sont installés depuis les dépôts disponibles : leur version peut différer ; comparer Suricata avant activation. Les paquets hôte non listés et tâches cron externes ne sont pas reproduits automatiquement.
- Volumes locaux et réseaux bridge locaux seulement. Les partages distants, montages hors périmètre et namespaces partagés sont refusés.
- La destination reçoit les données/configurations, pas les utilisateurs Linux d'origine. Les UID/GID numériques des fichiers sont conservés. Adapter les unités qui nécessitent un utilisateur hôte particulier avant activation.
- Ne pas exécuter `docker compose up` immédiatement après restauration : cela peut recréer des conteneurs à partir des images initiales plutôt que des instantanés. Conserver les images `soc-miroir/...` et adapter les Compose à ces images avant une gestion quotidienne avec Compose.
- Les images de capture restent dans Docker sur la source et consomment de l'espace. Aucune suppression automatique des images ou volumes n'est effectuée.
- Un échec laisse les éléments partiellement restaurés pour diagnostic. Repartir d'une VM cible neuve ; aucune purge automatique.

## Références de la méthode

- https://docs.docker.com/reference/cli/docker/container/commit/
- https://docs.docker.com/reference/cli/docker/image/save/
- https://docs.docker.com/reference/cli/docker/image/load/
- https://docs.docker.com/engine/install/ubuntu/
- https://docs.docker.com/reference/api/engine/

Une image issue de `docker commit` ne contient pas les volumes montés : c'est pourquoi ces données sont exportées séparément.
