# Validation du miroir

Le réseau de validation doit rester séparé du SOC d'origine. Copier les données revient aussi à copier les exécutions en attente, la file persistante et les tâches planifiées. Aucun confinement n'est ajouté.

## Source après export

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}'
systemctl status wazuh-to-soc.service --no-pager
```

Comparer au statut de départ. Certains services peuvent demander un délai. Un `running` sans contrôle de santé n'est pas une preuve de fonctionnement de l'application.

## Destination avant démarrage

1. Vérifier IP Ubuntu, interfaces Suricata, mémoire disponible, espace disque et droits des dossiers.
2. Régler `vm.max_map_count` pour les moteurs de recherche avant lancement :

```bash
sudo sysctl -w vm.max_map_count=262144
```

3. Mettre la même valeur dans un fichier `/etc/sysctl.d/99-soc.conf` pour la persistance.
4. Lire les configurations copiées localement sans les publier. Conserver SMTP et les cibles de scans inaccessibles sur le réseau isolé.

## Démarrage des composants techniques

Sur la copie uniquement :

```bash
docker start es-cortex misp-db misp-redis shuffle-database shuffle-opensearch wazuh-wazuh-indexer-1
```

Attendre l'initialisation des bases et vérifier leurs journaux localement et les contrôles de santé. Les journaux peuvent contenir des informations privées. Ensuite :

```bash
docker start thehive cortex misp wazuh-wazuh-manager-1 shuffle-backend
```

Vérifier leurs interfaces/API, puis :

```bash
docker start wazuh-wazuh-dashboard-1 shuffle-frontend
```

Le démarrage de Greenbone peut reprendre des tâches planifiées : ne démarrer `openvas` que sur un réseau où les anciennes cibles sont inaccessibles, puis désactiver/adapter ses planifications avant de lui donner accès au lab.

Le conteneur `tenzir-node` conserve son ancien lancement, mais sa fonction réseau réelle doit être vérifiée ; sa présence ne prouve pas un pipeline Suricata → Tenzir → Wazuh.

## Autoriser les traitements après vérification

- Configurer les destinations de test : TheHive, MISP, Cortex et une boîte mail de test.
- Examiner les files et anciennes exécutions Shuffle avant de démarrer `shuffle-orborus`.
- Adapter l'interface Suricata et le trafic réellement visible avant de démarrer la capture.
- Vérifier le seuil niveau 7 et le débit 6/minute du transfert restauré.
- Enrôler/raccorder les agents Windows au miroir, ou utiliser des VM Windows de test isolées.
- Effectuer un seul test et vérifier Wazuh → Shuffle → MISP/Cortex → TheHive → mail → validation humaine ; tester ensuite le doublon et le refus.
- Ne réactiver démarrage automatique et scans que lorsque les résultats sont constatés.

La méthode ne déclare jamais les intégrations opérationnelles sur la seule base d'un port ouvert. Greenbone se valide avec son état de feeds et un scan de cible autorisée. Les moteurs OpenSearch se valident par leur API/état de cluster et leurs données.
