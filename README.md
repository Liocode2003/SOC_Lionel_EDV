# 🛡️ SOC Endeavour Mining — Déploiement automatisé

<div align="center">

![SOC](https://img.shields.io/badge/SOC-Endeavour%20Mining-gold?style=for-the-badge\&logo=shield\&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-E95420?style=for-the-badge\&logo=ubuntu\&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge\&logo=docker\&logoColor=white)
![Wazuh](https://img.shields.io/badge/Wazuh-4.9.0-00bcd4?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**Conception et implémentation d’un Security Operations Center (SOC)**
*Projet de fin de cycle — ISGE-BF | Endeavour Mining | 2025–2026*

**NADZIGA Franck Lionel Elvis Kiswendsida**

</div>

---

## 📋 Description

Ce dépôt présente le script de déploiement automatisé du SOC Endeavour Mining.
Il permet d’installer et de préparer une stack SOC complète sur une machine Ubuntu 24.04 LTS à l’aide de Docker, Docker Compose et de services système.

Le script automatise le déploiement initial des principales composantes du SOC et prépare les intégrations entre les outils. Certaines opérations complémentaires, notamment la création des clés API, l’activation des feeds MISP, la configuration des analyseurs Cortex, la création des workflows Shuffle et l’enrôlement des agents Windows, sont finalisées depuis les interfaces d’administration.

---

## 🧰 Stack déployée

| Outil                 |            Version | Rôle                                               |
| --------------------- | -----------------: | -------------------------------------------------- |
| **Wazuh**             |              4.9.0 | SIEM / XDR — supervision, corrélation et détection |
| **Wazuh Indexer**     | OpenSearch intégré | Stockage et indexation des événements              |
| **Wazuh Dashboard**   |              4.9.0 | Interface de visualisation                         |
| **TheHive**           |                5.2 | Gestion des alertes et des incidents               |
| **Cortex**            |              3.1.8 | Analyse et enrichissement des observables          |
| **MISP**              |             Latest | Threat Intelligence Platform                       |
| **Shuffle**           |             Latest | SOAR — automatisation des réponses                 |
| **Suricata**          |             Latest | IDS/IPS réseau                                     |
| **Tenzir**            |             Latest | Pipeline de transformation et normalisation        |
| **Greenbone/OpenVAS** |             Latest | Scanner de vulnérabilités                          |

---

## ⚡ Installation

### Prérequis

* Ubuntu 24.04 LTS
* Minimum recommandé : **12 à 16 Go RAM**, 4 vCPU, 80 à 100 Go disque
* Accès Internet
* Droits root ou sudo

### Déploiement

```bash
git clone https://github.com/Liocode2003/SOC_Lionel_EDV.git
cd SOC_Lionel_EDV

chmod +x deploy_soc.sh
sudo ./deploy_soc.sh
```

> Le temps de déploiement dépend de la connexion Internet et du démarrage des services lourds comme Wazuh, MISP et Greenbone/OpenVAS.

---

## 🌐 Accès aux interfaces

Après le déploiement, les interfaces sont accessibles depuis l’adresse IP de la machine hôte :

| Interface             | URL                 |
| --------------------- | ------------------- |
| **Wazuh Dashboard**   | `https://<IP>:443`  |
| **TheHive**           | `http://<IP>:9000`  |
| **Cortex**            | `http://<IP>:9001`  |
| **MISP**              | `https://<IP>:8443` |
| **Shuffle**           | `http://<IP>:3001`  |
| **Greenbone/OpenVAS** | `https://<IP>:9392` |

Les identifiants d’accès sont stockés localement sur la machine de déploiement dans le fichier :

```bash
/opt/soc/credentials.txt
```

---

## 🔗 Intégrations prévues

Le SOC repose sur les intégrations suivantes :

```text
Agents Wazuh Windows ─────────► Wazuh
Suricata ─────────► Tenzir ─────────► Wazuh
OpenVAS/Greenbone ────────────► Wazuh

Wazuh ─────────────► TheHive
Wazuh ─────────────► Shuffle
TheHive ◄──────────► Cortex
MISP ──────────────► TheHive
```

Les intégrations reposent sur des scripts Python, des webhooks, des API REST et des services systemd. Les clés API doivent être validées ou créées depuis les interfaces des outils concernés.

---

## 🏗️ Architecture logique

```text
┌─────────────────────────────────────────────────────┐
│ Couche 1 — Sources                                  │
│ Serveur DC/DNS | Serveur File/Odoo | Kali Linux     │
└──────────────────────┬──────────────────────────────┘
                       │ Trafic réseau
                       ▼
┌─────────────────────────────────────────────────────┐
│ Couche 2 — Détection & Collecte                     │
│ Suricata ─────────► Tenzir                          │
│ OpenVAS/Greenbone ───────────────► Wazuh            │
└──────────────────────┬──────────────────────────────┘
                       │ Événements normalisés
                       ▼
┌─────────────────────────────────────────────────────┐
│ Couche 3 — SIEM / XDR                               │
│ Wazuh Manager + Wazuh Indexer + Dashboard           │
└──────────────────────┬──────────────────────────────┘
                       │ Alertes corrélées
                       ▼
┌─────────────────────────────────────────────────────┐
│ Couche 4 — Outils SOC                               │
│ TheHive | Cortex | MISP | Shuffle                   │
└─────────────────────────────────────────────────────┘
```

---

## 🛡️ Conformité normative

Le SOC est aligné avec plusieurs référentiels de cybersécurité :

| Référentiel         | Couverture                                                                     |
| ------------------- | ------------------------------------------------------------------------------ |
| **NIST CSF**        | Identify, Protect, Detect, Respond, Recover                                    |
| **MITRE ATT&CK**    | Classification des alertes selon les tactiques et techniques                   |
| **ISO 27001**       | Journalisation, surveillance, gestion des vulnérabilités et incidents          |
| **CIS Controls v8** | Inventaire, surveillance réseau, gestion des journaux et réponse aux incidents |
| **EBIOS RM**        | Analyse des risques et validation de scénarios opérationnels                   |

---

## 🧪 Tests de validation

Les tests réalisés depuis Kali Linux permettent de valider la chaîne de détection :

```bash
# Reconnaissance réseau — MITRE T1046
nmap -sV -sC -O -p- 192.168.152.131

# Brute force SMB — MITRE T1110
hydra -l administrator -P /usr/share/wordlists/rockyou.txt -t 1 smb://192.168.152.131

# Énumération Active Directory — MITRE T1087
enum4linux -a 192.168.152.131
```

Les résultats sont analysés dans Wazuh, Suricata, TheHive, Cortex, MISP et Shuffle afin de vérifier la détection, la corrélation, l’enrichissement et la réponse aux incidents.

---

## 📊 Résultats

Les résultats chiffrés, les captures d’écran et les preuves de fonctionnement sont documentés dans le rapport de projet, notamment :

* agents Windows actifs dans Wazuh ;
* alertes Suricata transmises à Wazuh via Tenzir ;
* alertes Wazuh créées dans TheHive ;
* enrichissement des observables via Cortex ;
* feeds MISP activés ;
* workflows Shuffle exécutés ;
* scans Greenbone/OpenVAS réalisés sur les serveurs Windows.

---

## 📁 Structure du dépôt

```text
SOC_Lionel_EDV/
├── deploy_soc.sh
├── README.md
└── docs/
    ├── architecture.md
    └── tests.md
```

---

## 👤 Auteur

**NADZIGA Franck Lionel Elvis Kiswendsida**
Ingénieur de Conception — Génie des Systèmes Numériques
ISGE-BF | Année universitaire 2025–2026

---

## 📄 Licence

Ce projet est distribué sous licence MIT.

---

<div align="center">

*"Un SOC n’est plus un luxe — c’est une nécessité."*

</div>
