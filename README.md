# 🛡️ SOC Endeavour Mining — Déploiement automatisé

<div align="center">

![SOC](https://img.shields.io/badge/SOC-Endeavour%20Mining-gold?style=for-the-badge&logo=shield&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Wazuh](https://img.shields.io/badge/Wazuh-4.9.0-00bcd4?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**Conception et implémentation d'un Security Operations Center (SOC)**  
*Projet de fin de cycle — ISGE-BF | Endeavour Mining | 2025–2026*

**NADZIGA Franck Lionel Elvis Kiswendsida**

</div>

---

## 📋 Description

Ce dépôt contient le script de déploiement automatisé complet du SOC Endeavour Mining.  
**Un seul script bash installe, déploie et intègre l'ensemble de la stack SOC** sur une VM Ubuntu 24.04 LTS — sans intervention manuelle.

### Ce que fait le script

```
Ubuntu 24.04 LTS (vierge)
        │
        ▼
sudo ./deploy_soc.sh
        │
        ▼
┌─────────────────────────────────────────┐
│          SOC OPÉRATIONNEL               │
│                                         │
│  Wazuh SIEM/XDR    ──► TheHive          │
│  Suricata IDS/IPS  ──► Shuffle SOAR     │
│  OpenVAS Scanner   ──► MISP TI          │
│  Tenzir Pipeline   ──► Cortex Analyzer  │
└─────────────────────────────────────────┘
```

---

## 🧰 Stack déployée

| Outil | Version | Rôle |
|-------|---------|------|
| **Wazuh** | 4.9.0 | SIEM / XDR — Cœur du SOC |
| **TheHive** | 4.1.24 | Case Management |
| **Cortex** | 3.1.8 | Analyse observables (VirusTotal, AbuseIPDB) |
| **MISP** | Latest | Threat Intelligence Platform |
| **Shuffle** | Latest | SOAR — Automatisation des réponses |
| **Suricata** | Latest | IDS/IPS réseau |
| **OpenVAS/Greenbone** | Latest | Scanner de vulnérabilités |
| **Tenzir** | Latest | Pipeline Suricata → Wazuh |

---

## ⚡ Installation en une commande

### Prérequis

- Ubuntu 24.04 LTS (serveur ou VM)
- Minimum **8 Go RAM**, 4 vCPUs, 50 Go disque
- Accès Internet
- Droits root (sudo)

### Déploiement

```bash
# 1. Cloner le dépôt
git clone https://github.com/Liocode2003/SOC_Lionel_EDV.git
cd SOC_Lionel_EDV

# 2. Rendre le script exécutable
chmod +x deploy_soc.sh

# 3. Lancer le déploiement (en root)
sudo ./deploy_soc.sh
```

> ⏱️ **Durée estimée : 15 à 30 minutes** selon la connexion Internet

---

## 🌐 Accès aux interfaces

Une fois le déploiement terminé, les interfaces sont accessibles depuis :

| Interface | URL | Identifiants |
|-----------|-----|-------------|
| **Wazuh Dashboard** | `https://<IP>:443` | `admin` / `MyS3cr37P450r.*-` |
| **TheHive** | `http://<IP>:9000` | `soc@soc.local` / `SOC@Endeavour2025!` |
| **Cortex** | `http://<IP>:9001` | `analyst@soc.local` / `SOC@Endeavour2025!` |
| **MISP** | `https://<IP>:8443` | `admin@admin.test` / `SOC@Endeavour2025!` |
| **Shuffle** | `http://<IP>:3001` | `admin@soc.local` / `SOC@Endeavour2025!` |
| **OpenVAS** | `https://<IP>:9392` | `admin` / `Admin@GVM2025` |

---

## 🔗 Intégrations automatiques

Le script configure **6 intégrations** entre les outils :

```
Wazuh ──────────────► TheHive       (alert-forwarder.py, toutes les minutes)
Wazuh ──────────────► Shuffle       (webhook, alertes niveau ≥ 7)
Wazuh ──────────────► MISP          (custom-misp, alertes niveau ≥ 10)
TheHive ────────────► Cortex        (analyse observables automatique)
MISP ───────────────► TheHive       (sync IOCs, toutes les 5 minutes)
Suricata ───────────► Wazuh         (via Tenzir pipeline, temps réel)
```

---

## 📁 Structure du dépôt

```
SOC_Lionel_EDV/
├── deploy_soc.sh          # Script de déploiement principal
├── README.md              # Ce fichier
└── docs/
    ├── architecture.md    # Description de l'architecture
    └── tests.md           # Procédures de test et validation
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│            Couche 1 — Sources                        │
│   Kali Linux  |  WinServer DC01  |  WinServer FS    │
└──────────────────────┬──────────────────────────────┘
                       │ logs agents / trafic réseau
┌──────────────────────▼──────────────────────────────┐
│            Couche 2 — Détection réseau               │
│        Suricata + Tenzir  |  OpenVAS                 │
└──────────────────────┬──────────────────────────────┘
                       │ alertes normalisées
┌──────────────────────▼──────────────────────────────┐
│            Couche 3 — SIEM                           │
│              Wazuh v4.9.0 (SIEM/XDR)                │
└──┬──────────┬──────────┬──────────┬─────────────────┘
   │          │          │          │
   ▼          ▼          ▼          ▼
TheHive    Shuffle     MISP    OpenSearch ML
Cortex     (SOAR)     (TI)    (Anomalies)
```

---

## 🛡️ Conformité normative

| Norme | Couverture |
|-------|-----------|
| **NIST CSF** | 5/5 fonctions (Identify, Protect, Detect, Respond, Recover) |
| **MITRE ATT&CK** | 7 tactiques mappées |
| **ISO 27001** | Contrôles A.12, A.13, A.16, A.17 |
| **CIS Controls v8** | 9 contrôles implémentés |
| **EBIOS RM** | 5 étapes couvertes |

---

## 📊 Résultats obtenus

| Métrique | Valeur |
|----------|--------|
| Alertes Wazuh générées | **4 303+** |
| Cases TheHive créés | **3 151+** |
| Events MISP | **185+** (10 feeds actifs) |
| Exécutions Shuffle | **100+** |
| Analyzers Cortex | **3** (VirusTotal x2 + AbuseIPDB) |
| Économie vs solutions commerciales | **~50 000 €/an** |

---

## 🧪 Tests de validation

Les tests suivants ont été réalisés depuis Kali Linux :

```bash
# Test 1 — Reconnaissance réseau (MITRE T1046)
nmap -sV -sC -O -p- 192.168.152.131

# Test 2 — Brute Force SMB (MITRE T1110)
hydra -l administrator -P /usr/share/wordlists/rockyou.txt -t 1 smb://192.168.152.131

# Test 3 — Énumération Active Directory (MITRE T1087)
enum4linux -a 192.168.152.131

# Test 4 — Scan vulnérabilités (OpenVAS)
# Via interface web : https://<IP>:9392
```

**Résultat : 4/4 attaques détectées ✅**

---

## 👤 Auteur

**NADZIGA Franck Lionel Elvis Kiswendsida**  
Ingénieur de Conception — Génie des Systèmes Numériques  
ISGE-BF | Année universitaire 2025–2026

- Professeur de suivi : **S/LTN GNAKINI Alane Chamir**
- Maître de stage : **M. TRAORE Alpha**
- Entreprise : **Endeavour Mining**

---

## 📄 Licence

Ce projet est sous licence MIT — voir le fichier [LICENSE](LICENSE) pour plus de détails.

---

<div align="center">

*"Un SOC n'est plus un luxe — c'est une nécessité."*

⭐ **N'oubliez pas de star le repo si ce projet vous a été utile !**

</div>
