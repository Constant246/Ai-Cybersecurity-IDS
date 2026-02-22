# AI-Cybersecurity-ID
Mini PROJET : Système de détection d'intrusion réseau grâce au Machine Learning (XGBoost + NSL-KDD) avec notifications automatiques sur Discord.

# Description

Ce projet est un **prototype académique** de système de détection d'intrusion (IDS) qui combine :

- **Machine Learning** : Modèle XGBoost entraîné sur le dataset NSL-KDD pour classifier le trafic réseau
- **Capture en temps réel** : Analyse des paquets réseau avec Scapy
- **Seuil adaptatif intelligent** : Résolution du biais ICMP présent dans NSL-KDD
- **Génération automatique de solutions** : 15 règles pour générer des contre-mesures actionnables
- **Notifications automatiques** : Intégration n8n → Discord/Slack
- **Dashboard de visualisation** : Interface Streamlit pour le monitoring

## Avertissement

**C'est un Mini Projet développé dans un environnement contrôlé (VirtualBox).**

❌ **NE PAS déployer en production** sans modifications importantes  
❌ **NE PAS utiliser** sur des réseaux non autorisés  
❌ **NE PAS scanner** des systèmes sans autorisation explicite  

✅ Utilisation recommandée : Apprentissage, recherche, démonstration académique

# 📸 Aperçu d'une alerte

Voici à quoi ressemble une alerte de sécurité interceptée et envoyée par notre système :

![Alerte de sécurité](images/test3.png)

## Innovation : Seuil Adaptatif

### Problème Identifié

Le dataset NSL-KDD contient **99% d'attaques ICMP** (smurf, pod), créant un biais important :
- Le modèle prédit **97-99%** pour **TOUT** trafic ICMP
- Un ping normal génère une Fausse alerte (100% faux positifs)

### Solution Implémentée

**Seuil dynamique selon le contexte :**

| Contexte | Paquets | Seuil | Résultat |
|----------|---------|-------|----------|
| ICMP léger (ping normal) | < 10 | 99.5% | ✅ 0% faux positifs |
| ICMP intensif (flood) | ≥ 10 | 85% | ✅ Détection confirmée |
| TCP/UDP (scan, brute force) | Tous | 30% | ✅ Détection standard |

**Impact :**
- **Avant** : 100% de faux positifs sur ping normal générant des alertes
- **Après** : 0% de faux positifs sur ping normal, 100% de détection sur floods

## Technologies

### Machine Learning
- **XGBoost** 2.0.3 : Classification binaire (200 arbres)
- **scikit-learn** 1.3.0 : Prétraitement et feature selection
- **pandas** 2.0.0 : Manipulation de données
- **joblib** 1.3.2 : Sérialisation des modèles

### Réseau & Sécurité
- **Scapy** 2.5.0 : Capture et analyse de paquets réseau
- **SQLite** 3 : Stockage persistant des logs

### Intégration & Visualisation
- **n8n** : Orchestration des workflows
- **Streamlit** 1.28.0 : Dashboard web interactif
- **Plotly** 5.17.0 : Graphiques dynamiques
- **requests** 2.31.0 : Communication avec webhooks

### Environnement de Test
- **VirtualBox** : Réseau isolé Host-Only
- **Kali Linux** : Machine attaquante
- **Windows 10/11** : Machine cible

# Fonctionnalités principales
* **Analyse intelligente** : Utilisation de XGBoost pour classifier le trafic normal ou malveillant.
* **Base de données locale** : Enregistrement sécurisé des logs via SQLite.
* **Automatisation** : Connexion à n8n pour envoyer des alertes (ex: Discord) sans exposer les webhooks.

## Utilisation

### Mode 1 : Détection en Temps Réel

**Lancer le sniffer sur la machine cible (Windows) :**
```bash
# IMPORTANT : Exécuter en tant qu'administrateur
python sniffer_elite_v3_with_solutions.py

### Mode 2 : Dashboard de Visualisation

**Lancer l'interface web Streamlit :**
```bash
streamlit run war_room.py
```

**Accéder au dashboard :**
- Ouvrez http://localhost:8501

**Fonctionnalités du dashboard :**
-  Graphiques en temps réel (protocoles, alertes)
-  Timeline des attaques
-  Top IP malveillantes
-  Table des logs détaillés
-  Filtres par protocole et gravité

### Mode 3 : Analyse Historique

**Consulter les logs SQLite :**
```bash
# Ouvrir la base de données
sqlite3 network_security.db

# Requêtes utiles
sqlite> SELECT * FROM logs ORDER BY timestamp DESC LIMIT 10;
sqlite> SELECT src_ip, COUNT(*) as nb_attaques 
        FROM logs 
        WHERE danger_score >= 0.3 
        GROUP BY src_ip 
        ORDER BY nb_attaques DESC;
sqlite> .quit
```

### Arrêter le Système
```bash
# Arrêter le sniffer
Ctrl + C

# Arrêter n8n (si démarré)
Ctrl + C

# Arrêter Streamlit (si démarré)
Ctrl + C
```

### Exemples de Commandes Générées

**Pour chaque attaque détectée, le système génère :**

✅ **3 actions immédiates** (commandes exécutables)  
✅ **3 étapes d'investigation** (forensics)  
✅ **3 mesures de prévention** (hardening)  
✅ **5 outils recommandés** (iptables, fail2ban, etc.)  
✅ **Indicateur d'escalade** (notifier CERT/CISO)

## Limitations

### Limitations Techniques

1. **Dataset obsolète (1999)**
   - Ne couvre pas les attaques modernes (ransomware, cryptomining, APT)
   - Comportements réseau différents d'aujourd'hui
   - **Solution future :** Migration vers CICIDS2017 ou UNSW-NB15

2. **Analyse paquet par paquet**
   - Le modèle a été entraîné sur des **connexions complètes**
   - Le sniffer analyse des **paquets individuels**
   - Décalage entre entraînement et inférence
   - **Solution future :** Agréger les paquets en sessions avant prédiction

3. **Seuil de détection empirique**
   - Seuil de 30% choisi par expérimentation
   - Non optimisé par courbe ROC
   - **Solution future :** Optimisation par métriques (F1-Score, Precision/Recall)

4. **Scalabilité limitée**
   - Single-threaded Python (~500 paquets/seconde)
   - Inadapté pour réseaux haute vitesse (10+ Gbps)
   - **Solution future :** Multiprocessing, Kafka + Spark

5. **Pas de tests unitaires**
   - Code non couvert par des tests automatisés
   - **Solution future :** Ajout de pytest pour validation continue
