# 🛡️ GUIDE DE DÉPANNAGE - Détecteur d'Attaques Réseau

## 📋 Problèmes Identifiés et Solutions

### ❌ **Problème 1 : Features Incomplètes**

**Avant :**
- Seulement 6-7 features sur 41 étaient calculées
- 34 valeurs à zéro → prédictions faussées

**Solution :**
- ✅ Calcul complet des 41 features
- ✅ Statistiques temporelles (count, srv_count, rates)
- ✅ Analyse par connexion et par host

---

### ❌ **Problème 2 : Mapping des Services**

**Avant :**
```python
service = "other"  # Pour la plupart des ports
```

**Après :**
```python
service_map = {
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    80: 'http',
    443: 'https',
    # ... 20+ services mappés
}
```

---

### ❌ **Problème 3 : Flags TCP Mal Interprétés**

**Avant :**
- Un seul flag "S0" détecté

**Après :**
- S0 : SYN sans réponse (scan)
- S1 : SYN-ACK (connexion)
- REJ : RST (rejet)
- SF : Connexion normale

---

## 🧪 TESTS RECOMMANDÉS

### **Test 1 : Scan SYN Simple**
```bash
# Sur Kali Linux
sudo nmap -sS 192.168.56.1

# Résultat attendu :
# 🚨 Plusieurs alertes avec :
# - FLAG: S0
# - SYN: > 5
# - Danger: > 0.3
```

### **Test 2 : Scan de Ports Complet**
```bash
# Sur Kali Linux
sudo nmap -p 1-1000 192.168.56.1

# Résultat attendu :
# 🚨 Nombreuses alertes
# - COUNT: > 10
# - Service variés détectés
```

### **Test 3 : Scan OS Detection**
```bash
# Sur Kali Linux  
sudo nmap -O 192.168.56.1

# Résultat attendu :
# 🚨 Alerte avec proto ICMP
# - Danger élevé
```

### **Test 4 : Trafic Normal (pour comparaison)**
```bash
# Sur Kali Linux
ping 192.168.56.1 -c 5

# Résultat attendu :
# ✅ Pas d'alerte (ou danger < 0.3)
# - Service: ecr_i
# - FLAG: SF
```

---

## 🔧 AJUSTEMENT DU SEUIL

Si vous avez trop ou pas assez d'alertes :

```python
# Dans sniffer_elite_v2.py, ligne 26
THRESHOLD = 0.3  # Ajustez cette valeur

# Recommandations :
# - 0.1 : Très sensible (beaucoup d'alertes)
# - 0.3 : Équilibré (recommandé pour nmap)
# - 0.5 : Conservateur (peu d'alertes)
```

Vous pouvez aussi utiliser votre script `main_test.py` pour tester différents seuils sur le dataset de test.

---

## 📊 VÉRIFICATION DES FEATURES

Pour vérifier que toutes les features sont bien calculées, ajoutez ce code après la ligne 227 du nouveau sniffer :

```python
# Debug : afficher les features calculées
print("\n=== DEBUG FEATURES ===")
for key, value in raw_data.items():
    if value != 0:  # Afficher seulement les valeurs non-nulles
        print(f"{key}: {value}")
print("=" * 25 + "\n")
```

---

## 🎯 INDICATEURS DE SCAN NMAP

Le nouveau sniffer détecte automatiquement ces patterns :

1. **SYN Flood** : `syn_count > 5` en 2 secondes
2. **Port Scanning** : `count > 10` connexions rapides
3. **Connexions Rejetées** : `flag = S0` (pas de réponse)
4. **Services Variés** : `diff_srv_rate` élevé

---

## ⚙️ COMMANDES DE DÉPANNAGE

### Vérifier l'interface réseau :
```bash
python check_interface.py
```

### Tester le modèle isolément :
```bash
python teste_script.py
```

### Ajuster la sensibilité :
```bash
python main_test.py
```

### Visualiser les logs :
```bash
streamlit run war_room.py
```

---

## 📝 CHECKLIST DE DÉMARRAGE

Avant de lancer un test :

- [ ] La VM Kali est bien sur le réseau Host-Only (192.168.56.x)
- [ ] L'interface 192.168.56.1 est détectée par check_interface.py
- [ ] Les fichiers .pkl sont dans le dossier `models/`
- [ ] La base de données network_security.db existe
- [ ] Le seuil THRESHOLD est configuré (recommandé : 0.3)

---

## 🐛 PROBLÈMES COURANTS

### "Aucune alerte détectée"
→ Vérifiez que le trafic passe bien par l'interface 192.168.56.1
→ Baissez le seuil à 0.1 temporairement
→ Ajoutez le code debug pour voir les features calculées

### "Trop d'alertes"
→ Augmentez le seuil à 0.5
→ Vérifiez qu'il n'y a pas d'autre trafic sur le réseau

### "Erreur de prédiction"
→ Vérifiez que les 3 fichiers .pkl sont bien présents
→ Relancez l'entraînement du modèle si nécessaire

---

## 📚 RESSOURCES

- Dataset NSL-KDD : https://www.unb.ca/cic/datasets/nsl.html
- Documentation nmap : https://nmap.org/book/man.html
- Scapy : https://scapy.readthedocs.io/

---

**Bon courage avec votre projet ! 🚀**
