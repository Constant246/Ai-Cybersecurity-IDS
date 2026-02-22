"""
Script de Diagnostic - Détecteur d'Attaques Réseau
Vérifie que tous les composants sont correctement configurés
"""

import os
import sys
import joblib
from scapy.all import conf, get_if_list

def print_section(title):
    """Affiche un titre de section"""
    print("\n" + "="*60)
    print(f"  {title}")
    print("="*60)

def check_files():
    """Vérifie la présence des fichiers nécessaires"""
    print_section("1. VÉRIFICATION DES FICHIERS")
    
    files_to_check = {
        'Modèle IA': 'models/elite_attack_detector.pkl',
        'Préprocesseur': 'models/preprocessor.pkl',
        'Features sélectionnées': 'models/selected_features.pkl',
        'Base de données': 'network_security.db',
        'Dataset Train': 'data/KDDTrain+.txt',
        'Dataset Test': 'data/KDDTest+.txt'
    }
    
    all_ok = True
    for name, path in files_to_check.items():
        exists = os.path.exists(path)
        status = "✅" if exists else "❌"
        print(f"{status} {name}: {path}")
        if not exists:
            all_ok = False
    
    return all_ok

def check_models():
    """Vérifie que les modèles se chargent correctement"""
    print_section("2. VÉRIFICATION DES MODÈLES")
    
    try:
        model = joblib.load('models/elite_attack_detector.pkl')
        print(f"✅ Modèle chargé : {type(model).__name__}")
        print(f"   - Nombre d'arbres : {model.n_estimators}")
        
        preprocessor = joblib.load('models/preprocessor.pkl')
        print(f"✅ Préprocesseur chargé")
        
        selected_features = joblib.load('models/selected_features.pkl')
        print(f"✅ Features sélectionnées : {len(selected_features)} features")
        print(f"   Top 5 : {selected_features[:5]}")
        
        return True
    except Exception as e:
        print(f"❌ Erreur de chargement : {e}")
        return False

def check_network():
    """Vérifie la configuration réseau"""
    print_section("3. VÉRIFICATION RÉSEAU")
    
    print("\n Interfaces réseau disponibles :")
    target_found = False
    
    for iface in conf.ifaces.values():
        try:
            ip = iface.ip if hasattr(iface, 'ip') else "N/A"
            is_target = "👉 CIBLE" if ip == "192.168.56.1" else ""
            print(f"   - {iface.name}: {ip} {is_target}")
            if ip == "192.168.56.1":
                target_found = True
        except:
            pass
    
    if target_found:
        print("\n✅ Interface Host-Only (192.168.56.1) TROUVÉE")
    else:
        print("\n❌ Interface Host-Only (192.168.56.1) NON TROUVÉE")
        print("   ⚠️  Vérifiez la configuration de VirtualBox")
    
    return target_found

def check_dependencies():
    """Vérifie les dépendances Python"""
    print_section("4. VÉRIFICATION DES DÉPENDANCES")
    
    dependencies = {
        'scapy': 'Capture de paquets',
        'sklearn': 'Machine Learning',
        'xgboost': 'Modèle de détection',
        'pandas': 'Manipulation de données',
        'joblib': 'Sauvegarde de modèles',
        'sqlite3': 'Base de données',
        'requests': 'Alertes HTTP'
    }
    
    all_ok = True
    for module, description in dependencies.items():
        try:
            __import__(module)
            print(f"✅ {module:15} : {description}")
        except ImportError:
            print(f"❌ {module:15} : {description} - NON INSTALLÉ")
            all_ok = False
    
    return all_ok

def check_database():
    """Vérifie la base de données"""
    print_section("5. VÉRIFICATION BASE DE DONNÉES")
    
    try:
        import sqlite3
        conn = sqlite3.connect('network_security.db')
        cursor = conn.cursor()
        
        # Vérifier la table logs
        cursor.execute("SELECT COUNT(*) FROM logs")
        count = cursor.fetchone()[0]
        print(f"✅ Base de données accessible")
        print(f"   - Nombre de logs : {count}")
        
        # Récupérer le dernier log
        if count > 0:
            cursor.execute("SELECT timestamp, src_ip, danger_score FROM logs ORDER BY id DESC LIMIT 1")
            last_log = cursor.fetchone()
            print(f"   - Dernier log : {last_log[0]} | IP: {last_log[1]} | Danger: {last_log[2]:.4f}")
        
        conn.close()
        return True
    except Exception as e:
        print(f"❌ Erreur base de données : {e}")
        return False

def test_prediction():
    """Test rapide de prédiction"""
    print_section("6. TEST DE PRÉDICTION")
    
    try:
        import pandas as pd
        
        model = joblib.load('models/elite_attack_detector.pkl')
        preprocessor = joblib.load('models/preprocessor.pkl')
        selected_features = joblib.load('models/selected_features.pkl')
        
        # Simulation d'un paquet normal
        FEATURE_NAMES = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
            'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
            'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
            'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login',
            'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
            'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
            'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
            'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
            'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
        ]
        
        # Trafic normal
        normal_data = {col: 0 for col in FEATURE_NAMES}
        normal_data.update({
            'protocol_type': 'tcp',
            'service': 'http',
            'flag': 'SF',
            'src_bytes': 250,
            'logged_in': 1,
            'count': 1,
            'srv_count': 1,
            'same_srv_rate': 1.0
        })
        
        df = pd.DataFrame([normal_data])
        X_transformed = preprocessor.transform(df)
        
        cat_cols = list(preprocessor.named_transformers_['cat'].get_feature_names_out())
        num_cols = list(preprocessor.named_transformers_['num'].get_feature_names_out())
        df_full = pd.DataFrame(X_transformed, columns=cat_cols + num_cols)
        X_final = df_full[selected_features]
        
        prob_normal = model.predict_proba(X_final)[0, 1]
        print(f"✅ Test trafic NORMAL : Danger = {prob_normal:.4f} ({prob_normal*100:.2f}%)")
        
        # Simulation scan nmap (SYN scan)
        scan_data = {col: 0 for col in FEATURE_NAMES}
        scan_data.update({
            'protocol_type': 'tcp',
            'service': 'private',
            'flag': 'S0',
            'src_bytes': 60,
            'count': 50,
            'srv_count': 10,
            'serror_rate': 0.8,
            'srv_serror_rate': 0.8,
            'same_srv_rate': 0.2,
            'diff_srv_rate': 0.8
        })
        
        df_scan = pd.DataFrame([scan_data])
        X_scan_transformed = preprocessor.transform(df_scan)
        df_scan_full = pd.DataFrame(X_scan_transformed, columns=cat_cols + num_cols)
        X_scan_final = df_scan_full[selected_features]
        
        prob_scan = model.predict_proba(X_scan_final)[0, 1]
        print(f"✅ Test SCAN NMAP   : Danger = {prob_scan:.4f} ({prob_scan*100:.2f}%)")
        
        if prob_scan > prob_normal:
            print("\n Le modèle distingue bien trafic normal vs scan !")
        else:
            print("\n⚠️  Attention : le modèle ne discrimine pas bien")
        
        return True
        
    except Exception as e:
        print(f"❌ Erreur de test : {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Exécute tous les tests de diagnostic"""
    print("\n")
    print("╔" + "="*58 + "╗")
    print("║" + " "*10 + "DIAGNOSTIC SYSTÈME - IDS RÉSEAU" + " "*17 + "║")
    print("╚" + "="*58 + "╝")
    
    results = {
        'Fichiers': check_files(),
        'Modèles': check_models(),
        'Réseau': check_network(),
        'Dépendances': check_dependencies(),
        'Base de données': check_database(),
        'Prédiction': test_prediction()
    }
    
    print_section("RÉSUMÉ")
    
    all_ok = True
    for name, status in results.items():
        icon = "✅" if status else "❌"
        print(f"{icon} {name}")
        if not status:
            all_ok = False
    
    print("\n" + "="*60)
    if all_ok:
        print(" TOUS LES TESTS SONT PASSÉS !")
    else:
        print("⚠️  CERTAINS TESTS ONT ÉCHOUÉ")
        print(" Consultez le GUIDE_DEPANNAGE.md pour plus d'aide")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()

