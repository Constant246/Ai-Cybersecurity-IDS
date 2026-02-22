import joblib
import pandas as pd
import numpy as np


def run_elite_simulation():
    # 1. Chargement des composants de l'IA
    try:
        model = joblib.load('models/elite_attack_detector.pkl')
        preprocessor = joblib.load('models/preprocessor.pkl')
        selected_features = joblib.load('models/selected_features.pkl')
        print("✅ Modèle et Pré-processeur chargés avec succès.\n")
    except FileNotFoundError:
        print("❌ Erreur : Fichiers .pkl introuvables dans le dossier 'models/'.")
        return

    THRESHOLD = 0.10  # notre réglage optimal à (10%)

    # 2. Définition des noms de colonnes (les 41 entrées)
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

    # 3. Préparation des données brutes (Scénario Normal)
    normal_raw = {
        'duration': 0, 'protocol_type': 'tcp', 'service': 'http', 'flag': 'SF',
        'src_bytes': 250, 'dst_bytes': 3500, 'land': 0, 'wrong_fragment': 0, 'urgent': 0,
        'hot': 0, 'num_failed_logins': 0, 'logged_in': 1, 'num_compromised': 0,
        'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0,
        'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0,
        'is_guest_login': 0, 'count': 1, 'srv_count': 1, 'serror_rate': 0.0,
        'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0,
        'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0,
        'dst_host_count': 1, 'dst_host_srv_count': 255, 'dst_host_same_srv_rate': 1.0,
        'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 0.05,
        'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0,
        'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0
    }

    # 4. Traitement des données par l'IA
    # Création du DataFrame avec l'ordre exact des colonnes
    df_raw = pd.DataFrame([normal_raw], columns=FEATURE_NAMES)

    # Transformation (Scaling + OneHotEncoding)
    X_transformed = preprocessor.transform(df_raw)

    # Récupération des noms des colonnes générées (122 au total)
    cat_cols = list(preprocessor.named_transformers_['cat'].get_feature_names_out())
    num_cols = list(preprocessor.named_transformers_['num'].get_feature_names_out())
    all_gen_cols = cat_cols + num_cols

    df_transformed = pd.DataFrame(X_transformed, columns=all_gen_cols)

    # Sélection des 20 caractéristiques Importants
    X_final = df_transformed[selected_features]

    # 5. Prédiction finale
    proba = model.predict_proba(X_final)[0, 1]
    verdict = "🚨 ALERTE : ATTAQUE !" if proba >= THRESHOLD else "✅ TRAFIC NORMAL"

    print(f"--- RÉSULTAT DE LA SIMULATION ---")
    print(f"Probabilité d'attaque : {proba * 100:.4f}%")
    print(f"Verdict final : {verdict}")


if __name__ == "__main__":
    run_elite_simulation()

