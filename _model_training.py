
import os
import joblib
import pandas as pd
from xgboost import XGBClassifier
from sklearn.metrics import classification_report
# On importe la fonction de notre premier script
from _preprocessing import run_preprocessing

def train_elite_model():
    # 1. Définition des chemins et chargement des fichiers
    TRAIN_FILE = 'data/KDDTrain+.txt'
    TEST_FILE = 'data/KDDTest+.txt'

    print("Etape 1 : Lancement du pré-traitement...")
    x_train, x_test, y_train, y_test, preprocessor = run_preprocessing(TRAIN_FILE, TEST_FILE)

    # 2. Récupération des noms de colonnes pour le filtrage
    cat_cols = list(preprocessor.named_transformers_['cat'].get_feature_names_out())
    num_cols = list(preprocessor.named_transformers_['num'].get_feature_names_out())
    all_features = cat_cols + num_cols

    # Création de DataFrames pour manipuler les colonnes par nom
    x_train_df = pd.DataFrame(x_train, columns=all_features)
    x_test_df = pd.DataFrame(x_test, columns=all_features)

    # 3. Sélection des "Top Features"
    # Nous prenons les 20 plus importantes pour maximiser la clarté du signal
    top_features = ['service_ecr_i', 'src_bytes', 'service_http', 'wrong_fragment', 'hot',
        'logged_in', 'dst_host_same_srv_rate', 'dst_bytes', 'service_ftp_data',
        'dst_host_same_src_port_rate', 'count', 'protocol_type_tcp', 'service_smtp',
        'service_private', 'srv_count', 'dst_host_srv_diff_host_rate', 'flag_S1',
        'dst_host_srv_count', 'duration', 'protocol_type_icmp'
    ]

    x_train_final = x_train_df[top_features]
    x_test_final = x_test_df[top_features]

    # 4. Entrainement avec Hyper-paramètres ajustés
    # On augmente un peu la profondeur et les arbres pour compenser le moins de colonnes
    print("f\n--- Phase 2 : Entrainement du modèle Elite( {len(top_features)} features) ---")
    model = XGBClassifier(
        n_estimators=200,
        learning_rate=0.05,
        max_depth=8,
        random_state=42,
        eval_metric='logloss',
    )

    model.fit(x_train_final, y_train)

    # 5. Evaluation finale
    print("\n--- Phase 3 : Evaluation finale ---")
    y_pred = model.predict(x_test_final)
    print(classification_report(y_test, y_pred))

    # Sauvegarde
    if not os.path.exists('models'): os.makedirs('models')
    joblib.dump(model, 'models/elite_attack_detector.pkl')
    # Très important : On sauvegarde aussi la liste des features pour le futur script de test
    joblib.dump(top_features, 'models/selected_features.pkl')
    print("\n Modèle Elite et liste des caractéristiques sauvegardés !")

    # Sauvegarde du script d'entrainement
    joblib.dump(preprocessor, 'models/preprocessor.pkl')
    print("Pré-processeur sauvegarder !")


if __name__ == "__main__":
    train_elite_model()


