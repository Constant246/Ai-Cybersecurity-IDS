import joblib
import pandas as pd
import numpy as np
from sklearn.metrics import classification_report
from _preprocessing import run_preprocessing

def test_sensitivity():
    # 1. Chargement du modèle et des features sélectionnés
    model = joblib.load('models/elite_attack_detector.pkl')
    top_features = joblib.load('models/selected_features.pkl')


    # 2. Chargement des données de test
    _, x_test, _, y_test, preprocessor = run_preprocessing('data/KDDTrain+.txt', 'data/KDDTest+.txt')

    # Préparation des données comme pour l'entrainement
    all_cols = list(preprocessor.named_transformers_['cat'].get_feature_names_out()) + \
               list(preprocessor.named_transformers_['num'].get_feature_names_out())
    x_test_df = pd.DataFrame(x_test, columns=all_cols)
    x_test_final = x_test_df[top_features]

    # 3. Récupération des PROBABILITES (au lieu des classes)
    probabilities = model.predict_proba(x_test_final)[:, 1] # Probabilité que ce soit une attaque

    # 4. TESTE DE PLUSIEURS SEUILS
    for threshold in [0.5, 0.3, 0.2, 0.1]:
        print(f"\n--- RESULTAT AVEC SEUIL DE SENSIBILITE : {threshold*100}% ---")
        # Si proba > seuil, alors c'est une attaque (1), sinon 0
        y_pred_custom = (probabilities >= threshold).astype(int)
        print(classification_report(y_test, y_pred_custom))


if __name__ == "__main__":
    test_sensitivity()

