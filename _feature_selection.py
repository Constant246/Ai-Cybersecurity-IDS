import pandas as pd
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from _preprocessing import run_preprocessing


def perform_feature_selection():
    # 1. Charger les données traitées
    TRAIN_FILE = 'data/KDDTrain+.txt'
    TEST_FILE = 'data/KDDTest+.txt'
    x_train, x_test, y_train, y_test, preprocessor = run_preprocessing(TRAIN_FILE, TEST_FILE)


    # 2. Charger le modèle XGBoost qu'on a entrainé
    model = joblib.load('models/attack_detector_model.pkl')

    # 3. Récupérer l'importance des caractéristiques
    # On récupère les noms des colonnes après transformations
    cat_features = preprocessor.named_transformers_['cat'].get_feature_names_out()
    num_features = preprocessor.named_transformers_['num'].get_feature_names_out()
    all_features = list(cat_features) + list(num_features)

    importances = model.feature_importances_
    feature_imp_df = pd.DataFrame({'feature':all_features, 'importance':importances})
    feature_imp_df = feature_imp_df.sort_values(by=['importance'], ascending=False)

    # 4. Afficher le top 20 des caractéristiques
    print("\n--- TOP 20 des caractéristiques les plus importants")
    print(feature_imp_df.head(20))

    # 5. Visualisation
    plt.figure(figsize=(10, 8))
    sns.barplot(x='importance', y='feature', data=feature_imp_df.head(20))
    plt.title("Top 20 Features - XGBoost importance")
    plt.tight_layout()
    plt.show()

    return feature_imp_df

if __name__ == "__main__":
    perform_feature_selection()


