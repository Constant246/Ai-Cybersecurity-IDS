# ----------------------------------------------------------------------
# Fichier : preprocessing.py
# Objectif : Pré-traitement complet du dataset NSL-KDD pour la classification binaire.
# ----------------------------------------------------------------------


import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder
from imblearn.over_sampling import SMOTE
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline

fichier_entrain = "KDDTrain+.txt"
fichier_test = "KDDTest+.txt"

#--- Définition des constantes ---#

# Liste des 41 caractéristiques
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
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
    'label', 'difficulty' # Le fichier brut KDDTrain+.txt a 43 colonnes,
                          # dont 'label' et 'difficulty' (colonne 43, souvent ignorée).
]

# Colonnes catégorielles à encoder
CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]

# --- 2. Fonctions de Chargement et Étiquetage Binaire ---

def load_data(file_path, features_name):
    """Charge le dataset et applique les noms de colonnes."""
    # Le fichier n'a pas d'en-tête, on les fournit
    df = pd.read_csv(file_path, names=features_name, index_col=False)
    return df

def create_binary_target(df):
    """Crée la colonne cible binaire (0: Normal, 1: Attaque)."""
    # Si le label est 'normal', c'est 0, sinon c'est 1 (Attaque)
    df['target'] = df['label'].apply(lambda x: 0 if x == 'normal' else 1)

    # Séparation des features (X) de la cible (Y)
    X = df.drop(['label', 'difficulty', 'target'], axis=1)
    Y = df['target']

    print(f"Distribution des classes: \n{Y.value_counts()}")
    return X, Y

# --- 3. Création du pipeline de Transformation (Meilleure Pratique)

def create_preprocessor(x_train):
    """
    Crée un ColumnTransformer pour appliquer les transformations appropriées
    aux colonne catégorielles et numériques.
    :param X_train:
    :return:
    """

    # Identifier les colonnes numériques (celles qui ne sont pas catégorielles)
    # Note: Toutes les 41 features sont considérées ici. Les colonnes
    # binaires originales sont laissées dans le NumericTransformer .

    numeric_features = x_train.columns.drop(CATEGORICAL_FEATURES).tolist()

    # On définit les transformations

    preprocessor = ColumnTransformer(
        transformers=[
            # 1. Encodage One-Hot pour les variables catégorielles
            ('cat',
             # sparse_output = False pour obtenir une matrice dense
             OneHotEncoder(handle_unknown= 'ignore', sparse_output= False),
             CATEGORICAL_FEATURES),

            # 2. Mise à l'échelle (StandardScaler) pour toutes les autres colonnes(numériques +
            # binaires d'origine
            ('num',
             StandardScaler(),
             numeric_features)

        ],
        # Ne rien faire avec les colonnes restantes
        remainder= 'passthrough'
    )
    return preprocessor

# --- 4. Fonction Prinipale d'Exécution ---

def run_preprocessing(train_file, test_file):

    print("--- Démarrage du pré-traitement ---")

    # CHARGEMENT DES DONNEES
    train_df = load_data(train_file, FEATURE_NAMES)
    test_df = load_data(test_file, FEATURE_NAMES)

    # CREATION DE LA CIBLE BINAIRE (Y)
    x_train, y_train = create_binary_target(train_df)
    x_test, y_test = create_binary_target(test_df)

    print(f"\nShape initial Train (X): {x_train.shape}")
    print(f"Shape initial Test (X): {x_test.shape}")

    # CREATION ET ENTRAINEMENT DU PRE-PROCESSEUR
    preprocessor = create_preprocessor(x_train)
    print("\nEntrainement du pré-preprocesseur (fitting) sur les données d'entrainement")

    # On entraine le pré-processeur UNIQUEMENT sur X_train pour capturer les statistiques (moyenne/std, catégorie)
    preprocessor.fit(x_train)

    # APPLICATION DE LA TRANSFORMATION
    print("Transformation des ensembles de Train et Test...")

    # On utilise le pré-processeur ENTRAINE pour transformer les deux ensembles.
    x_train_processed = preprocessor.transform(x_train)
    x_test_processed = preprocessor.transform(x_test)

    print(f"Shape final après transformation Train: {x_train_processed.shape}")
    print(f"Shape final après transformation Test: {x_test_processed.shape}")

    # Le nombre de colonne augmente à cause du One-Hot Encoding des 3 colonnes catégorielles.
    print("--- Pré-traitement terminé avec succès ---")

    # Retourner les données pretes pour le ML et le pré-processeur
    return x_train_processed, x_test_processed, y_train, y_test, preprocessor

# --- 5. Bloc d'Exécution ---

if __name__ == "__main__":

    TRAIN_FILE_PATH = 'data/KDDTrain+.txt'
    TEST_FILE_PATH = 'data/KDDTest+.txt'

    # Exécuter le pipeline
    x_train_final, x_test_final, y_train_final, y_test_final, preprocessor_fitted = \
    run_preprocessing(TRAIN_FILE_PATH, TEST_FILE_PATH)

    # Ici, nous pouvons sauvegarder les données et le pré-processeur
    # pour les utiliser dans un autre script d'entrainement

    # Exemple de vérification (nous verrons que la moyenne est proche de 0 et
    # l'écart-type proche de 1
    print("\nVérification de la premère ligne après mise à l'échelle: ")
    print(x_train_final[0, :5])


