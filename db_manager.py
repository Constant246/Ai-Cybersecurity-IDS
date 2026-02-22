# Pour travailler avec les bases de données SQLite(stockage de nos logs)
import sqlite3
# Pour manipuler les données sous forme de tableau (DataFrames)
import pandas as pd

# Nom du fichier de base de données
DB_NAME = "network_security.db"

"""Cette fonction Crée la table logs si elle n'existe pas déjà."""
def init_db():
    # Création de la base de données
    conn = sqlite3.connect(DB_NAME)
    # Pointeur pour parler à la base de données
    c = conn.cursor()
    # Exécution d'une commande SQL
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            length INTEGER,
            danger_score REAL
        )
    ''')
    # Pour enrégistrer définitivement les modifications dans la base de données
    conn.commit()
    # Fermer les connexions après usage
    conn.close()

# ICI : J'ai renommé la fonction en 'insert_packet' pour que le sniffer la reconnaisse !
# Le role de cette fontcion : Ajouter une nouvelle ligne dans la table logs
def insert_packet(timestamp, src_ip, dst_ip, protocol, length, danger_score):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        INSERT INTO logs (timestamp, src_ip, dst_ip, protocol, length, danger_score)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (timestamp, src_ip, dst_ip, protocol, length, danger_score))
    conn.commit()
    conn.close()

def get_recent_logs(limit=1000):
    ''' Récupère les logs les plus récents depuis la base de données '''
    try:
        conn = sqlite3.connect(DB_NAME)
        query = f'''
            SELECT timestamp, src_ip, dst_ip, protocol, length, danger_score 
            FROM logs 
            ORDER BY ID DESC LIMIT {limit}
        '''
        # pd.read_sql_query() : Fonction pandas qui exécute le requète SQL
        df = pd.read_sql_query(query, conn)
        conn.close()
        # df : DataFrame qui contient tous les logs
        return df
    except Exception as e:
        print(f"Erreur lors de la récupération des logs : {e}")
        # Retourner un DataFrame vide en cas d'erreur
        return pd.DataFrame(columns=['timestamp', 'src_ip', 'dst_ip', 'protocol', 'length', 'danger_score'])

