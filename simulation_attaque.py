import sqlite3
import time
import random


from db_manager import DB_NAME

# Configuration
DB_NAME = "network_security.db"

def simulation_attaque():
    print(" LANCEMENT DE LA SIMULATION D'ATTAQUE DDOS...")
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    protocols = ["TCP", "UDP"]
    ips_suspectes = ["192.168.1.50", "10.0.0.666", "172.16.0.99"]

    # On génère 100 paquets très rapidement
    for i in range(100):
        # Création de fausses données alarmantes
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        src_ip = random.choice(ips_suspectes)
        dst_ip = "192.168.1.1"
        protocol = random.choice(protocols)
        length = random.randint(1000, 5000) # Gros paquets
        danger_score = random.uniform(0.8, 1.0) # Danger

        # Insertion dans la base
        c.execute(''' 
            INSERT INTO logs (timestamp, src_ip, dst_ip, protocol, length, danger_score) 
            VALUES (?, ?, ?, ?, ?, ?) 
        ''', (timestamp, src_ip, dst_ip, protocol, length, danger_score))

        if i % 10 == 0:
            print(f"🚀 Envoi de rafale de paquets... Score danger: {danger_score:.2f}")

        time.sleep(0.05) # Très rapide

    conn.commit()
    conn.close()
    print("✅ Attaque terminé. Vérifiez POWER BI !")

if __name__ == "__main__":
    simulation_attaque()

