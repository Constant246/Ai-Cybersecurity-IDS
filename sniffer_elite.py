import os
import joblib
import pandas as pd
import time
import requests
from collections import defaultdict, deque
from scapy.all import sniff, conf, get_if_addr
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6



# --- IMPORT DU GESTIONNAIRE SQL ---
import db_manager

# --- INITIALISATION DE LA BDD ---
print("🗄️ Initialisation de la Base de Données...")
db_manager.init_db()

# 1. CHARGEMENT DE L'INTELLIGENCE
try:
    model = joblib.load('models/elite_attack_detector.pkl')
    preprocessor = joblib.load('models/preprocessor.pkl')
    selected_features = joblib.load('models/selected_features.pkl')
    print("✅ Modèles IA chargés.")
except Exception as e:
    print(f"❌ Erreur de chargement des fichiers .pkl : {e}")
    exit()

# 2. CONFIGURATION
N8N_WEBHOOK_URL = "http://localhost:5678/webhook-test/ff8d5a85-c0be-4ef2-857d-8471667576aa"
THRESHOLD = 0.3  # Seuil abaissé pour mieux détecter les scans nmap

# 3. DETECTION DE L'IP DE L'INTERFACE VIRTUALBOX
"""
    Détecte l'IP de l'interface VirtualBox Host-Only.

    Cette fonction parcourt toutes les interfaces réseau disponibles
    et cherche celle qui correspond à l'adresse 192.168.56.1
    (adresse standard de VirtualBox Host-Only).

    Returns:
        str: Adresse IP de l'interface VirtualBox (ex: "192.168.56.1")
        None: Si l'interface n'est pas trouvée
"""
def get_virtualbox_ip():
    try:
        # Parcourt toutes les interfaces Scapy
        # conf.ifaces : Dictionnaire Scapy de toutes les interfaces
        # .values() : Récupère les objets interfaces (pas les noms)
        for iface in conf.ifaces.values():
            # Vérifie si l'interface a une IP
            if hasattr(iface, 'ip') and iface.ip:
                # Cherche l'interface Virtualbox
                if iface.ip.startswith("192.168.56."):
                    return iface.ip

        # Si on a pas trouvé avec le préfixe, on cherche excatement 192.168.56.1
        for iface in conf.ifaces.values():
            if hasattr(iface, 'ip') and iface.ip == "192.168.56.1":
                return iface.ip

        return None
    except Exception as e:
        print(f" ⚠️ Erreur détection IP Virtualbox : {e}")
        return None

# Détection au démarrage
VIRTUALBOX_IP = get_virtualbox_ip()
if VIRTUALBOX_IP:
    print(f" 🖥️ Interface Virtualbox détectée : {VIRTUALBOX_IP}")
    print(f" 📡 Le sniffer ignorera le traffic sortant de {VIRTUALBOX_IP}")
else:
    print(f"⚠️  Interface VirtualBox non détectée")
    print(f"⚠️  Le filtrage du trafic sortant sera désactivé")

# 3. STRUCTURES DE DONNÉES POUR ANALYSE TEMPORELLE
# Historique sur 2 secondes
packet_history = deque(maxlen=1000)

# Statistiques par connexion (src_ip, dst_ip)
connection_stats = defaultdict(lambda: {
    'count': 0,
    'srv_count': 0,
    'serror_count': 0,
    'rerror_count': 0,
    'same_srv_count': 0,
    'diff_srv_count': 0,
    'syn_count': 0,
    'rst_count': 0,
    'fin_count': 0,
    'last_service': None,
    'services': set(),
    'start_time': time.time()
})

# Statistiques par hôte de destination
dst_host_stats = defaultdict(lambda: {
    'count': 0,
    'srv_count': defaultdict(int),
    'serror_count': 0,
    'same_srv_count': 0,
    'diff_srv_count': 0,
    'same_src_port_count': 0,
    'connections': []
})


def map_service(dst_port, proto):
    """Mapping précis des ports vers les noms de services du dataset NSL-KDD"""
    service_map = {
        7: 'echo',
        20: 'ftp_data',
        21: 'ftp',
        22: 'ssh',
        23: 'telnet',
        25: 'smtp',
        53: 'domain_u' if proto == 'udp' else 'domain',
        79: 'finger',
        80: 'http',
        110: 'pop_3',
        111: 'sunrpc',
        113: 'auth',
        119: 'nntp',
        123: 'ntp_u',
        135: 'loc_srv',
        139: 'netbios_ns',
        143: 'imap4',
        161: 'snmp',
        443: 'https',
        445: 'microsoft_ds',
        512: 'exec',
        513: 'login',
        514: 'shell',
        1433: 'sql_net',
        3306: 'mysql',
        5432: 'postgres',
        6000: 'X11',
        8080: 'http_8001',
    }

    return service_map.get(dst_port, 'private')


def extract_tcp_flags(packet):
    """Extrait et interprète les flags TCP selon la nomenclature NSL-KDD"""
    if TCP not in packet:
        return 'SF'

    flags = packet[TCP].flags

    # SYN sans ACK = tentative de connexion
    if flags & 0x02 and not (flags & 0x10):  # SYN et pas ACK
        return 'S0'  # Connection attempt

    # SYN-ACK
    if flags & 0x02 and flags & 0x10:
        return 'S1'  # Connection established

    # RST = connexion rejetée
    if flags & 0x04:
        return 'REJ'  # Connection rejected

    # FIN = fermeture normale
    if flags & 0x01:
        return 'SF'  # Normal establishment and termination

    # Connexion établie (ACK)
    if flags & 0x10:
        return 'SF'

    return 'OTH'


def calculate_connection_stats(src_ip, dst_ip, service, flag, packet_type=None):
    # packet_type = pour distinguer request/reply
    """Calcule les statistiques de connexion en temps réel

       packet_type : 'echo-request' ou 'echo-reply' pour les ICMP
    """
    conn_key = (src_ip, dst_ip)
    conn = connection_stats[conn_key]
    dst = dst_host_stats[dst_ip]

    now = time.time()

    # Mise à jour des compteurs de connexion
    conn['count'] += 1
    dst['count'] += 1

    # Comptage par service
    if service == conn['last_service']:
        conn['same_srv_count'] += 1
        dst['same_srv_count'] += 1
    else:
        conn['diff_srv_count'] += 1
        dst['diff_srv_count'] += 1

    conn['last_service'] = service
    conn['services'].add(service)
    dst['srv_count'][service] += 1

    # Comptage des erreurs (flags suspects)
    if flag in ['S0', 'REJ', 'RSTO']:
        conn['serror_count'] += 1
        dst['serror_count'] += 1

    if flag in ['REJ', 'RSTR', 'RSTOS0']:
        conn['rerror_count'] += 1

    # Détection de scan (nombreux SYN sans réponse)
    if flag == 'S0':
        conn['syn_count'] += 1

    # Nettoyage des anciennes connexions (> 2 secondes)
    keys_to_remove = []
    for key, data in connection_stats.items():
        if now - data['start_time'] > 2.0:
            keys_to_remove.append(key)

    for key in keys_to_remove:
        del connection_stats[key]

    # Calcul des statistiques
    srv_count = dst['srv_count'][service]
    count = min(conn['count'], 511)  # Limitation comme dans NSL-KDD

    # Calcul des taux
    serror_rate = conn['serror_count'] / max(conn['count'], 1)
    rerror_rate = conn['rerror_count'] / max(conn['count'], 1)
    same_srv_rate = conn['same_srv_count'] / max(conn['count'], 1)
    diff_srv_rate = conn['diff_srv_count'] / max(conn['count'], 1)
    srv_diff_host_rate = (dst['diff_srv_count'] / max(dst['count'], 1))

    # Statistiques du host de destination
    dst_host_count = min(dst['count'], 255)
    dst_host_srv_count = min(srv_count, 255)
    dst_host_same_srv_rate = dst['same_srv_count'] / max(dst['count'], 1)
    dst_host_serror_rate = dst['serror_count'] / max(dst['count'], 1)

    return {
        'count': count,
        'srv_count': min(srv_count, 511),
        'serror_rate': serror_rate,
        'srv_serror_rate': serror_rate,  # Simplifié
        'rerror_rate': rerror_rate,
        'srv_rerror_rate': rerror_rate,  # Simplifié
        'same_srv_rate': same_srv_rate,
        'diff_srv_rate': diff_srv_rate,
        'srv_diff_host_rate': srv_diff_host_rate,
        'dst_host_count': dst_host_count,
        'dst_host_srv_count': dst_host_srv_count,
        'dst_host_same_srv_rate': dst_host_same_srv_rate,
        'dst_host_diff_srv_rate': 1.0 - dst_host_same_srv_rate,
        'dst_host_serror_rate': dst_host_serror_rate,
        'dst_host_srv_serror_rate': dst_host_serror_rate,
        'syn_count': conn['syn_count']
    }


def send_to_n8n(prob, raw_data, src_ip):
    """Envoie l'alerte à n8n pour analyse par les agents IA"""

    payload = {
        "src_ip": src_ip,
        "dst_ip": raw_data.get('dst_ip', 'unknown'),  # ← AJOUTER
        "protocol": raw_data.get('protocol_type', 'unknown'),
        "port": raw_data.get('dst_port', 0),  # ← AJOUTER
        "service": raw_data.get('service', 'other'),
        "flag": raw_data.get('flag', 'unknown'),
        "danger_score": round(float(prob), 4),
        "attacker_ip": src_ip,
        "count": raw_data.get('count', 0),
        "syn_count": raw_data.get('syn_count', 0)
    }

    try:
        response = requests.post(N8N_WEBHOOK_URL, json=payload, timeout=2)
        if response.status_code == 200:
            print(f"   ✅ Alerte envoyée à n8n (Status: {response.status_code})")
        else:
            print(f"   ⚠️  n8n a répondu avec le code {response.status_code}")
    except requests.exceptions.Timeout:
        print(f"  Timeout lors de l'envoi à n8n (> 2s)")
    except requests.exceptions.ConnectionError:
        print(f"   ❌ Impossible de se connecter à n8n (vérifiez que n8n tourne)")
    except Exception as e:
        print(f"   ❌ Erreur envoi n8n : {e}")


def packet_callback(packet):
    """Analyse chaque paquet capturé"""

    # --- 1. IDENTIFICATION DE LA COUCHE IP ---
    layer_ip = None

    # Essayer d'obtenir la couche IP de différentes manières
    if IP in packet:
        layer_ip = packet[IP]

        # ✅ FILTRE : Ignore le trafic sortant de l'interface VirtualBox
        # Utilise VIRTUALBOX_IP au lieu de LOCAL_IP
        if VIRTUALBOX_IP and layer_ip.src == VIRTUALBOX_IP:
            # C'est du traffic sortant, donc on ignore silencieusememnt
            return  # <- On sort immédiatement

        # Arrivé ici, on peut afficher le traffic, car il est sortant
        # 🔴 DEBUG : Afficher TOUS les paquets capturés
        print(f"📦 PAQUET CAPTURÉ : {packet.summary()}")
        print(f"✅ IPV4 détecté : {layer_ip.src} -> {layer_ip.dst}")

    elif IPv6 in packet:
        layer_ip = packet[IPv6]

        # 🔴 DEBUG : Afficher TOUS les paquets capturés
        print(f"📦 PAQUET CAPTURÉ : {packet.summary()}")
        print(f"   ✅ IPv6 détecté : {layer_ip.src} → {layer_ip.dst}")

    else:
        # 🔴 DEBUG : Afficher TOUS les paquets capturés
        print(f"📦 PAQUET CAPTURÉ : {packet.summary()}")
        print(f"   ⚠️  Pas de couche IP, paquet ignoré")
        return

    try:
        src_ip = layer_ip.src
        dst_ip = layer_ip.dst

        # Calculer la taille du payload
        if hasattr(layer_ip, 'len'):
            payload_len = layer_ip.len
        else:
            payload_len = len(bytes(layer_ip.payload)) if layer_ip.payload else 0

        # --- 2. DÉTECTION DU PROTOCOLE ET SERVICE ---
        proto = "icmp"
        service = "ecr_i"
        tcp_flag = "SF"
        dst_port = 0
        src_port = 0
        duration = 0

        if TCP in packet:
            proto = "tcp"
            tcp_layer = packet[TCP]
            dst_port = tcp_layer.dport
            src_port = tcp_layer.sport
            service = map_service(dst_port, proto)
            tcp_flag = extract_tcp_flags(packet)
            print(f"   🔹 TCP détecté : Port {dst_port} | Service: {service} | Flag: {tcp_flag}")

        elif UDP in packet:
            proto = "udp"
            udp_layer = packet[UDP]
            dst_port = udp_layer.dport
            src_port = udp_layer.sport
            service = map_service(dst_port, proto)
            print(f"   🔹 UDP détecté : Port {dst_port} | Service: {service}")

        elif ICMP in packet:
            proto = "icmp"           # <- Proto = icmp
            service = "ecr_i"        # <- echo reply/request
            print(f" 🔹 ICMP détecté")

        # --- 3. CALCUL DES STATISTIQUES ---
        stats = calculate_connection_stats(src_ip, dst_ip, service, tcp_flag)

        # --- 4. CONSTRUCTION DU VECTEUR DE FEATURES (41 features) ---
        raw_data = {
            'duration': duration,
            'protocol_type': proto,
            'service': service,
            'flag': tcp_flag,
            'src_bytes': payload_len,
            'dst_bytes': 0,
            'land': 1 if src_ip == dst_ip else 0,
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': 1 if dst_port in [21, 22, 23, 25] else 0,
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0,
            'count': stats['count'],
            'srv_count': stats['srv_count'],
            'serror_rate': stats['serror_rate'],
            'srv_serror_rate': stats['srv_serror_rate'],
            'rerror_rate': stats['rerror_rate'],
            'srv_rerror_rate': stats['srv_rerror_rate'],
            'same_srv_rate': stats['same_srv_rate'],
            'diff_srv_rate': stats['diff_srv_rate'],
            'srv_diff_host_rate': stats['srv_diff_host_rate'],
            'dst_host_count': stats['dst_host_count'],
            'dst_host_srv_count': stats['dst_host_srv_count'],
            'dst_host_same_srv_rate': stats['dst_host_same_srv_rate'],
            'dst_host_diff_srv_rate': stats['dst_host_diff_srv_rate'],
            'dst_host_same_src_port_rate': 0.0,
            'dst_host_srv_diff_host_rate': 0.0,
            'dst_host_serror_rate': stats['dst_host_serror_rate'],
            'dst_host_srv_serror_rate': stats['dst_host_srv_serror_rate'],
            'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0,
            'syn_count': stats['syn_count']
        }

        # --- 5. PRÉDICTION IA ---
        df_raw = pd.DataFrame([raw_data])

        # Suppression de syn_count qui n'est pas dans les features originales
        df_raw_clean = df_raw.drop(['syn_count'], axis=1)

        X_transformed = preprocessor.transform(df_raw_clean)

        # Reconstruction des colonnes
        cat_cols = list(preprocessor.named_transformers_['cat'].get_feature_names_out())
        num_cols = list(preprocessor.named_transformers_['num'].get_feature_names_out())
        df_full = pd.DataFrame(X_transformed, columns=cat_cols + num_cols)

        # Sélection des features
        X_final = df_full[selected_features]

        # Calcul de la probabilité
        prob = model.predict_proba(X_final)[0, 1]

        print(f"   🎯 Probabilité d'attaque : {prob:.4f} ({prob * 100:.1f}%)")

        # --- 6. ENREGISTREMENT SQL ---
        current_time = time.strftime("%Y-%m-%d %H:%M:%S")
        db_manager.insert_packet(
            timestamp=current_time,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=proto,
            length=payload_len,
            danger_score=float(prob)
        )

        # --- 7. AFFICHAGE ET ALERTES ---
        # Indicateurs de scan
        scan_indicators = []
        if stats['syn_count'] > 5:
            scan_indicators.append(f"SYN:{stats['syn_count']}")
        if stats['count'] > 10:
            scan_indicators.append(f"COUNT:{stats['count']}")
        if tcp_flag == 'S0':
            scan_indicators.append("FLAG:S0")

        indicators_str = " | ".join(scan_indicators) if scan_indicators else ""

        # SEUIL ADAPTATIF - LOGIQUE INTELLIGENTE
        # Cette logique ajuste le seuil d'alerte selon le type de traffic
        if proto == "icmp" and stats['count'] < 10:
            # CAS 1: ICMP avec peu de paquets
            # Probablement un Ping normal (ping -c 5 )
            # Seuil élevé pour éviter les faux positifs
            seuil_icmp = 0.995
            raison = "ICMP léger (ping normal)"

        elif proto == "icmp" and stats['count'] >= 10:
            # CAS 2: ICMP avec beaucoup de parquets
            # Pourrait etre un ICMP flood ou ping sweep(attaque)
            # Seuil réduit pour détecter l'anomalie
            seuil_icmp = 0.85
            raison = "ICMP intensif (potentiellement un flood)"
        else:
            # CAS 3: TCP ou UDP
            # Protocoles principaux pour les scans nmap
            seuil_icmp = THRESHOLD
            raison = "Traffic TCP/UDP"

        if prob >= seuil_icmp or scan_indicators:
            # Choix de l'icone selon la gravité
            status_icon = "🚨" if prob >= seuil_icmp else "⚠️"

            # Affichage de l'alerte avec tous les détails
            print(f"\n{status_icon} {proto.upper()}:{dst_port} | {src_ip} → {dst_ip} | "
                  f"Service:{service} | Flag:{tcp_flag} | "
                  f"Danger:{prob:.4f} | {indicators_str}\n")

            # Affichage du seuil utilisé
            print(f" Seuil appliqué: {seuil_icmp*100:.1f}% ({raison})\n")

        if prob >= seuil_icmp:
            print(f"🔥 ALERTE ATTAQUE DÉTECTÉE ({prob * 100:.1f}%) !")

            # Préparer les données pour n8n
            alert_data = {
                **raw_data,              # Copie tous les champs de raw_data
                'dst_ip': dst_ip,
                'dst_port': dst_port
            }

            send_to_n8n(prob, alert_data, src_ip)

        print("-" * 80)  # Séparateur pour la lisibilité

    except Exception as e:
        print(f"⚠️ Erreur traitement : {e}")
        import traceback
        traceback.print_exc()

# -----------------------------------------------------------
# LANCEMENT DU SNIFFER
# -----------------------------------------------------------
print("🛡️ Sniffer Elite PRO v2 (Mode SQL + Analyse Avancée)")
print(f"🎯 Seuil d'alerte : {THRESHOLD * 100}%")

conf.sniff_promisc = True

# Recherche de l'interface VirtualBox
target_iface = None
print("🔍 Recherche de l'interface VirtualBox (192.168.56.1)...")

for face in conf.ifaces.values():
    if face.ip == "192.168.56.1":
        target_iface = face
        break

if target_iface:
    print(f"✅ Interface trouvée -> {target_iface.description}")
    print("📡 En écoute des scans nmap...\n")
    sniff(iface=target_iface.name, prn=packet_callback, store=0, filter="ip")
else:
    print("⚠️ Interface Host-Only introuvable. Lancement sur interface par défaut...")
    sniff(prn=packet_callback, store=0, filter="ip")

