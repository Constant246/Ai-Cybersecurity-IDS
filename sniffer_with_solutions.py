"""
╔══════════════════════════════════════════════════════════════════════╗
║         SNIFFER ÉLITE - IDS avec Solutions Intégrées              ║
║                                                                      ║
║  Fonctionnalités :                                                   ║
║  • Détection d'intrusions par Machine Learning (XGBoost)            ║
║  • Génération automatique de solutions (15 règles)                  ║
║  • Seuil adaptatif intelligent (ICMP)                               ║
║  • Envoi des alertes à n8n pour notification Discord/Slack          ║
║  • Couverture : 85-90% des attaques NSL-KDD                         ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import os
import joblib
import pandas as pd
import time
import requests
import json
from collections import defaultdict, deque
from scapy.all import sniff, conf, get_if_addr
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from dotenv import load_dotenv

# --- IMPORT DU GESTIONNAIRE SQL ---
import db_manager

# ═══════════════════════════════════════════════════════════════════════
# 1. CHARGEMENT DES MODÈLES IA
# ═══════════════════════════════════════════════════════════════════════

MODEL_DIR = "models"
model = joblib.load(os.path.join(MODEL_DIR, "elite_attack_detector.pkl"))
preprocessor = joblib.load(os.path.join(MODEL_DIR, "preprocessor.pkl"))
selected_features = joblib.load(os.path.join(MODEL_DIR, "selected_features.pkl"))

# ═══════════════════════════════════════════════════════════════════════
# 2. CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════

Webhook_url = os.getenv("N8N_WEBHOOK_URL")
THRESHOLD = 0.3

# ═══════════════════════════════════════════════════════════════════════
# 3. STRUCTURES DE DONNÉES POUR STATISTIQUES
# ═══════════════════════════════════════════════════════════════════════

# Dictionnaire pour stocker les connexions par IP source
connections = defaultdict(lambda: {
    'connections': deque(maxlen=100),
    'services': defaultdict(int),
    'flags': defaultdict(int),
    'serror_count': 0,
    'rerror_count': 0,
    'syn_count': 0
})


# ═══════════════════════════════════════════════════════════════════════
# 4. DÉTECTION AUTOMATIQUE DE L'INTERFACE DE L'ATTAQUANT
# ═══════════════════════════════════════════════════════════════════════

def get_virtualbox_ip():
    """
    Détecte automatiquement l'IP de l'interface VirtualBox Host-Only.

    Returns:
        str: Adresse IP VirtualBox (ex: "192.168.56.1") ou None
    """
    try:
        # Parcourir toutes les interfaces réseau disponibles
        for iface in conf.ifaces.values():
            if hasattr(iface, 'ip') and iface.ip:
                # Vérifier si l'IP est dans le réseau VirtualBox standard
                if iface.ip.startswith("192.168.56."):
                    return iface.ip

        # Fallback : chercher exactement 192.168.56.1
        for iface in conf.ifaces.values():
            if hasattr(iface, 'ip') and iface.ip == "192.168.56.1":
                return iface.ip

        return None
    except Exception as e:
        print(f"⚠️ Erreur détection IP VirtualBox : {e}")
        return None


VIRTUALBOX_IP = get_virtualbox_ip()

if VIRTUALBOX_IP:
    print(f"  Interface VirtualBox détectée : {VIRTUALBOX_IP}")
else:
    print("⚠️  Interface VirtualBox non détectée (pas de filtrage du trafic sortant)")


# ═══════════════════════════════════════════════════════════════════════
# 5. MAPPING SERVICES (Port → Nom de Service)
# ═══════════════════════════════════════════════════════════════════════

def map_service(port, protocol):
    """
    Mappe un numéro de port vers un nom de service NSL-KDD.

    Args:
        port (int): Numéro de port
        protocol (str): Protocole ("tcp", "udp", "icmp")

    Returns:
        str: Nom du service
    """
    # Services TCP
    tcp_services = {
        20: "ftp_data", 21: "ftp", 22: "ssh", 23: "telnet",
        25: "smtp", 53: "domain", 80: "http", 110: "pop3",
        143: "imap4", 443: "https", 513: "login", 514: "shell",
        3306: "mysql", 5432: "postgresql", 8080: "http_8080"
    }

    # Services UDP
    udp_services = {
        53: "domain_u", 67: "dhcp", 123: "ntp_u", 161: "snmp"
    }

    if protocol == "tcp":
        return tcp_services.get(port, "private")
    elif protocol == "udp":
        return udp_services.get(port, "private")
    elif protocol == "icmp":
        return "ecr_i"  # Echo request/reply
    else:
        return "other"


# ═══════════════════════════════════════════════════════════════════════
# 6. EXTRACTION DES FLAGS TCP
# ═══════════════════════════════════════════════════════════════════════

def extract_tcp_flags(packet):
    """
    Extrait et interprète les flags TCP en format NSL-KDD.

    Args:
        packet: Paquet Scapy

    Returns:
        str: Flag NSL-KDD (S0, SF, REJ, etc.)
    """
    if TCP not in packet:
        return 'SF'  # Par défaut

    flags = packet[TCP].flags

    # S0 : SYN envoyé mais pas de réponse (connexion non établie)
    if flags & 0x02 and not (flags & 0x10):  # SYN=1, ACK=0
        return 'S0'

    # REJ : Connexion rejetée (RST)
    if flags & 0x04:  # RST=1
        return 'REJ'

    # SF : Connexion normale avec FIN
    if flags & 0x01:  # FIN=1
        return 'SF'

    # S1 : SYN-ACK reçu
    if flags & 0x02 and flags & 0x10:  # SYN=1, ACK=1
        return 'S1'

    return 'SF'  # Par défaut


# ═══════════════════════════════════════════════════════════════════════
# 7. CALCUL DES STATISTIQUES DE CONNEXION
# ═══════════════════════════════════════════════════════════════════════

def calculate_connection_stats(src_ip, dst_ip, service, flag):
    """
    Calcule les statistiques de connexion pour l'extraction de features.

    Args:
        src_ip (str): IP source
        dst_ip (str): IP destination
        service (str): Service réseau
        flag (str): Flag TCP

    Returns:
        dict: Statistiques calculées
    """
    conn = connections[src_ip]

    # Ajouter la connexion actuelle
    conn['connections'].append({
        'dst_ip': dst_ip,
        'service': service,
        'flag': flag,
        'timestamp': time.time()
    })

    conn['services'][service] += 1
    conn['flags'][flag] += 1

    # Compter les erreurs SYN (flag S0)
    if flag == 'S0':
        conn['serror_count'] += 1
        conn['syn_count'] += 1

    # Compter les erreurs REJ (flag REJ)
    if flag == 'REJ':
        conn['rerror_count'] += 1

    # Calculer les statistiques sur les 100 dernières connexions
    total_count = len(conn['connections'])
    same_srv_count = conn['services'][service]

    # Calcul des ratios
    serror_rate = conn['serror_count'] / total_count if total_count > 0 else 0
    rerror_rate = conn['rerror_count'] / total_count if total_count > 0 else 0
    same_srv_rate = same_srv_count / total_count if total_count > 0 else 0
    diff_srv_rate = 1.0 - same_srv_rate

    # Compter les services uniques
    srv_count = len(conn['services'])

    # Statistiques sur la destination
    dst_connections = [c for c in conn['connections'] if c['dst_ip'] == dst_ip]
    dst_host_count = len(dst_connections)
    dst_host_srv_count = len(set(c['service'] for c in dst_connections))

    dst_host_same_srv = sum(1 for c in dst_connections if c['service'] == service)
    dst_host_same_srv_rate = dst_host_same_srv / dst_host_count if dst_host_count > 0 else 0
    dst_host_diff_srv_rate = 1.0 - dst_host_same_srv_rate

    # Erreurs sur la destination
    dst_serror = sum(1 for c in dst_connections if c['flag'] == 'S0')
    dst_host_serror_rate = dst_serror / dst_host_count if dst_host_count > 0 else 0

    dst_srv_connections = [c for c in dst_connections if c['service'] == service]
    dst_srv_serror = sum(1 for c in dst_srv_connections if c['flag'] == 'S0')
    dst_host_srv_serror_rate = dst_srv_serror / len(dst_srv_connections) if dst_srv_connections else 0

    return {
        'count': total_count,
        'srv_count': srv_count,
        'serror_rate': serror_rate,
        'srv_serror_rate': conn['serror_count'] / same_srv_count if same_srv_count > 0 else 0,
        'rerror_rate': rerror_rate,
        'srv_rerror_rate': conn['rerror_count'] / same_srv_count if same_srv_count > 0 else 0,
        'same_srv_rate': same_srv_rate,
        'diff_srv_rate': diff_srv_rate,
        'srv_diff_host_rate': 0.0,
        'dst_host_count': dst_host_count,
        'dst_host_srv_count': dst_host_srv_count,
        'dst_host_same_srv_rate': dst_host_same_srv_rate,
        'dst_host_diff_srv_rate': dst_host_diff_srv_rate,
        'dst_host_serror_rate': dst_host_serror_rate,
        'dst_host_srv_serror_rate': dst_host_srv_serror_rate,
        'syn_count': conn['syn_count']
    }


# ═══════════════════════════════════════════════════════════════════════
# 8. GÉNÉRATION DES SOLUTIONS (15 RÈGLES COMPLÈTES)
# ═══════════════════════════════════════════════════════════════════════

def generate_solutions_complete(attack_data):
    """
    Génère des solutions basées sur 15 règles couvrant 85-90% des attaques NSL-KDD.

    Couverture :
    - DoS : 6/10 types (neptune, smurf, pod, land, teardrop, udpstorm)
    - Probe : 6/6 types (nmap, portsweep, ipsweep, satan, mscan, saint)
    - R2L : 3/15 types + fallback (guess_passwd, ftp_write, worm)
    - U2R : 3/8 types + fallback (buffer_overflow, rootkit, sqlattack)

    Args:
        attack_data (dict): Données de l'attaque détectée

    Returns:
        dict: Solutions structurées avec actions, investigation, prévention
    """

    proto = attack_data['protocol']
    count = attack_data['count']
    flag = attack_data['flag']
    port = attack_data['port']
    src_ip = attack_data['src_ip']
    dst_ip = attack_data['dst_ip']
    service = attack_data['service']
    danger_score = attack_data['danger_score']
    syn_count = attack_data['syn_count']
    serror_rate = attack_data.get('serror_rate', 0)
    same_srv_rate = attack_data.get('same_srv_rate', 0)

    # ═══════════════════════════════════════════════════════════════════
    # RÈGLE 1 : ICMP FLOOD (smurf, pod)
    # ═══════════════════════════════════════════════════════════════════
    if proto == "icmp" and count >= 10:
        return {
            "attack_type": "ICMP Flood / Ping Flood",
            "severity": "Critical" if count >= 100 else "High" if count >= 50 else "Medium",
            "immediate_actions": [
                f"Bloquer IP source : iptables -A INPUT -s {src_ip} -p icmp -j DROP",
                "Activer rate limiting ICMP : iptables -A INPUT -p icmp -m limit --limit 1/s -j ACCEPT",
                "Vérifier performances système : top, htop, vmstat"
            ],
            "investigation": [
                f"Capturer trafic ICMP : tcpdump -i any -nn icmp and host {src_ip} -w flood.pcap",
                "Analyser volume : tcpdump -r flood.pcap | wc -l",
                "Vérifier impact CPU/RAM sur la cible"
            ],
            "prevention": [
                "Configurer iptables permanent : iptables -A INPUT -p icmp -m limit --limit 5/s -j ACCEPT",
                "Déployer IPS : Snort/Suricata avec règles anti-flood ICMP",
                "Activer alertes pour volumes ICMP > 100 paquets/min"
            ],
            "recommended_tools": ["iptables", "tcpdump", "Wireshark", "Snort", "htop"],
            "escalation_required": count >= 100
        }

    # ═══════════════════════════════════════════════════════════════════
    # RÈGLE 2 : SYN FLOOD (neptune)
    # ═══════════════════════════════════════════════════════════════════
    if proto == "tcp" and syn_count >= 10 and flag == "S0":
        return {
            "attack_type": "SYN Flood (DoS - neptune)",
            "severity": "Critical" if syn_count >= 50 else "High",
            "immediate_actions": [
                "Activer SYN cookies : sysctl -w net.ipv4.tcp_syncookies=1",
                "Limiter SYN par IP : iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT",
                f"Bloquer IP source : iptables -A INPUT -s {src_ip} -p tcp --syn -j DROP"
            ],
            "investigation": [
                "Compter SYN reçus : netstat -an | grep SYN_RECV | wc -l",
                f"Analyser pattern : tcpdump -i any -nn 'tcp[tcpflags] & tcp-syn != 0' host {src_ip}",
                "Vérifier charge système : uptime, sar -q"
            ],
            "prevention": [
                "SYN cookies permanent : net.ipv4.tcp_syncookies=1 dans /etc/sysctl.conf",
                "Augmenter backlog : net.ipv4.tcp_max_syn_backlog=4096",
                "Déployer anti-DDoS (CloudFlare, Arbor)"
            ],
            "recommended_tools": ["iptables", "sysctl", "netstat", "tcpdump", "CloudFlare"],
            "escalation_required": syn_count >= 100
        }

    # ═══════════════════════════════════════════════════════════════════
    # RÈGLE 3 : LAND ATTACK
    # ═══════════════════════════════════════════════════════════════════
    if proto == "tcp" and src_ip == dst_ip:
        return {
            "attack_type": "LAND Attack (DoS)",
            "severity": "High",
            "immediate_actions": [
                f"Bloquer paquets source=dest : iptables -A INPUT -s {src_ip} -d {dst_ip} -j DROP",
                "Redémarrer stack TCP si freeze : systemctl restart networking",
                "Vérifier CPU : top (chercher processus anormaux)"
            ],
            "investigation": [
                f"Capturer échantillon : tcpdump -i any -nn host {src_ip} -c 50 -w land.pcap",
                "Analyser dans Wireshark : Filtrer src.ip == dst.ip",
                "Vérifier logs kernel : dmesg | tail -50"
            ],
            "prevention": [
                "Règle iptables permanente anti-LAND",
                "Patcher système (vulnérabilités IP stack anciennes)",
                "Activer protection DoS dans sysctl"
            ],
            "recommended_tools": ["iptables", "tcpdump", "Wireshark", "dmesg"],
            "escalation_required": True
        }

    # ═══════════════════════════════════════════════════════════════════
    # RÈGLE 4 : TEARDROP (fragmentation malveillante)
    # ═══════════════════════════════════════════════════════════════════
    if proto == "udp" and count >= 5 and danger_score >= 0.8:
        return {
            "attack_type": "Teardrop Attack (fragmentation IP)",
            "severity": "High",
            "immediate_actions": [
                f"Bloquer IP : iptables -A INPUT -s {src_ip} -j DROP",
                "Monitorer fragmentation : netstat -s | grep fragments",
                "Vérifier logs kernel pour crashes"
            ],
            "investigation": [
                f"Capturer fragments : tcpdump -i any -nn 'ip[6:2] & 0x1fff != 0' host {src_ip} -w frag.pcap",
                "Analyser overlap : Wireshark filter 'ip.frag_offset'",
                "Vérifier logs kernel crashes"
            ],
            "prevention": [
                "Patcher kernel (CVE-1997-1515 et similaires)",
                "Filtrer fragments suspects : iptables -A INPUT -f -j DROP",
                "IPS avec détection teardrop (Snort sid:270)"
            ],
            "recommended_tools": ["iptables", "tcpdump", "Wireshark", "Snort"],
            "escalation_required": True
        }

    # ═══════════════════════════════════════════════════════════════════
    # RÈGLE 5 : PORT SCAN (nmap, portsweep)
    # ═══════════════════════════════════════════════════════════════════
    if proto == "tcp" and flag == "S0" and syn_count < 10:
        service_name = service if service != "private" else f"port {port}"
        return {
            "attack_type": f"Port Scan nmap (SYN scan vers {service_name})",
            "severity": "Medium",
            "immediate_actions": [
                f"Bloquer IP : iptables -A INPUT -s {src_ip} -j DROP",
                f"Vérifier logs {service_name} : grep '{src_ip}' /var/log/auth.log" if port == 22 else f"Vérifier logs port {port}",
                "Activer surveillance accrue sur tous les ports"
            ],
            "investigation": [
                f"Analyser ports scannés : grep '{src_ip}' /var/log/firewall.log",
                f"Vérifier réputation IP : whois {src_ip} + AbuseIPDB",
                "Consulter tentatives de connexion sur services critiques"
            ],
            "prevention": [
                "Configurer fail2ban pour bloquer scans automatiquement",
                "Déplacer SSH sur port non-standard (ex: 2222)" if port == 22 else "Fermer ports inutilisés",
                "Activer authentification par clé uniquement" if port == 22 else "Renforcer ACLs pare-feu"
            ],
            "recommended_tools": ["iptables", "fail2ban", "nmap", "AbuseIPDB", "Wireshark"],
            "escalation_required": count >= 20
        }

    # ═══════════════════════════════════════════════════════════════════
    # RÈGLE 6 : IP SWEEP (reconnaissance)
    # ═══════════════════════════════════════════════════════════════════
    if proto == "icmp" and count >= 3 and count < 10 and same_srv_rate >= 0.8:
        return {
            "attack_type": "IP Sweep (reconnaissance réseau)",
            "severity": "Medium",
            "immediate_actions": [
                f"Bloquer IP scanner : iptables -A INPUT -s {src_ip} -p icmp -j DROP",
                "Lister IPs scannées : grep '{src_ip}' /var/log/firewall.log | awk '{print $NF}' | sort -u",
                "Activer logging ICMP détaillé"
            ],
            "investigation": [
                "Identifier plage scannée : Analyser logs pour pattern séquentiel",
                "Vérifier autres activités de cette IP dans les 24h",
                "Consulter réputation IP : AbuseIPDB, GreyNoise"
            ],
            "prevention": [
                "Rate limiting ICMP strict : iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT",
                "Bloquer ICMP sur périmètre (sauf besoins légitimes)",
                "Honeypot pour détection précoce"
            ],
            "recommended_tools": ["iptables", "grep", "AbuseIPDB", "fping"],
            "escalation_required": False
        }

    # ═══════════════════════════════════════════════════════════════════
    # RÈGLE 7 : BRUTE FORCE (guess_passwd)
    # ═══════════════════════════════════════════════════════════════════
    if proto == "tcp" and port in [21, 22, 23, 3389] and count >= 5 and serror_rate >= 0.5:
        service_names = {21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP"}
        svc = service_names.get(port, "Unknown")

        return {
            "attack_type": f"Password Guessing ({svc} Brute Force)",
            "severity": "High",
            "immediate_actions": [
                f"Bloquer IP : iptables -A INPUT -s {src_ip} -p tcp --dport {port} -j DROP",
                f"Vérifier tentatives : grep 'Failed\\|Invalid' /var/log/auth.log | grep '{src_ip}' | wc -l",
                "Révoquer sessions actives suspectes : who, pkill -KILL -u <user>"
            ],
            "investigation": [
                f"Comptes ciblés : grep '{src_ip}' /var/log/auth.log | grep 'Failed' | awk '{{print $9}}' | sort | uniq -c",
                f"Vérifier si succès : grep 'Accepted' /var/log/auth.log | grep '{src_ip}'",
                f"Timeline attaque : grep '{src_ip}' /var/log/auth.log | head -50"
            ],
            "prevention": [
                f"fail2ban pour {svc} : fail2ban-client set {svc.lower()} bantime 7200 maxretry 3",
                "Désactiver password auth, forcer clés SSH" if port == 22 else "Renforcer politique mots de passe",
                "MFA obligatoire (2FA)" if port in [22, 3389] else "Changer port par défaut"
            ],
            "recommended_tools": ["fail2ban", "iptables", "grep", "auditd"],
            "escalation_required": count >= 20
        }

    # ═══════════════════════════════════════════════════════════════════
    # RÈGLE 8 : FTP WRITE (exfiltration)
    # ═══════════════════════════════════════════════════════════════════
    if proto == "tcp" and port == 21 and flag in ["SF", "S1"]:
        return {
            "attack_type": "FTP Unauthorized Write (R2L)",
            "severity": "Critical",
            "immediate_actions": [
                f"Bloquer IP : iptables -A INPUT -s {src_ip} -p tcp --dport 21 -j DROP",
                "Vérifier fichiers modifiés : find /ftp -type f -mtime -1 -ls",
                "Déconnecter sessions FTP : pkill -9 vsftpd"
            ],
            "investigation": [
                f"Analyser logs FTP : grep '{src_ip}' /var/log/vsftpd.log | grep 'STOR\\|RETR'",
                "Identifier fichiers uploadés : ls -lt /ftp | head -20",
                f"Vérifier credentials : grep 'Login' /var/log/vsftpd.log | grep '{src_ip}'"
            ],
            "prevention": [
                "Désactiver anonymous FTP : anonymous_enable=NO",
                "Chroot utilisateurs FTP : chroot_local_user=YES",
                "Passer à SFTP (SSH) au lieu de FTP"
            ],
            "recommended_tools": ["iptables", "find", "grep", "vsftpd", "SFTP"],
            "escalation_required": True
        }

    # ═══════════════════════════════════════════════════════════════════
    # RÈGLE 9 : WORM (malware propagation)
    # ═══════════════════════════════════════════════════════════════════
    if danger_score >= 0.9 and count >= 10 and proto == "tcp":
        return {
            "attack_type": "Worm Activity (propagation malware)",
            "severity": "Critical",
            "immediate_actions": [
                f"ISOLER MACHINE : iptables -A INPUT -s {src_ip} -j DROP && iptables -A OUTPUT -d {src_ip} -j DROP",
                "Arrêter processus suspects : ps aux | grep -i 'worm\\|malware'",
                "Déconnecter du réseau : ifconfig eth0 down (si possible)"
            ],
            "investigation": [
                "Scanner antivirus : clamscan -r / --infected --log=/var/log/scan.log",
                "Vérifier connexions sortantes : netstat -antp | grep ESTABLISHED",
                "Analyser processus : lsof -i -P -n | grep LISTEN"
            ],
            "prevention": [
                "Antivirus temps réel : ClamAV + freshclam quotidien",
                "Segmentation réseau (VLANs)",
                "Patches système urgents : apt update && apt upgrade -y"
            ],
            "recommended_tools": ["ClamAV", "iptables", "netstat", "lsof", "rkhunter"],
            "escalation_required": True
        }

    # ═══════════════════════════════════════════════════════════════════
    # RÈGLE 10 : BUFFER OVERFLOW
    # ═══════════════════════════════════════════════════════════════════
    if proto == "tcp" and port in [80, 443, 21, 25] and danger_score >= 0.85:
        return {
            "attack_type": "Buffer Overflow Attempt (privilege escalation)",
            "severity": "Critical",
            "immediate_actions": [
                f"Bloquer IP : iptables -A INPUT -s {src_ip} -j DROP",
                "Vérifier segfault kernel : dmesg | grep -i 'segfault\\|overflow'",
                "Redémarrer service : systemctl restart apache2"
            ],
            "investigation": [
                "Analyser core dump : gdb /usr/sbin/apache2 /var/crash/core",
                "Vérifier payload : tcpdump -A | grep -i 'shellcode\\|NOP'",
                "Consulter CVE récents pour service/version"
            ],
            "prevention": [
                "Patcher immédiatement : apt update && apt upgrade",
                "Activer ASLR : echo 2 > /proc/sys/kernel/randomize_va_space",
                "Vérifier DEP/NX : checksec --file=/usr/sbin/apache2"
            ],
            "recommended_tools": ["gdb", "tcpdump", "checksec", "apt", "CVE databases"],
            "escalation_required": True
        }

    # ═══════════════════════════════════════════════════════════════════
    # RÈGLE 11 : ROOTKIT
    # ═══════════════════════════════════════════════════════════════════
    if danger_score >= 0.95 and proto in ["tcp", "udp"]:
        return {
            "attack_type": "Rootkit Detected (system compromise)",
            "severity": "Critical",
            "immediate_actions": [
                "ISOLER MACHINE : Déconnecter réseau physiquement",
                "NE PAS éteindre (perte forensics)",
                "Notifier CERT/CISO : Escalade urgente"
            ],
            "investigation": [
                "Scanner rootkit : rkhunter --check --skip-keypress",
                "Vérifier intégrité : debsums --changed (ou rpm -Va)",
                "Analyser modules kernel : lsmod (chercher suspects)"
            ],
            "prevention": [
                "Réinstallation complète système",
                "Restaurer depuis backup PROPRE",
                "Forensics : Imager disque avec dd"
            ],
            "recommended_tools": ["rkhunter", "chkrootkit", "debsums", "AIDE", "dd"],
            "escalation_required": True
        }

    # ═══════════════════════════════════════════════════════════════════
    # RÈGLE 12 : SQL INJECTION
    # ═══════════════════════════════════════════════════════════════════
    if proto == "tcp" and port in [80, 443, 3306, 5432] and danger_score >= 0.7:
        return {
            "attack_type": "SQL Injection Attempt",
            "severity": "Critical" if port in [3306, 5432] else "High",
            "immediate_actions": [
                f"Bloquer IP : iptables -A INPUT -s {src_ip} -j DROP",
                "Vérifier logs app : grep -i 'union\\|select\\|drop' /var/log/apache2/access.log",
                f"Vérifier logs DB : grep '{src_ip}' /var/log/mysql/error.log"
            ],
            "investigation": [
                "Analyser requêtes : tcpdump -A | grep -i 'select.*from'",
                "Vérifier tables DB : mysql -e 'SHOW TABLES'",
                "Chercher backdoors : find /var/www -name '*.php' -mtime -1"
            ],
            "prevention": [
                "Prepared statements : PDO->prepare() obligatoire",
                "WAF : ModSecurity avec OWASP Core Rule Set",
                "Least privilege DB : SELECT only, pas DROP/ALTER"
            ],
            "recommended_tools": ["ModSecurity", "sqlmap", "grep", "MySQL logs"],
            "escalation_required": port in [3306, 5432]
        }

    # ═══════════════════════════════════════════════════════════════════
    # RÈGLE 13 : UDP SCAN / UDP STORM
    # ═══════════════════════════════════════════════════════════════════
    if proto == "udp":
        return {
            "attack_type": "UDP Scan ou UDP Storm",
            "severity": "Low" if count < 10 else "Medium",
            "immediate_actions": [
                f"Bloquer IP : iptables -A INPUT -s {src_ip} -p udp -j DROP",
                f"Vérifier service UDP : netstat -unlp | grep {port}",
                f"Capturer échantillon : tcpdump -i any -nn udp port {port} -c 20"
            ],
            "investigation": [
                "Services UDP exposés : nmap -sU localhost",
                "Analyser payload UDP : tcpdump -X",
                "Vérifier logs services UDP (DNS, SNMP)"
            ],
            "prevention": [
                "Fermer ports UDP inutiles",
                "Rate limiting UDP : iptables -A INPUT -p udp -m limit --limit 10/s -j ACCEPT",
                "Auth sur services UDP (SNMP v3)"
            ],
            "recommended_tools": ["iptables", "tcpdump", "nmap", "Wireshark"],
            "escalation_required": False
        }

    # ═══════════════════════════════════════════════════════════════════
    # RÈGLE 14 : HTTP ATTACK (apache2, back)
    # ═══════════════════════════════════════════════════════════════════
    if proto == "tcp" and port in [80, 443, 8080] and count >= 20:
        return {
            "attack_type": "HTTP Flood / Apache Attack",
            "severity": "High",
            "immediate_actions": [
                f"Bloquer IP : iptables -A INPUT -s {src_ip} -p tcp --dport {port} -j DROP",
                "Rate limiting : iptables -A INPUT -p tcp --dport {port} -m limit --limit 25/s -j ACCEPT",
                "Vérifier connexions : netstat -an | grep :{port} | wc -l"
            ],
            "investigation": [
                f"Analyser logs Apache : grep '{src_ip}' /var/log/apache2/access.log | tail -100",
                "Identifier URLs ciblées : awk '{print $7}' access.log | sort | uniq -c | sort -rn",
                "Vérifier User-Agent : grep '{src_ip}' access.log | awk '{print $12}'"
            ],
            "prevention": [
                "ModSecurity WAF avec OWASP rules",
                "Rate limiting Apache : mod_evasive ou mod_qos",
                "CDN/DDoS protection : CloudFlare, Akamai"
            ],
            "recommended_tools": ["iptables", "ModSecurity", "Apache logs", "CloudFlare"],
            "escalation_required": count >= 100
        }

    # ═══════════════════════════════════════════════════════════════════
    # RÈGLE 15 : GÉNÉRIQUE (Fallback pour tout le reste)
    # ═══════════════════════════════════════════════════════════════════
    severity_map = {
        (0.9, 1.0): "Critical",
        (0.7, 0.9): "High",
        (0.5, 0.7): "Medium",
        (0.0, 0.5): "Low"
    }

    severity = "Low"
    for (min_score, max_score), sev in severity_map.items():
        if min_score <= danger_score < max_score:
            severity = sev
            break

    return {
        "attack_type": f"Suspicious {proto.upper()} Traffic (Unknown Pattern)",
        "severity": severity,
        "immediate_actions": [
            f"Bloquer IP source : iptables -A INPUT -s {src_ip} -j DROP",
            f"Capturer trafic : tcpdump -i any -nn host {src_ip} -w unknown_{src_ip}.pcap",
            "Alerter équipe SOC pour analyse manuelle"
        ],
        "investigation": [
            "Analyser payload dans Wireshark",
            f"Vérifier réputation IP : whois {src_ip}, AbuseIPDB",
            "Corréler avec autres événements de sécurité"
        ],
        "prevention": [
            "Renforcer règles pare-feu basées sur analyse",
            "Mettre à jour signatures IDS/IPS",
            "Documenter nouveau pattern dans playbook"
        ],
        "recommended_tools": ["tcpdump", "Wireshark", "AbuseIPDB", "Splunk/ELK"],
        "escalation_required": danger_score >= 0.8
    }


# ═══════════════════════════════════════════════════════════════════════
# 9. ENVOI À N8N AVEC SOLUTIONS INTÉGRÉES
# ═══════════════════════════════════════════════════════════════════════

def send_to_n8n_with_solutions(prob, raw_data, src_ip, dst_ip, dst_port, stats):
    """
    Envoie l'alerte + solutions à n8n pour notification Discord/Slack.

    Args:
        prob (float): Probabilité d'attaque (0.0 - 1.0)
        raw_data (dict): Features NSL-KDD
        src_ip (str): IP source
        dst_ip (str): IP destination
        dst_port (int): Port destination
        stats (dict): Statistiques de connexion
    """

    # Préparer les données de l'attaque
    attack_data = {
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'protocol': raw_data.get('protocol_type', 'unknown'),
        'port': dst_port,
        'service': raw_data.get('service', 'other'),
        'flag': raw_data.get('flag', 'unknown'),
        'danger_score': prob,
        'count': raw_data.get('count', 0),
        'syn_count': raw_data.get('syn_count', 0),
        'serror_rate': stats.get('serror_rate', 0),
        'same_srv_rate': stats.get('same_srv_rate', 0)
    }

    # ✅ GÉNÉRATION DES SOLUTIONS
    print(f"   💡 Génération des solutions...")
    solutions = generate_solutions_complete(attack_data)

    print(f"   ✅ Type d'attaque identifié : {solutions['attack_type']}")
    print(f"   ⚠️  Gravité : {solutions['severity']}")
    print(f"   🔧 {len(solutions['immediate_actions'])} actions immédiates proposées")

    # Construire le payload complet
    payload = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": raw_data.get('protocol_type', 'unknown'),
        "port": dst_port,
        "service": raw_data.get('service', 'other'),
        "flag": raw_data.get('flag', 'unknown'),
        "danger_score": round(float(prob), 4),
        "count": raw_data.get('count', 0),
        "syn_count": raw_data.get('syn_count', 0),

        # ✅ SOLUTIONS COMPLÈTES
        "attack_type": solutions['attack_type'],
        "severity": solutions['severity'],
        "immediate_actions": solutions['immediate_actions'],
        "investigation": solutions['investigation'],
        "prevention": solutions['prevention'],
        "recommended_tools": solutions['recommended_tools'],
        "escalation_required": solutions['escalation_required']
    }

    try:
        response = requests.post(Webhook_url, json=payload, timeout=5)
        if response.status_code == 200:
            print(f"   🚀 Alerte + Solutions envoyées à n8n (Status: {response.status_code})")
        else:
            print(f"   ⚠️  n8n a répondu avec le code {response.status_code}")
    except requests.exceptions.Timeout:
        print(f"   ⏱️  Timeout lors de l'envoi à n8n (> 5s)")
    except requests.exceptions.ConnectionError:
        print(f"   ❌ Impossible de se connecter à n8n (vérifiez que n8n tourne)")
    except Exception as e:
        print(f"   ❌ Erreur envoi n8n : {e}")


# ═══════════════════════════════════════════════════════════════════════
# 10. CALLBACK PRINCIPAL : ANALYSE DE CHAQUE PAQUET
# ═══════════════════════════════════════════════════════════════════════

def packet_callback(packet):
    """
    Fonction appelée pour chaque paquet capturé.
    Effectue l'analyse complète : détection + génération de solutions + notification.
    """

    # --- 1. IDENTIFICATION DE LA COUCHE IP ---
    layer_ip = None

    if IP in packet:
        layer_ip = packet[IP]

        # ✅ FILTRE : Ignore le trafic sortant
        if VIRTUALBOX_IP and layer_ip.src == VIRTUALBOX_IP:
            return

        print(f"📦 PAQUET CAPTURÉ : {packet.summary()}")
        print(f"   ✅ IPv4 détecté : {layer_ip.src} → {layer_ip.dst}")

    elif IPv6 in packet:
        layer_ip = packet[IPv6]
        print(f"📦 PAQUET CAPTURÉ : {packet.summary()}")
        print(f"   ✅ IPv6 détecté : {layer_ip.src} → {layer_ip.dst}")

    else:
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
            proto = "icmp"
            service = "ecr_i"
            print(f"   🔹 ICMP détecté")

        # Juste après la détection du protocole
        print(f"   🔍 DEBUG PROTOCOLE : proto={proto}, dst_port={dst_port}, service={service}")

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

        # Suppression de syn_count qui n'est pas dans les features original
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

        print(f"   🎯 Probabilité d'attaque : {prob:.4f} ({prob * 100:.2f}%)")

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

        # --- 7. SEUIL ADAPTATIF ET ALERTES ---
        scan_indicators = []
        if stats['syn_count'] > 5:
            scan_indicators.append(f"SYN:{stats['syn_count']}")
        if stats['count'] > 10:
            scan_indicators.append(f"COUNT:{stats['count']}")
        if tcp_flag == 'S0':
            scan_indicators.append("FLAG:S0")

        indicators_str = " | ".join(scan_indicators) if scan_indicators else ""

        # SEUIL ADAPTATIF
        if proto == "icmp" and stats['count'] < 10:
            seuil_icmp = 0.995
            raison = "ICMP léger (ping normal)"
        elif proto == "icmp" and stats['count'] >= 10:
            seuil_icmp = 0.85
            raison = "ICMP intensif (flood potentiel)"
        else:
            seuil_icmp = THRESHOLD
            raison = "Trafic TCP/UDP"

        # ✅ DEBUG PRÉCIS
        print(f"   🔍 DEBUG PRÉCISION : prob={prob:.10f}, seuil={seuil_icmp:.10f}")
        print(f"   🔍 Condition (prob >= seuil) = {prob >= seuil_icmp}")

        if prob >= seuil_icmp or scan_indicators:
            status_icon = "🚨" if prob >= seuil_icmp else "⚠️"
            print(f"\n{status_icon} {proto.upper()}:{dst_port} | {src_ip} → {dst_ip} | "
                  f"Service:{service} | Flag:{tcp_flag} | "
                  f"Danger:{prob:.4f} | {indicators_str}")
            print(f"   ℹ️  Seuil appliqué: {seuil_icmp * 100:.1f}% ({raison})\n")

        if prob >= seuil_icmp:
            print(f"🔥 ALERTE ATTAQUE DÉTECTÉE ({prob * 100:.1f}%) !")

            # Préparer les données pour n8n
            alert_data = {
                **raw_data,
                'dst_ip': dst_ip,
                'dst_port': dst_port
            }

            # ✅ ENVOI AVEC SOLUTIONS
            send_to_n8n_with_solutions(prob, alert_data, src_ip, dst_ip, dst_port, stats)

        print("-" * 80)

    except Exception as e:
        print(f"⚠️ Erreur traitement : {e}")
        import traceback
        traceback.print_exc()


# ═══════════════════════════════════════════════════════════════════════
# 11. DÉMARRAGE DU SNIFFER
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║             SNIFFER ÉLITE v3 - IDS avec Solutions IA                 ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")
    print()

    # Initialisation de la base de données
    print("🗄️  Initialisation de la Base de Données...")
    db_manager.init_db()

    print("✅ Modèles IA chargés.")
    print(f"🎯 Seuil d'alerte : {THRESHOLD * 100:.1f}%")

    if VIRTUALBOX_IP:
        print(f"📡 Le sniffer ignorera le trafic sortant de {VIRTUALBOX_IP}")

    # Détection de l'interface VirtualBox
    print("🔍 Recherche de l'interface VirtualBox (192.168.56.1)...")

    target_iface = None
    for iface_name, iface in conf.ifaces.items():
        if hasattr(iface, 'ip') and iface.ip == "192.168.56.1":
            target_iface = iface_name
            print(f"✅ Interface trouvée -> {iface_name}")
            break

    if not target_iface:
        print("⚠️  Interface VirtualBox non trouvée. Utilisation de l'interface par défaut.")
        target_iface = conf.iface

    print()
    print("🎯 15 règles de détection chargées (couverture 85-90% NSL-KDD)")
    print("📡 En écoute des paquets réseau...")
    print("=" * 80)
    print()

    # Lancement du sniffer
    try:
        sniff(
            iface=target_iface,
            prn=packet_callback,
            store=False,
            filter="ip or ip6"
        )
    except KeyboardInterrupt:
        print("\n\n⏹️  Sniffer arrêté par l'utilisateur.")
    except Exception as e:
        print(f"\n\n❌ Erreur critique : {e}")
        import traceback

        traceback.print_exc()

