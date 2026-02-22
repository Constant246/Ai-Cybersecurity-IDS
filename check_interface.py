from scapy.all import get_if_list, get_if_hwaddr, conf

print("🔍 RECHERCHE DES INTERFACES RÉSEAUX DISPONIBLES...")
print("-" * 60)

# Affiche toutes les interfaces vues par Scapy
for face in get_if_list():
    try:
        mac = get_if_hwaddr(face)
        print(f"Nom : {face} \t (MAC: {mac})")
    except:
        print(f"Nom : {face} \t (Erreur lecture MAC)")

print("-" * 60)


