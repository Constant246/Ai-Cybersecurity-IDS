import requests

url = "http://localhost:5678/webhook-test/ff8d5a85-c0be-4ef2-857d-8471667576aa"

fake_alert = {
    "event_type": "TEST_ALERT",
    "source_ip": "192.168.1.66",
    "hazard_score": 0.99,
    "protocol": "tcp",
    "service": "http",
    "bytes": 50000,
    "density_count": 150
}

try:
    r = requests.post(url, json=fake_alert)
    print(f"Statut : {r.status_code} - Réponse : {r.text}")
except Exception as e:
    print(f"Erreur : {e}")