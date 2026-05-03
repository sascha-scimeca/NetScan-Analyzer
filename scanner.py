import xml.etree.ElementTree as ET

# Analyse simple des ports
def analyze_port(port):
    risky_ports = {
        "445": "CRITIQUE - SMB (risque ransomware)",
        "139": "NetBIOS ancien (risqué)",
        "135": "RPC Windows (surface d'attaque)",
        "22": "SSH (vérifier mots de passe)",
        "3389": "RDP (accès distant)",
        "80": "HTTP (web service)",
        "443": "HTTPS (web sécurisé)"
    }
    return risky_ports.get(port, "OK / standard")

# Score de risque
def risk_score(port):
    scores = {
        "445": 5,
        "139": 4,
        "135": 4,
        "3389": 4,
        "22": 2,
        "80": 1,
        "443": 1
    }
    return scores.get(port, 0)


# Chargement du fichier Nmap XML
tree = ET.parse("scan.xml")
root = tree.getroot()

print("\n=== ANALYSE RESEAU ===\n")

for host in root.findall("host"):
    ip = host.find("address").get("addr")

    print(f"\nMachine: {ip}")

    total_score = 0
    open_ports = host.findall(".//port")

    if not open_ports:
        print("  Aucun port détecté")
        continue

    for port in open_ports:
        state = port.find("state").get("state")

        if state == "open":
            port_id = port.get("portid")
            service = port.find("service").get("name")

            analysis = analyze_port(port_id)
            score = risk_score(port_id)
            total_score += score

            print(f"  Port {port_id} -> {service} -> {analysis}")

    # Résumé sécurité machine
    if total_score >= 8:
        level = "RISQUE ÉLEVÉ"
    elif total_score >= 4:
        level = "RISQUE MODÉRÉ"
    else:
        level = "FAIBLE RISQUE"

    print(f"  -> Score sécurité : {total_score} ({level})")