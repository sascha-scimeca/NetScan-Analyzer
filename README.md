# NetScan-Analyzer
Network Scanner & Port Analyzer
# Description

Ce projet est un outil simple de scan réseau et d’analyse des services actifs basé sur Nmap.

Il permet de :

scanner un réseau local

identifier les machines connectées

détecter les ports ouverts

analyser les services actifs

attribuer un score de risque de sécurité

# Fonctionnalités

Scan du réseau local

Détection des machines actives

Identification des ports ouverts

Détection des services (HTTP, SSH, SMB, etc.)

Analyse basique des risques de sécurité

Score de sécurité par machine

Génération de sortie lisible en terminal

# Analyse de sécurité intégrée

Le projet attribue des niveaux de risque selon les ports détectés :

Risque élevé : SMB (445), NetBIOS (139), RPC (135), RDP (3389)
Risque modéré : SSH (22)
Faible risque : HTTP/HTTPS (80/443)
Standard : autres services
Technologies utilisées
Python 3
XML parsing (xml.etree.ElementTree)
Nmap (scan réseau)
Système Windows

# Utilisation
1. Lancer un scan réseau
nmap -sT -sV -oX scan.xml 192.168.1.0/24
2. Lancer le script Python
python scanner.py
Exemple de sortie
Machine: 192.168.1.149
  Port 445 -> microsoft-ds -> CRITIQUE - SMB (risque ransomware)
  Port 139 -> netbios-ssn -> NetBIOS ancien (risqué)
  -> Score sécurité : 9 (RISQUE ÉLEVÉ)
   
# Objectif du projet

Ce projet a été conçu pour apprendre :

le scan réseau
l’analyse de services réseau
la détection de surfaces d’attaque
les bases de la cybersécurité offensive et défensive
