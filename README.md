# 🔵 Blue Team Network Scanner

Outil de surveillance réseau développé en Python.

## Fonctionnalités
- Scan automatique du réseau local toutes les 30 secondes
- Identification des appareils via adresse IP et MAC
- Détection des nouveaux appareils inconnus (alerte ⚠)
- Identification du fabricant via API macvendors
- Logs automatiques sauvegardés dans scan_log.txt
- Affichage coloré en temps réel dans le terminal

## Technologies
- Python 3.14
- Scapy (scan réseau ARP)
- Colorama (affichage couleur)
- Requests (API fabricant MAC)
- Npcap (driver réseau Windows)

## Contexte
Projet personnel développé dans le cadre de ma préparation au BTS CIEL option Cybersécurité (Ensitech Cergy, rentrée 2026). Objectif : cartographier un réseau local et détecter les intrusions en temps réel — compétence clé Blue Team.

## Utilisation
```bash
py scanner.py
```

## Auteur
Sevan Vienney-Osmandjian