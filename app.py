from flask import Flask, render_template_string
from scapy.all import ARP, Ether, srp
import requests
import socket
import os
import datetime
import threading
import time
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)
appareils_connus = {}
derniers_appareils = []

EMAIL = "sevanvo7@gmail.com"
MOT_DE_PASSE = "xrlnscdlyzrlaiev"

def get_fabricant(mac):
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        return r.text if r.status_code == 200 else "Inconnu"
    except:
        return "Inconnu"

def ping(ip):
    return "🟢 Actif" if os.system(f"ping -n 1 -w 500 {ip} > nul 2>&1") == 0 else "🔴 Inactif"

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Inconnu"

def envoyer_alerte(ip, mac, fabricant, hostname):
    try:
        msg = MIMEText(f"""
⚠ NOUVEL APPAREIL DÉTECTÉ

IP : {ip}
MAC : {mac}
Fabricant : {fabricant}
Nom : {hostname}
Heure : {datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")}
        """)
        msg['Subject'] = f"⚠ Blue Team — Nouvel appareil : {ip}"
        msg['From'] = EMAIL
        msg['To'] = EMAIL
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as s:
            s.login(EMAIL, MOT_DE_PASSE)
            s.send_message(msg)
    except:
        pass

def scanner():
    global derniers_appareils
    while True:
        arp = ARP(pdst="192.168.10.0/24")
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        resultat = srp(ether/arp, timeout=3, verbose=0)[0]
        appareils = []
        for _, reponse in resultat:
            ip = reponse.psrc
            mac = reponse.hwsrc
            fabricant = get_fabricant(mac)
            hostname = get_hostname(ip)
            nouveau = mac not in appareils_connus
            if nouveau:
                envoyer_alerte(ip, mac, fabricant, hostname)
                appareils_connus[mac] = ip
            appareils.append({
                'ip': ip,
                'mac': mac,
                'fabricant': fabricant,
                'hostname': hostname,
                'ping': ping(ip),
                'statut': 'NOUVEAU' if nouveau else 'Connu'
            })
        derniers_appareils = appareils
        time.sleep(30)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Blue Team Scanner</title>
    <meta http-equiv="refresh" content="30">
    <style>
        body { background: #0a0a0a; color: #00ff88; font-family: monospace; padding: 20px; }
        h1 { color: #00ccff; text-align: center; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background: #111; color: #00ccff; padding: 10px; border: 1px solid #222; }
        td { padding: 10px; border: 1px solid #222; }
        tr:hover { background: #111; }
        .nouveau { color: #ff4444; font-weight: bold; }
        .connu { color: #00ff88; }
        .actif { color: #00ff88; }
        .inactif { color: #ff4444; }
        .header { text-align: center; color: #555; margin-bottom: 20px; }
    </style>
</head>
<body>
    <h1>🔵 BLUE TEAM — SCANNER RÉSEAU</h1>
    <p class="header">Dernière mise à jour : {{ now }} — {{ count }} appareil(s) détecté(s)</p>
    <table>
        <tr>
            <th>IP</th>
            <th>MAC</th>
            <th>Fabricant</th>
            <th>Nom d'hôte</th>
            <th>Ping</th>
            <th>Statut</th>
        </tr>
        {% for a in appareils %}
        <tr>
            <td>{{ a.ip }}</td>
            <td>{{ a.mac }}</td>
            <td>{{ a.fabricant }}</td>
            <td>{{ a.hostname }}</td>
            <td class="{{ 'actif' if '🟢' in a.ping else 'inactif' }}">{{ a.ping }}</td>
            <td class="{{ 'nouveau' if a.statut == 'NOUVEAU' else 'connu' }}">{{ a.statut }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML,
        appareils=derniers_appareils,
        now=datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        count=len(derniers_appareils)
    )

t = threading.Thread(target=scanner, daemon=True)
t.start()

app.run(host='0.0.0.0', port=5000, debug=False)