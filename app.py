from flask import Flask, render_template_string, request, redirect, session, jsonify, Response
from scapy.all import ARP, Ether, srp, send, sniff, IP as ScapyIP
import requests
import socket
import os
import json
import csv
import io
import sqlite3
import datetime
import threading
import time
import smtplib
import psutil
import schedule
import whois
import dns.resolver
from email.mime.text import MIMEText
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.lib.pagesizes import A4

app = Flask(__name__)
app.secret_key = "blueteam2026"

EMAIL = "sevanvo7@gmail.com"
MOT_DE_PASSE_EMAIL = "xrlnscdlyzrlaiev"
MOT_DE_PASSE_DASHBOARD = "blueteam2026"
TELEGRAM_TOKEN = "8800824706:AAGh6KgKCtpD1gr-ItC79LdET52wNUo0HvI"
TELEGRAM_CHAT_ID = "5455515480"
RESEAU = "192.168.10.0/24"
GATEWAY = "192.168.10.1"

appareils_connus = {}
derniers_appareils = []
historique = []
ip_bloquees = []
ip_deconnectees = []
logs = []
nouveaux_appareils = []
noms_personnalises = {}
whitelist = []
blacklist_auto = {}
stats = {"total_scans": 0, "total_blocages": 0, "start_time": datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")}
timeline = []
heure_debut = datetime.datetime.now()
arp_suspects = 0
gateway_mac_connu = None
scan_precedent = []
paquets_captures = []

PORTS_CONNUS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3389: "RDP", 8080: "HTTP-Alt"
}

OS_SIGNATURES = {
    "Windows": ["Microsoft", "DESKTOP", "WIN"],
    "Apple": ["Apple", "iPhone", "iPad", "MacBook"],
    "Android": ["Android", "Samsung", "Xiaomi", "Huawei"],
    "Linux": ["Linux", "Ubuntu", "Raspberry"],
    "Routeur": ["Cudy", "TP-Link", "Livebox", "Freebox", "SFR"]
}

IOT_SIGNATURES = ["camera", "cam", "smart", "tv", "alexa", "echo", "nest", "ring", "philips", "hue", "sonos"]
TOR_EXIT_NODES = set()
VPN_SIGNATURES = ["vpn", "tunnel", "mullvad", "nordvpn", "expressvpn", "proton"]

def init_db():
    conn = sqlite3.connect("blueteam.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS appareils (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT, mac TEXT, fabricant TEXT, hostname TEXT,
        os TEXT, ports TEXT, statut TEXT, timestamp TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS blocages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT, action TEXT, timestamp TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        count INTEGER, timestamp TEXT
    )""")
    conn.commit()
    conn.close()

def sauvegarder_appareil(a):
    conn = sqlite3.connect("blueteam.db")
    c = conn.cursor()
    c.execute("INSERT INTO appareils (ip,mac,fabricant,hostname,os,ports,statut,timestamp) VALUES (?,?,?,?,?,?,?,?)",
        (a['ip'], a['mac'], a['fabricant'], a['hostname'], a['os'], a['ports'], a['statut'],
         datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")))
    conn.commit()
    conn.close()

def sauvegarder_scan(count):
    conn = sqlite3.connect("blueteam.db")
    c = conn.cursor()
    c.execute("INSERT INTO scans (count,timestamp) VALUES (?,?)",
        (count, datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")))
    conn.commit()
    conn.close()

def sauvegarder_blocage(ip, action):
    conn = sqlite3.connect("blueteam.db")
    c = conn.cursor()
    c.execute("INSERT INTO blocages (ip,action,timestamp) VALUES (?,?,?)",
        (ip, action, datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")))
    conn.commit()
    conn.close()

def get_historique_blocages():
    conn = sqlite3.connect("blueteam.db")
    c = conn.cursor()
    c.execute("SELECT * FROM blocages ORDER BY id DESC LIMIT 50")
    rows = c.fetchall()
    conn.close()
    return rows

def get_historique_scans():
    conn = sqlite3.connect("blueteam.db")
    c = conn.cursor()
    c.execute("SELECT count, timestamp FROM scans ORDER BY id DESC LIMIT 20")
    rows = c.fetchall()
    conn.close()
    return rows

def telegram_alert(message):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        requests.post(url, data={"chat_id": TELEGRAM_CHAT_ID, "text": message}, timeout=5)
    except:
        pass

def get_fabricant(mac):
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        return r.text[:30] if r.status_code == 200 else "Inconnu"
    except:
        return "Inconnu"

def ping(ip):
    return "🟢" if os.system(f"ping -n 1 -w 500 {ip} > nul 2>&1") == 0 else "🔴"

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Inconnu"

def scan_ports(ip):
    ports_ouverts = []
    for port, nom in PORTS_CONNUS.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            if s.connect_ex((ip, port)) == 0:
                ports_ouverts.append(f"{port}/{nom}")
            s.close()
        except:
            pass
    return ports_ouverts if ports_ouverts else ["Aucun"]

def detecter_os(fabricant, hostname):
    texte = (fabricant + " " + hostname).upper()
    for os_type, sigs in OS_SIGNATURES.items():
        for sig in sigs:
            if sig.upper() in texte:
                return os_type
    return "Inconnu"

def detecter_iot(fabricant, hostname):
    texte = (fabricant + " " + hostname).lower()
    return any(sig in texte for sig in IOT_SIGNATURES)

def detecter_mac_spoofing(mac):
    if mac[1] in ['2', '6', 'a', 'e']:
        return True
    return False

def detecter_vpn(fabricant, hostname):
    texte = (fabricant + " " + hostname).lower()
    return any(sig in texte for sig in VPN_SIGNATURES)

def geoip(ip):
    try:
        if ip.startswith(("192.168", "10.", "172.")):
            return "Réseau local"
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=country,city,isp,proxy,hosting", timeout=3)
        if r.status_code == 200:
            d = r.json()
            return f"{d.get('city','?')}, {d.get('country','?')} — {d.get('isp','?')}"
        return "Inconnu"
    except:
        return "Inconnu"

def whois_lookup(ip):
    try:
        if ip.startswith(("192.168", "10.", "172.")):
            return "IP locale"
        w = whois.whois(ip)
        return str(w.org)[:40] if w.org else "Inconnu"
    except:
        return "Inconnu"

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Inconnu"

def check_tor(ip):
    return ip in TOR_EXIT_NODES

def banner_grab(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, port))
        banner = s.recv(1024).decode(errors='ignore').strip()
        s.close()
        return banner[:60] if banner else ""
    except:
        return ""

def comparer_scans(ancien, nouveau):
    ips_ancien = {a['ip'] for a in ancien}
    ips_nouveau = {a['ip'] for a in nouveau}
    apparus = ips_nouveau - ips_ancien
    disparus = ips_ancien - ips_nouveau
    return list(apparus), list(disparus)

def score_menace(a):
    score = 0
    if a['statut'] == 'NOUVEAU': score += 30
    if a['os'] == 'Inconnu': score += 10
    if '22/SSH' in a['ports']: score += 20
    if '23/Telnet' in a['ports']: score += 30
    if '3389/RDP' in a['ports']: score += 20
    if a.get('mac_aleatoire'): score += 25
    if a['fabricant'] == 'Inconnu': score += 15
    if a.get('vpn'): score += 15
    if a.get('tor'): score += 40
    return min(score, 100)

def couleur_score(score):
    if score >= 70: return "#ff4444"
    if score >= 40: return "#ff8800"
    return "#00ff88"

def ajouter_log(message):
    now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    logs.append(f"[{now}] {message}")
    if len(logs) > 200:
        logs.pop(0)

def envoyer_alerte_email(ip, mac, fabricant, hostname):
    try:
        msg = MIMEText(f"⚠ NOUVEL APPAREIL\nIP: {ip}\nMAC: {mac}\nFabricant: {fabricant}\nNom: {hostname}")
        msg['Subject'] = f"⚠ Blue Team — {ip}"
        msg['From'] = EMAIL
        msg['To'] = EMAIL
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as s:
            s.login(EMAIL, MOT_DE_PASSE_EMAIL)
            s.send_message(msg)
    except:
        pass

def bloquer_ip(ip):
    os.system(f'netsh advfirewall firewall add rule name="BLOCK_{ip}" dir=in action=block remoteip={ip}')
    os.system(f'netsh advfirewall firewall add rule name="BLOCK_{ip}" dir=out action=block remoteip={ip}')
    ajouter_log(f"🚫 BLOQUÉ : {ip}")
    sauvegarder_blocage(ip, "BLOQUÉE")
    stats["total_blocages"] += 1
    telegram_alert(f"🚫 IP bloquée : {ip}")

def debloquer_ip(ip):
    os.system(f'netsh advfirewall firewall delete rule name="BLOCK_{ip}"')
    ajouter_log(f"✅ DÉBLOQUÉ : {ip}")
    sauvegarder_blocage(ip, "DÉBLOQUÉE")

def arp_spoof(ip_cible, duree=300):
    def _spoof():
        try:
            pkt1 = ARP(op=2, pdst=ip_cible, psrc=GATEWAY)
            pkt2 = ARP(op=2, pdst=GATEWAY, psrc=ip_cible)
            fin = time.time() + duree
            while time.time() < fin and ip_cible in ip_deconnectees:
                send(pkt1, verbose=0)
                send(pkt2, verbose=0)
                time.sleep(1)
        except:
            pass
    threading.Thread(target=_spoof, daemon=True).start()

def charger_tor_exit_nodes():
    global TOR_EXIT_NODES
    try:
        r = requests.get("https://check.torproject.org/torbulkexitlist", timeout=10)
        if r.status_code == 200:
            TOR_EXIT_NODES = set(r.text.strip().split('\n'))
            ajouter_log(f"🧅 {len(TOR_EXIT_NODES)} nœuds Tor chargés")
    except:
        pass

def capturer_paquets():
    def _capture(pkt):
        global arp_suspects
        if pkt.haslayer(ARP):
            if pkt[ARP].op == 2:
                arp_suspects += 1
                if arp_suspects % 10 == 0:
                    ajouter_log(f"⚠ {arp_suspects} paquets ARP suspects détectés")
    try:
        sniff(filter="arp", prn=_capture, store=0, timeout=25)
    except:
        pass

def rapport_hebdo():
    try:
        apparus, disparus = comparer_scans(scan_precedent, derniers_appareils)
        msg = MIMEText(f"""
📊 RAPPORT HEBDOMADAIRE BLUE TEAM

Appareils : {len(derniers_appareils)}
Total scans : {stats['total_scans']}
Total blocages : {stats['total_blocages']}
Paquets ARP suspects : {arp_suspects}
Apparus cette semaine : {', '.join(apparus) if apparus else 'Aucun'}
Disparus cette semaine : {', '.join(disparus) if disparus else 'Aucun'}
Uptime : depuis {stats['start_time']}

Derniers logs :
{chr(10).join(logs[-10:])}
        """)
        msg['Subject'] = "📊 Blue Team — Rapport hebdomadaire"
        msg['From'] = EMAIL
        msg['To'] = EMAIL
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as s:
            s.login(EMAIL, MOT_DE_PASSE_EMAIL)
            s.send_message(msg)
        ajouter_log("📊 Rapport hebdo envoyé")
    except:
        pass

def scanner():
    global derniers_appareils, historique, nouveaux_appareils, gateway_mac_connu, scan_precedent
    while True:
        heure = datetime.datetime.now().hour
        intervalle = 60 if (heure >= 23 or heure < 7) else 30

        try:
            resultat = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=RESEAU), timeout=3, verbose=0)[0]
        except:
            time.sleep(intervalle)
            continue

        scan_precedent = derniers_appareils.copy()
        appareils = []
        nouveaux_appareils = []

        for _, reponse in resultat:
            ip = reponse.psrc
            mac = reponse.hwsrc
            fabricant = get_fabricant(mac)
            hostname = get_hostname(ip)
            os_detecte = detecter_os(fabricant, hostname)
            ports = scan_ports(ip)
            mac_aleatoire = detecter_mac_spoofing(mac)
            iot = detecter_iot(fabricant, hostname)
            vpn = detecter_vpn(fabricant, hostname)
            tor = check_tor(ip)
            nom = noms_personnalises.get(ip, "")
            nouveau = mac not in appareils_connus

            # Détection changement MAC gateway
            if ip == GATEWAY:
                if gateway_mac_connu and mac != gateway_mac_connu:
                    ajouter_log(f"🚨 ALERTE : MAC gateway changée ! {gateway_mac_connu} → {mac}")
                    telegram_alert(f"🚨 MAC GATEWAY CHANGÉE\nAncienne: {gateway_mac_connu}\nNouvelle: {mac}")
                gateway_mac_connu = mac

            a = {
                'ip': ip, 'mac': mac, 'fabricant': fabricant,
                'hostname': hostname, 'ping': ping(ip),
                'statut': 'NOUVEAU' if nouveau else 'Connu',
                'bloque': ip in ip_bloquees,
                'deconnecte': ip in ip_deconnectees,
                'ports': ', '.join(ports),
                'os': os_detecte, 'iot': iot,
                'mac_aleatoire': mac_aleatoire,
                'vpn': vpn, 'tor': tor,
                'nom': nom,
                'whitelist': ip in whitelist,
                'geo': geoip(ip),
                'banners': {},
            }

            # Banner grab ports ouverts
            for p in [80, 22, 21, 23]:
                b = banner_grab(ip, p)
                if b:
                    a['banners'][p] = b

            a['score'] = score_menace(a)
            a['couleur_score'] = couleur_score(a['score'])

            if nouveau:
                appareils_connus[mac] = ip
                nouveaux_appareils.append(ip)
                if ip not in whitelist:
                    envoyer_alerte_email(ip, mac, fabricant, hostname)
                    telegram_alert(f"⚠ NOUVEL APPAREIL\nIP: {ip}\nMAC: {mac}\nFabricant: {fabricant}\nOS: {os_detecte}\nScore: {a['score']}/100\nPorts: {', '.join(ports)}")
                ajouter_log(f"⚠ NOUVEAU — {ip} | {fabricant} | {os_detecte} | Score: {a['score']}/100")
                sauvegarder_appareil(a)
                timeline.append({'heure': datetime.datetime.now().strftime("%H:%M:%S"), 'event': f"Connexion: {ip} ({os_detecte})", 'type': 'connexion'})

                blacklist_auto[ip] = blacklist_auto.get(ip, 0) + 1
                if blacklist_auto[ip] >= 3 and ip not in ip_bloquees and ip not in whitelist:
                    ip_bloquees.append(ip)
                    bloquer_ip(ip)
                    ajouter_log(f"🤖 AUTO-BLOQUÉ : {ip}")

            appareils.append(a)

        # Détection appareils disparus
        ips_nouveau = {a['ip'] for a in appareils}
        for a_ancien in scan_precedent:
            if a_ancien['ip'] not in ips_nouveau:
                timeline.append({'heure': datetime.datetime.now().strftime("%H:%M:%S"), 'event': f"Déconnexion: {a_ancien['ip']}", 'type': 'deconnexion'})

        derniers_appareils = sorted(appareils, key=lambda x: x['score'], reverse=True)
        historique.append({'heure': datetime.datetime.now().strftime("%H:%M:%S"), 'count': len(appareils)})
        if len(historique) > 50: historique.pop(0)
        if len(timeline) > 100: timeline.pop(0)

        stats["total_scans"] += 1
        sauvegarder_scan(len(appareils))
        ajouter_log(f"🔍 Scan #{stats['total_scans']} — {len(appareils)} appareil(s) | ARP suspects: {arp_suspects}")
        time.sleep(intervalle)

schedule.every().monday.at("08:00").do(rapport_hebdo)
schedule.every(6).hours.do(charger_tor_exit_nodes)

def run_schedule():
    while True:
        schedule.run_pending()
        time.sleep(60)

LOGIN_HTML = """<!DOCTYPE html><html><head><title>Blue Team</title>
<style>body{background:#0a0a0a;color:#00ff88;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.box{background:#111;border:1px solid #222;padding:40px;border-radius:5px;text-align:center;min-width:300px}
h1{color:#00ccff}
input{background:#0a0a0a;border:1px solid #333;color:#00ff88;padding:10px;width:200px;font-family:monospace;margin:10px auto;display:block}
button{background:#00ccff;color:black;border:none;padding:10px 30px;cursor:pointer;font-family:monospace;font-weight:bold;margin-top:10px}
.erreur{color:#ff4444}</style></head><body>
<div class="box"><h1>🔵 BLUE TEAM</h1><p>Accès sécurisé</p>
{% if erreur %}<p class="erreur">❌ Mot de passe incorrect</p>{% endif %}
<form method="POST"><input type="password" name="password" placeholder="Mot de passe">
<button type="submit">Connexion</button></form></div></body></html>"""

HTML = """<!DOCTYPE html><html><head><title>Blue Team Scanner</title>
<meta http-equiv="refresh" content="30">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
*{box-sizing:border-box}
body{background:#0a0a0a;color:#00ff88;font-family:monospace;padding:20px;margin:0}
h1{color:#00ccff;text-align:center;font-size:1.4em}
h2{color:#00ccff;margin-top:25px;font-size:1em}
table{width:100%;border-collapse:collapse;margin-top:10px;font-size:10px}
th{background:#111;color:#00ccff;padding:6px;border:1px solid #222}
td{padding:5px 6px;border:1px solid #1a1a1a;vertical-align:middle}
tr:hover{background:#0f0f0f}
.nouveau{color:#ff4444;font-weight:bold}.connu{color:#00ff88}
.actif{color:#00ff88}.inactif{color:#ff4444}
.header{text-align:center;color:#555;font-size:10px;margin-bottom:8px}
.chart-container{width:100%;max-width:800px;margin:15px auto}
.btn{border:none;padding:3px 6px;cursor:pointer;border-radius:3px;font-family:monospace;font-size:9px;margin:1px}
.btn-bloquer{background:#ff4444;color:white}
.btn-debloquer{background:#00ff88;color:black}
.btn-deconnecter{background:#ff8800;color:black}
.btn-reconnecter{background:#00ccff;color:black}
.btn-whitelist{background:#aa88ff;color:black}
.btn-nom{background:#444;color:white}
.btn-export{background:#333;color:#00ff88;border:1px solid #555;padding:4px 9px;text-decoration:none;font-family:monospace;font-size:10px;margin:2px;display:inline-block}
.bloque{background:#1a0000}.deconnecte{background:#1a0a00}.whitelisted{background:#001500}
.iot{color:#ff88ff}.mac-rand{color:#ffff00}.tor-badge{color:#9944ff}.vpn-badge{color:#44aaff}
.logs{background:#050505;border:1px solid #1a1a1a;padding:8px;max-height:200px;overflow-y:auto;margin-top:8px}
.log-line{color:#444;font-size:9px;margin:1px 0;padding:1px 3px}
.log-line.alerte{color:#ff4444}.log-line.action{color:#ff8800}.log-line.scan{color:#00aacc}
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:10px 0}
.stat-box{background:#111;border:1px solid #1a1a1a;padding:12px;text-align:center;border-radius:4px}
.stat-val{font-size:1.6em;color:#00ccff;font-weight:bold}
.stat-label{font-size:9px;color:#444;margin-top:3px}
.deconnexion{background:#222;color:#00ff88;border:1px solid #444;padding:4px 12px;cursor:pointer;font-family:monospace;font-size:10px}
.search-bar{background:#111;border:1px solid #333;color:#00ff88;padding:6px;font-family:monospace;width:220px;font-size:10px}
.score-bar{height:5px;border-radius:3px;margin-top:2px;min-width:3px}
.timeline-item{font-size:9px;color:#444;margin:1px 0;padding:2px 4px;border-left:2px solid #222}
.timeline-item.connexion{border-left-color:#00ff88;color:#00aa55}
.timeline-item.deconnexion{border-left-color:#ff4444;color:#aa3333}
select{background:#111;border:1px solid #333;color:#00ff88;padding:4px;font-family:monospace;font-size:10px}
.nav{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center}
.banner-info{color:#888;font-size:9px;font-style:italic}
.geo-info{color:#4488aa;font-size:9px}
.comparison-box{background:#111;border:1px solid #222;padding:10px;margin:10px 0;font-size:10px}
.apparu{color:#00ff88}.disparu{color:#ff4444}
@media(max-width:768px){.stats-grid{grid-template-columns:repeat(2,1fr)}}
</style></head><body>

<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;margin-bottom:5px">
<h1 style="margin:0">🔵 BLUE TEAM — SCANNER RÉSEAU</h1>
<form method="POST" action="/logout"><button class="deconnexion">🔓 Déco</button></form>
</div>
<p class="header">{{ now }} — {{ count }} appareil(s) — Scan #{{ stats.total_scans }} — ⏱ {{ uptime }} — ARP suspects: {{ arp_suspects }}</p>

<div class="stats-grid">
<div class="stat-box"><div class="stat-val">{{ count }}</div><div class="stat-label">Appareils</div></div>
<div class="stat-box"><div class="stat-val" style="color:#ff4444">{{ stats.total_blocages }}</div><div class="stat-label">Blocages</div></div>
<div class="stat-box"><div class="stat-val" style="color:#00ccff">{{ stats.total_scans }}</div><div class="stat-label">Scans</div></div>
<div class="stat-box"><div class="stat-val" style="color:#aa88ff">{{ nouveaux_count }}</div><div class="stat-label">Nouveaux</div></div>
</div>

{% if apparus or disparus %}
<div class="comparison-box">
📊 Comparaison avec scan précédent —
{% if apparus %}<span class="apparu">Apparus: {{ apparus|join(', ') }}</span>{% endif %}
{% if disparus %} | <span class="disparu">Disparus: {{ disparus|join(', ') }}</span>{% endif %}
</div>
{% endif %}

<div class="nav">
<input class="search-bar" type="text" id="search" placeholder="🔍 IP, MAC, OS, fabricant..." onkeyup="filtrer()">
<select onchange="trierTable(this.value)">
<option value="">Trier...</option>
<option value="score">Score</option>
<option value="ip">IP</option>
<option value="os">OS</option>
<option value="statut">Statut</option>
</select>
<a class="btn-export" href="/export/csv">📥 CSV</a>
<a class="btn-export" href="/export/pdf">📄 PDF</a>
<a class="btn-export" href="/export/json">{ } JSON</a>
<a class="btn-export" href="/api/appareils" target="_blank">🔌 API</a>
</div>

<table id="tableau">
<tr><th>Score</th><th>IP</th><th>Nom</th><th>MAC</th><th>Fabricant</th><th>Hôte</th><th>OS</th><th>Géo</th><th>Ports / Banners</th><th>Ping</th><th>Statut</th><th>Actions</th></tr>
{% for a in appareils %}
<tr class="{{ 'bloque' if a.bloque else 'deconnecte' if a.deconnecte else 'whitelisted' if a.whitelist else '' }}"
    data-ip="{{ a.ip }}" data-mac="{{ a.mac }}" data-os="{{ a.os }}" data-statut="{{ a.statut }}" data-fabricant="{{ a.fabricant }}">
<td>
<div style="color:{{ a.couleur_score }};font-weight:bold;font-size:11px">{{ a.score }}/100</div>
<div class="score-bar" style="background:{{ a.couleur_score }};width:{{ a.score }}%"></div>
</td>
<td style="font-size:10px">{{ a.ip }}</td>
<td style="color:#888;font-size:9px">{{ a.nom if a.nom else '—' }}</td>
<td style="font-size:9px">
{{ a.mac }}
{% if a.mac_aleatoire %}<span class="mac-rand" title="MAC aléatoire">⚠</span>{% endif %}
</td>
<td style="font-size:10px">{{ a.fabricant }}</td>
<td style="font-size:9px">{{ a.hostname }}</td>
<td style="font-size:10px">
{{ a.os }}
{% if a.iot %}<span class="iot"> 📡</span>{% endif %}
{% if a.vpn %}<span class="vpn-badge"> VPN</span>{% endif %}
{% if a.tor %}<span class="tor-badge"> TOR🧅</span>{% endif %}
</td>
<td class="geo-info">{{ a.geo }}</td>
<td style="font-size:9px">
<span style="color:#ff8800">{{ a.ports }}</span>
{% for port, banner in a.banners.items() %}
<div class="banner-info">{{ port }}: {{ banner }}</div>
{% endfor %}
</td>
<td>{{ a.ping }}</td>
<td class="{{ 'nouveau' if a.statut == 'NOUVEAU' else 'connu' }}" style="font-size:10px">{{ a.statut }}</td>
<td>
{% if a.bloque %}
<form method="POST" action="/debloquer" style="display:inline"><input type="hidden" name="ip" value="{{ a.ip }}"><button class="btn btn-debloquer">✅</button></form>
{% else %}
<form method="POST" action="/bloquer" style="display:inline"><input type="hidden" name="ip" value="{{ a.ip }}"><button class="btn btn-bloquer">🚫</button></form>
{% endif %}
{% if a.deconnecte %}
<form method="POST" action="/reconnecter" style="display:inline"><input type="hidden" name="ip" value="{{ a.ip }}"><button class="btn btn-reconnecter">🔌</button></form>
{% else %}
<form method="POST" action="/deconnecter" style="display:inline"><input type="hidden" name="ip" value="{{ a.ip }}"><button class="btn btn-deconnecter">⚡</button></form>
{% endif %}
{% if not a.whitelist %}
<form method="POST" action="/whitelist" style="display:inline"><input type="hidden" name="ip" value="{{ a.ip }}"><button class="btn btn-whitelist">✓</button></form>
{% endif %}
<form method="POST" action="/renommer" style="display:inline">
<input type="hidden" name="ip" value="{{ a.ip }}">
<input type="text" name="nom" placeholder="nom" style="width:50px;background:#0a0a0a;border:1px solid #333;color:#00ff88;font-family:monospace;font-size:9px;padding:2px">
<button class="btn btn-nom">✏</button>
</form>
</td>
</tr>
{% endfor %}
</table>

<div class="chart-container"><canvas id="g"></canvas></div>

<h2>📅 Timeline connexions</h2>
<div class="logs">
{% for t in timeline[-30:]|reverse %}
<div class="timeline-item {{ t.type }}">{{ t.heure }} — {{ t.event }}</div>
{% endfor %}
</div>

<h2>🔒 Historique blocages (SQLite)</h2>
<div class="logs">
{% for b in blocages %}
<div class="log-line action">[{{ b[3] }}] {{ b[2] }} — {{ b[1] }}</div>
{% endfor %}
</div>

<h2>📋 Logs temps réel</h2>
<div class="logs">
{% for log in logs[-100:]|reverse %}
<div class="log-line {% if '⚠' in log or '🚨' in log %}alerte{% elif '🚫' in log or '⚡' in log or '🤖' in log %}action{% elif '🔍' in log %}scan{% endif %}">{{ log }}</div>
{% endfor %}
</div>

<script>
const ctx=document.getElementById('g').getContext('2d');
new Chart(ctx,{type:'line',data:{labels:{{ labels|safe }},datasets:[{label:'Appareils',data:{{ data|safe }},borderColor:'#00ccff',backgroundColor:'rgba(0,204,255,0.08)',borderWidth:2,pointBackgroundColor:'#00ff88',tension:0.4,fill:true}]},
options:{responsive:true,plugins:{legend:{labels:{color:'#00ff88'}}},scales:{x:{ticks:{color:'#444'},grid:{color:'#0f0f0f'}},y:{ticks:{color:'#444'},grid:{color:'#0f0f0f'},beginAtZero:true}}}});

function filtrer(){
    var q=document.getElementById('search').value.toLowerCase();
    document.querySelectorAll('#tableau tr:not(:first-child)').forEach(function(r){
        r.style.display=r.innerText.toLowerCase().includes(q)?'':'none';
    });
}

function trierTable(col){
    var tbody=document.getElementById('tableau');
    var rows=Array.from(tbody.querySelectorAll('tr:not(:first-child)'));
    rows.sort(function(a,b){return(a.dataset[col]||'').localeCompare(b.dataset[col]||'')});
    rows.forEach(function(r){tbody.appendChild(r)});
}
</script>
</body></html>"""

@app.route('/')
def index():
    if not session.get('logged_in'): return redirect('/login')
    labels = [h['heure'] for h in historique]
    data = [h['count'] for h in historique]
    uptime = str(datetime.datetime.now() - heure_debut).split('.')[0]
    blocages = get_historique_blocages()
    apparus, disparus = comparer_scans(scan_precedent, derniers_appareils)
    return render_template_string(HTML,
        appareils=derniers_appareils,
        now=datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        count=len(derniers_appareils),
        labels=labels, data=data, logs=logs,
        nouveaux=len(nouveaux_appareils) > 0,
        nouveaux_count=len(nouveaux_appareils),
        stats=stats, uptime=uptime,
        timeline=timeline, blocages=blocages,
        apparus=apparus, disparus=disparus,
        arp_suspects=arp_suspects
    )

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        if request.form.get('password') == MOT_DE_PASSE_DASHBOARD:
            session['logged_in'] = True
            return redirect('/')
        return render_template_string(LOGIN_HTML, erreur=True)
    return render_template_string(LOGIN_HTML, erreur=False)

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect('/login')

@app.route('/bloquer', methods=['POST'])
def bloquer():
    if not session.get('logged_in'): return redirect('/login')
    ip = request.form.get('ip')
    if ip and ip not in ip_bloquees:
        ip_bloquees.append(ip)
        bloquer_ip(ip)
    return redirect('/')

@app.route('/debloquer', methods=['POST'])
def debloquer():
    if not session.get('logged_in'): return redirect('/login')
    ip = request.form.get('ip')
    if ip and ip in ip_bloquees:
        ip_bloquees.remove(ip)
        debloquer_ip(ip)
    return redirect('/')

@app.route('/deconnecter', methods=['POST'])
def deconnecter():
    if not session.get('logged_in'): return redirect('/login')
    ip = request.form.get('ip')
    if ip and ip not in ip_deconnectees:
        ip_deconnectees.append(ip)
        arp_spoof(ip)
        ajouter_log(f"⚡ DÉCONNEXION : {ip}")
        timeline.append({'heure': datetime.datetime.now().strftime("%H:%M:%S"), 'event': f"Déconnexion forcée: {ip}", 'type': 'deconnexion'})
    return redirect('/')

@app.route('/reconnecter', methods=['POST'])
def reconnecter():
    if not session.get('logged_in'): return redirect('/login')
    ip = request.form.get('ip')
    if ip and ip in ip_deconnectees:
        ip_deconnectees.remove(ip)
        ajouter_log(f"🔌 RECONNEXION : {ip}")
    return redirect('/')

@app.route('/whitelist', methods=['POST'])
def add_whitelist():
    if not session.get('logged_in'): return redirect('/login')
    ip = request.form.get('ip')
    if ip and ip not in whitelist:
        whitelist.append(ip)
        ajouter_log(f"✓ WHITELIST : {ip}")
    return redirect('/')

@app.route('/renommer', methods=['POST'])
def renommer():
    if not session.get('logged_in'): return redirect('/login')
    ip = request.form.get('ip')
    nom = request.form.get('nom', '').strip()
    if ip and nom:
        noms_personnalises[ip] = nom
        ajouter_log(f"✏️ {ip} → {nom}")
    return redirect('/')

@app.route('/export/csv')
def export_csv():
    if not session.get('logged_in'): return redirect('/login')
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['IP','MAC','Fabricant','Hostname','OS','Géo','Ports','Ping','Statut','Score','IoT','VPN','TOR'])
    for a in derniers_appareils:
        writer.writerow([a['ip'],a['mac'],a['fabricant'],a['hostname'],a['os'],a['geo'],a['ports'],a['ping'],a['statut'],a['score'],a['iot'],a['vpn'],a['tor']])
    output.seek(0)
    return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition':'attachment;filename=blueteam.csv'})

@app.route('/export/json')
def export_json():
    if not session.get('logged_in'): return redirect('/login')
    return Response(json.dumps(derniers_appareils, ensure_ascii=False, indent=2), mimetype='application/json', headers={'Content-Disposition':'attachment;filename=blueteam.json'})

@app.route('/export/pdf')
def export_pdf():
    if not session.get('logged_in'): return redirect('/login')
    buffer = io.BytesIO()
    c = rl_canvas.Canvas(buffer, pagesize=A4)
    w, h = A4
    c.setFillColorRGB(0,0.8,0.5)
    c.setFont("Helvetica-Bold",14)
    c.drawString(50,h-40,"BLUE TEAM — RAPPORT RÉSEAU")
    c.setFont("Helvetica",9)
    c.setFillColorRGB(0.5,0.5,0.5)
    c.drawString(50,h-60,f"Généré le {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')} — {len(derniers_appareils)} appareils — Scans: {stats['total_scans']} — Blocages: {stats['total_blocages']}")
    y = h-90
    c.setFillColorRGB(0,0.8,1)
    c.setFont("Helvetica-Bold",9)
    c.drawString(50,y,f"{'IP':<17} {'OS':<10} {'Score':<7} {'Ports':<25} {'Géo':<20} Statut")
    y-=12
    c.setFont("Helvetica",8)
    for a in derniers_appareils:
        if y < 40:
            c.showPage()
            y = h-40
        score = a['score']
        if score >= 70: c.setFillColorRGB(1,0.3,0.3)
        elif score >= 40: c.setFillColorRGB(1,0.5,0)
        else: c.setFillColorRGB(0,0.9,0.5)
        ligne = f"{a['ip']:<17} {a['os']:<10} {score}/100  {a['ports'][:25]:<25} {a['geo'][:20]:<20} {a['statut']}"
        c.drawString(50,y,ligne)
        y-=11
    c.save()
    buffer.seek(0)
    return Response(buffer.getvalue(), mimetype='application/pdf', headers={'Content-Disposition':'attachment;filename=blueteam.pdf'})

@app.route('/api/appareils')
def api_appareils():
    if not session.get('logged_in'): return jsonify({'error':'non autorisé'}),401
    return jsonify(derniers_appareils)

@app.route('/api/stats')
def api_stats():
    if not session.get('logged_in'): return jsonify({'error':'non autorisé'}),401
    return jsonify({**stats, 'appareils': len(derniers_appareils), 'arp_suspects': arp_suspects})

@app.route('/api/logs')
def api_logs():
    if not session.get('logged_in'): return jsonify({'error':'non autorisé'}),401
    return jsonify(logs[-50:])

init_db()
threading.Thread(target=scanner, daemon=True).start()
threading.Thread(target=run_schedule, daemon=True).start()
threading.Thread(target=capturer_paquets, daemon=True).start()
threading.Thread(target=charger_tor_exit_nodes, daemon=True).start()

app.run(host='0.0.0.0', port=5000, debug=False)