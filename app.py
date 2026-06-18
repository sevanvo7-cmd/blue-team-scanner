from flask import Flask, render_template_string, request, redirect, session, jsonify, Response
from scapy.all import ARP, Ether, srp, send, sniff
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
import hashlib
import secrets
from email.mime.text import MIMEText
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.lib.pagesizes import A4
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per minute"])

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
stats = {
    "total_scans": 0, "total_blocages": 0,
    "total_deconnexions": 0, "total_nouveaux": 0,
    "start_time": datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
}
timeline = []
heure_debut = datetime.datetime.now()
arp_suspects = 0
gateway_mac_connu = None
scan_precedent = []
TOR_EXIT_NODES = set()
themes = {"current": "dark"}
notes_appareils = {}
tags_appareils = {}
alertes_custom = []
scan_schedule_interval = 30
scan_paused = False

PORTS_CONNUS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3389: "RDP", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 5900: "VNC", 1433: "MSSQL", 3306: "MySQL",
    5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB"
}

OS_SIGNATURES = {
    "Windows": ["Microsoft", "DESKTOP", "WIN"],
    "Apple": ["Apple", "iPhone", "iPad", "MacBook"],
    "Android": ["Android", "Samsung", "Xiaomi", "Huawei"],
    "Linux": ["Linux", "Ubuntu", "Raspberry"],
    "Routeur": ["Cudy", "TP-Link", "Livebox", "Freebox", "SFR"]
}

IOT_SIGNATURES = ["camera","cam","smart","tv","alexa","echo","nest","ring","philips","hue","sonos","xiaomi","tuya"]
VPN_SIGNATURES = ["vpn","tunnel","mullvad","nordvpn","expressvpn","proton","wireguard"]

THEMES = {
    "dark": {"bg": "#0a0a0a", "text": "#00ff88", "accent": "#00ccff", "border": "#222"},
    "red": {"bg": "#0a0000", "text": "#ff4444", "accent": "#ff8800", "border": "#330000"},
    "blue": {"bg": "#00000a", "text": "#4488ff", "accent": "#00ccff", "border": "#000033"},
    "matrix": {"bg": "#000000", "text": "#00ff00", "accent": "#00aa00", "border": "#003300"}
}

def init_db():
    conn = sqlite3.connect("blueteam.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS appareils (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT, mac TEXT, fabricant TEXT, hostname TEXT,
        os TEXT, ports TEXT, statut TEXT, timestamp TEXT, score INTEGER
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS blocages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT, action TEXT, timestamp TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        count INTEGER, timestamp TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT, note TEXT, timestamp TEXT
    )""")
    conn.commit()
    conn.close()

def sauvegarder_appareil(a):
    conn = sqlite3.connect("blueteam.db")
    c = conn.cursor()
    c.execute("INSERT INTO appareils (ip,mac,fabricant,hostname,os,ports,statut,timestamp,score) VALUES (?,?,?,?,?,?,?,?,?)",
        (a['ip'],a['mac'],a['fabricant'],a['hostname'],a['os'],a['ports'],a['statut'],
         datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"),a.get('score',0)))
    conn.commit()
    conn.close()

def sauvegarder_blocage(ip, action):
    conn = sqlite3.connect("blueteam.db")
    c = conn.cursor()
    c.execute("INSERT INTO blocages (ip,action,timestamp) VALUES (?,?,?)",
        (ip, action, datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")))
    conn.commit()
    conn.close()

def sauvegarder_note(ip, note):
    conn = sqlite3.connect("blueteam.db")
    c = conn.cursor()
    c.execute("INSERT INTO notes (ip,note,timestamp) VALUES (?,?,?)",
        (ip, note, datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")))
    conn.commit()
    conn.close()

def get_historique_blocages():
    conn = sqlite3.connect("blueteam.db")
    c = conn.cursor()
    c.execute("SELECT * FROM blocages ORDER BY id DESC LIMIT 50")
    rows = c.fetchall()
    conn.close()
    return rows

def get_notes(ip):
    conn = sqlite3.connect("blueteam.db")
    c = conn.cursor()
    c.execute("SELECT note, timestamp FROM notes WHERE ip=? ORDER BY id DESC LIMIT 5", (ip,))
    rows = c.fetchall()
    conn.close()
    return rows

def get_historique_appareil(ip):
    conn = sqlite3.connect("blueteam.db")
    c = conn.cursor()
    c.execute("SELECT timestamp, ports, score FROM appareils WHERE ip=? ORDER BY id DESC LIMIT 10", (ip,))
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

def ping_ms(ip):
    import subprocess
    try:
        result = subprocess.run(f"ping -n 1 -w 1000 {ip}", capture_output=True, text=True, timeout=3)
        for line in result.stdout.split('\n'):
            if 'ms' in line.lower() and ('temps' in line.lower() or 'time' in line.lower()):
                parts = line.split('=')
                for p in parts:
                    if 'ms' in p:
                        return p.strip().replace('ms','').strip() + 'ms'
        return "🔴"
    except:
        return "🔴"

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Inconnu"

def scan_ports_etendu(ip):
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
    return any(sig in (fabricant+hostname).lower() for sig in IOT_SIGNATURES)

def detecter_mac_spoofing(mac):
    return mac[1] in ['2','6','a','e']

def detecter_vpn(fabricant, hostname):
    return any(sig in (fabricant+hostname).lower() for sig in VPN_SIGNATURES)

def geoip(ip):
    try:
        if ip.startswith(("192.168","10.","172.")):
            return "Réseau local"
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=country,city,isp,proxy", timeout=3)
        if r.status_code == 200:
            d = r.json()
            return f"{d.get('city','?')}, {d.get('country','?')}"
        return "?"
    except:
        return "?"

def check_tor(ip):
    return ip in TOR_EXIT_NODES

def banner_grab(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, port))
        banner = s.recv(1024).decode(errors='ignore').strip()
        s.close()
        return banner[:50] if banner else ""
    except:
        return ""

def check_vulnerabilites(ports_str):
    vulns = []
    if "23/Telnet" in ports_str: vulns.append("⚠ Telnet non chiffré")
    if "21/FTP" in ports_str: vulns.append("⚠ FTP non chiffré")
    if "445/SMB" in ports_str: vulns.append("⚠ SMB exposé (EternalBlue)")
    if "3389/RDP" in ports_str: vulns.append("⚠ RDP exposé (BlueKeep)")
    if "3306/MySQL" in ports_str: vulns.append("⚠ MySQL exposé")
    if "27017/MongoDB" in ports_str: vulns.append("⚠ MongoDB exposé")
    if "6379/Redis" in ports_str: vulns.append("⚠ Redis exposé")
    return vulns

def comparer_scans(ancien, nouveau):
    ips_a = {a['ip'] for a in ancien}
    ips_n = {a['ip'] for a in nouveau}
    return list(ips_n - ips_a), list(ips_a - ips_n)

def score_menace(a):
    score = 0
    if a['statut'] == 'NOUVEAU': score += 30
    if a['os'] == 'Inconnu': score += 10
    if '22/SSH' in a['ports']: score += 20
    if '23/Telnet' in a['ports']: score += 30
    if '3389/RDP' in a['ports']: score += 20
    if '445/SMB' in a['ports']: score += 15
    if a.get('mac_aleatoire'): score += 25
    if a['fabricant'] == 'Inconnu': score += 15
    if a.get('vpn'): score += 15
    if a.get('tor'): score += 40
    if a.get('vulns'): score += len(a['vulns']) * 10
    return min(score, 100)

def couleur_score(score):
    if score >= 70: return "#ff4444"
    if score >= 40: return "#ff8800"
    return "#00ff88"

def niveau_risque(score):
    if score >= 70: return "CRITIQUE"
    if score >= 40: return "MOYEN"
    return "FAIBLE"

def ajouter_log(message):
    now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    logs.append(f"[{now}] {message}")
    if len(logs) > 500:
        logs.pop(0)

def verifier_alertes_custom(a):
    for alerte in alertes_custom:
        if alerte['type'] == 'score' and a['score'] >= int(alerte['valeur']):
            telegram_alert(f"🚨 ALERTE CUSTOM: {a['ip']} score {a['score']}/100 >= {alerte['valeur']}")
        elif alerte['type'] == 'port' and alerte['valeur'] in a['ports']:
            telegram_alert(f"🚨 ALERTE CUSTOM: Port {alerte['valeur']} ouvert sur {a['ip']}")

def envoyer_alerte_email(ip, mac, fabricant, hostname, score, vulns):
    try:
        corps = f"""⚠ NOUVEL APPAREIL DÉTECTÉ
IP: {ip}
MAC: {mac}
Fabricant: {fabricant}
Nom: {hostname}
Score de menace: {score}/100
Vulnérabilités: {', '.join(vulns) if vulns else 'Aucune'}
Heure: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}"""
        msg = MIMEText(corps)
        msg['Subject'] = f"⚠ Blue Team [{niveau_risque(score)}] — {ip}"
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

def charger_tor():
    global TOR_EXIT_NODES
    try:
        r = requests.get("https://check.torproject.org/torbulkexitlist", timeout=10)
        if r.status_code == 200:
            TOR_EXIT_NODES = set(r.text.strip().split('\n'))
            ajouter_log(f"🧅 {len(TOR_EXIT_NODES)} nœuds Tor")
    except:
        pass

def capturer_arp():
    global arp_suspects
    def _cap(pkt):
        global arp_suspects
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:
            arp_suspects += 1
    try:
        sniff(filter="arp", prn=_cap, store=0, timeout=25)
    except:
        pass

def rapport_hebdo():
    try:
        apparus, disparus = comparer_scans(scan_precedent, derniers_appareils)
        corps = f"""📊 RAPPORT HEBDOMADAIRE BLUE TEAM
═══════════════════════════════

📡 Appareils actifs : {len(derniers_appareils)}
🔍 Total scans : {stats['total_scans']}
🚫 Total blocages : {stats['total_blocages']}
⚡ Déconnexions forcées : {stats['total_deconnexions']}
👾 Nouveaux appareils : {stats['total_nouveaux']}
📦 Paquets ARP suspects : {arp_suspects}
⏱ Uptime : depuis {stats['start_time']}

📈 Apparus : {', '.join(apparus) if apparus else 'Aucun'}
📉 Disparus : {', '.join(disparus) if disparus else 'Aucun'}

🔴 Appareils critiques (score ≥70) :
{chr(10).join([f"  • {a['ip']} — {a['score']}/100" for a in derniers_appareils if a['score'] >= 70]) or '  Aucun'}

📋 Derniers logs :
{chr(10).join(logs[-15:])}"""
        msg = MIMEText(corps)
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
        if scan_paused:
            time.sleep(5)
            continue

        heure = datetime.datetime.now().hour
        intervalle = 60 if (heure >= 23 or heure < 7) else scan_schedule_interval

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
            ports = scan_ports_etendu(ip)
            ports_str = ', '.join(ports)
            mac_aleatoire = detecter_mac_spoofing(mac)
            iot = detecter_iot(fabricant, hostname)
            vpn = detecter_vpn(fabricant, hostname)
            tor = check_tor(ip)
            nom = noms_personnalises.get(ip, "")
            tags = tags_appareils.get(ip, [])
            vulns = check_vulnerabilites(ports_str)
            latence = ping_ms(ip)
            nouveau = mac not in appareils_connus

            if ip == GATEWAY:
                if gateway_mac_connu and mac != gateway_mac_connu:
                    ajouter_log(f"🚨 MAC GATEWAY CHANGÉE ! {gateway_mac_connu} → {mac}")
                    telegram_alert(f"🚨 ALERTE CRITIQUE\nMAC Gateway changée !\nAncienne: {gateway_mac_connu}\nNouvelle: {mac}")
                gateway_mac_connu = mac

            banners = {}
            for p in [80, 22, 21, 23, 8080]:
                b = banner_grab(ip, p)
                if b:
                    banners[p] = b

            a = {
                'ip': ip, 'mac': mac, 'fabricant': fabricant,
                'hostname': hostname, 'ping': latence,
                'statut': 'NOUVEAU' if nouveau else 'Connu',
                'bloque': ip in ip_bloquees,
                'deconnecte': ip in ip_deconnectees,
                'ports': ports_str, 'os': os_detecte,
                'iot': iot, 'mac_aleatoire': mac_aleatoire,
                'vpn': vpn, 'tor': tor, 'nom': nom,
                'whitelist': ip in whitelist,
                'geo': geoip(ip), 'banners': banners,
                'vulns': vulns, 'tags': tags,
                'risque': niveau_risque(0)
            }
            a['score'] = score_menace(a)
            a['couleur_score'] = couleur_score(a['score'])
            a['risque'] = niveau_risque(a['score'])

            verifier_alertes_custom(a)

            if nouveau:
                appareils_connus[mac] = ip
                nouveaux_appareils.append(ip)
                stats["total_nouveaux"] += 1
                if ip not in whitelist:
                    envoyer_alerte_email(ip, mac, fabricant, hostname, a['score'], vulns)
                    telegram_alert(f"⚠ NOUVEL APPAREIL [{niveau_risque(a['score'])}]\nIP: {ip}\nMAC: {mac}\nOS: {os_detecte}\nScore: {a['score']}/100\nPorts: {ports_str}\nVulns: {', '.join(vulns) if vulns else 'Aucune'}")
                ajouter_log(f"⚠ NOUVEAU [{a['risque']}] {ip} | {fabricant} | {os_detecte} | {a['score']}/100")
                sauvegarder_appareil(a)
                timeline.append({'heure': datetime.datetime.now().strftime("%H:%M:%S"), 'event': f"Connexion: {ip} ({os_detecte}) [{a['risque']}]", 'type': 'connexion'})

                blacklist_auto[ip] = blacklist_auto.get(ip, 0) + 1
                if blacklist_auto[ip] >= 3 and ip not in ip_bloquees and ip not in whitelist:
                    ip_bloquees.append(ip)
                    bloquer_ip(ip)
                    ajouter_log(f"🤖 AUTO-BLOQUÉ (3x) : {ip}")

            appareils.append(a)

        ips_nouveau = {a['ip'] for a in appareils}
        for a_ancien in scan_precedent:
            if a_ancien['ip'] not in ips_nouveau:
                timeline.append({'heure': datetime.datetime.now().strftime("%H:%M:%S"), 'event': f"Déconnexion: {a_ancien['ip']}", 'type': 'deconnexion'})
                ajouter_log(f"📴 Déconnexion détectée : {a_ancien['ip']}")

        derniers_appareils = sorted(appareils, key=lambda x: x['score'], reverse=True)
        historique.append({'heure': datetime.datetime.now().strftime("%H:%M:%S"), 'count': len(appareils)})
        if len(historique) > 50: historique.pop(0)
        if len(timeline) > 200: timeline.pop(0)

        stats["total_scans"] += 1
        ajouter_log(f"🔍 Scan #{stats['total_scans']} — {len(appareils)} appareils | ARP: {arp_suspects}")
        time.sleep(intervalle)

schedule.every().monday.at("08:00").do(rapport_hebdo)
schedule.every(6).hours.do(charger_tor)

def run_schedule():
    while True:
        schedule.run_pending()
        time.sleep(60)

LOGIN_HTML = """<!DOCTYPE html><html><head><title>Blue Team</title>
<style>body{background:#0a0a0a;color:#00ff88;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.box{background:#111;border:1px solid #222;padding:40px;border-radius:5px;text-align:center;min-width:320px}
h1{color:#00ccff;margin-bottom:5px}p{color:#555;font-size:11px}
input{background:#0a0a0a;border:1px solid #333;color:#00ff88;padding:10px;width:220px;font-family:monospace;margin:10px auto;display:block;border-radius:3px}
button{background:#00ccff;color:black;border:none;padding:10px 30px;cursor:pointer;font-family:monospace;font-weight:bold;margin-top:10px;border-radius:3px}
.erreur{color:#ff4444;font-size:11px}</style></head><body>
<div class="box"><h1>🔵 BLUE TEAM</h1><p>Tableau de bord sécurisé</p>
{% if erreur %}<p class="erreur">❌ Mot de passe incorrect</p>{% endif %}
<form method="POST"><input type="password" name="password" placeholder="Mot de passe">
<button type="submit">→ Connexion</button></form></div></body></html>"""

def get_theme():
    return THEMES.get(themes["current"], THEMES["dark"])

HTML = """<!DOCTYPE html><html><head><title>Blue Team Scanner</title>
<meta http-equiv="refresh" content="30">
<meta name="viewport" content="width=device-width,initial-scale=1">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
:root{--bg:{{ theme.bg }};--text:{{ theme.text }};--accent:{{ theme.accent }};--border:{{ theme.border }}}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:monospace;padding:15px}
h1{color:var(--accent);font-size:1.3em}
h2{color:var(--accent);margin-top:20px;font-size:.95em;border-bottom:1px solid var(--border);padding-bottom:4px}
table{width:100%;border-collapse:collapse;margin-top:8px;font-size:10px}
th{background:#111;color:var(--accent);padding:6px;border:1px solid var(--border);white-space:nowrap}
td{padding:5px 6px;border:1px solid #1a1a1a;vertical-align:top}
tr:hover{background:#0d0d0d}
.nouveau{color:#ff4444;font-weight:bold}.connu{color:#00ff88}
.header{text-align:center;color:#555;font-size:10px;margin:5px 0}
.chart-container{width:100%;max-width:750px;margin:15px auto}
.btn{border:none;padding:3px 6px;cursor:pointer;border-radius:3px;font-family:monospace;font-size:9px;margin:1px;white-space:nowrap}
.btn-bloquer{background:#ff4444;color:white}
.btn-debloquer{background:#00ff88;color:black}
.btn-deconnecter{background:#ff8800;color:black}
.btn-reconnecter{background:#00ccff;color:black}
.btn-whitelist{background:#aa88ff;color:black}
.btn-note{background:#446644;color:white}
.btn-tag{background:#664444;color:white}
.btn-export{background:#1a1a1a;color:var(--text);border:1px solid var(--border);padding:4px 8px;text-decoration:none;font-family:monospace;font-size:10px;margin:2px;display:inline-block;border-radius:3px}
.bloque{background:#1a0000!important}.deconnecte{background:#1a0800!important}.whitelisted{background:#001500!important}
.iot{color:#ff88ff}.mac-rand{color:#ffff00}.tor-b{color:#9944ff}.vpn-b{color:#44aaff}
.logs{background:#050505;border:1px solid var(--border);padding:8px;max-height:180px;overflow-y:auto;margin-top:6px}
.log-line{color:#444;font-size:9px;margin:1px 0;padding:1px 3px;border-radius:2px}
.log-line.alerte{color:#ff4444;background:#1a0000}.log-line.action{color:#ff8800}.log-line.scan{color:#00aacc}
.stats-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:6px;margin:10px 0}
.stat-box{background:#111;border:1px solid var(--border);padding:10px;text-align:center;border-radius:4px}
.stat-val{font-size:1.4em;color:var(--accent);font-weight:bold}
.stat-label{font-size:8px;color:#555;margin-top:2px}
.deconnexion{background:#1a1a1a;color:var(--text);border:1px solid #444;padding:4px 10px;cursor:pointer;font-family:monospace;font-size:10px;border-radius:3px}
.search-bar{background:#111;border:1px solid var(--border);color:var(--text);padding:5px;font-family:monospace;width:200px;font-size:10px;border-radius:3px}
.score-bar{height:4px;border-radius:2px;margin-top:2px}
.t-item{font-size:9px;margin:1px 0;padding:2px 4px;border-left:2px solid #222}
.t-item.connexion{border-left-color:#00ff88;color:#00aa55}
.t-item.deconnexion{border-left-color:#ff4444;color:#aa3333}
select{background:#111;border:1px solid var(--border);color:var(--text);padding:3px;font-family:monospace;font-size:10px;border-radius:3px}
.nav{display:flex;gap:6px;margin:10px 0;flex-wrap:wrap;align-items:center}
.vuln{color:#ff4444;font-size:8px;display:block}
.banner-i{color:#666;font-size:8px;font-style:italic}
.geo-i{color:#4488aa;font-size:9px}
.tag{background:#333;color:#aaa;padding:1px 4px;border-radius:2px;font-size:8px;margin:1px}
.risque-CRITIQUE{color:#ff4444;font-weight:bold}
.risque-MOYEN{color:#ff8800}
.risque-FAIBLE{color:#00ff88}
.ctrl-bar{display:flex;gap:8px;align-items:center;background:#111;border:1px solid var(--border);padding:8px;border-radius:4px;margin-bottom:10px;flex-wrap:wrap}
.input-sm{background:#0a0a0a;border:1px solid #333;color:var(--text);padding:3px 6px;font-family:monospace;font-size:10px;border-radius:3px;width:80px}
.comp-box{background:#111;border:1px solid var(--border);padding:8px;margin:8px 0;font-size:10px;border-radius:4px}
.apparu{color:#00ff88}.disparu{color:#ff4444}
@media(max-width:768px){.stats-grid{grid-template-columns:repeat(2,1fr)}th,td{font-size:9px;padding:3px}}
</style></head><body>

<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;margin-bottom:8px">
<h1>🔵 BLUE TEAM — SCANNER RÉSEAU</h1>
<div style="display:flex;gap:5px;align-items:center">
<form method="POST" action="/theme" style="display:inline">
<select name="theme" onchange="this.form.submit()" title="Thème">
<option value="dark" {% if theme_name=='dark' %}selected{% endif %}>🌑 Dark</option>
<option value="red" {% if theme_name=='red' %}selected{% endif %}>🔴 Red</option>
<option value="blue" {% if theme_name=='blue' %}selected{% endif %}>🔵 Blue</option>
<option value="matrix" {% if theme_name=='matrix' %}selected{% endif %}>💚 Matrix</option>
</select>
</form>
<form method="POST" action="/logout"><button class="deconnexion">🔓</button></form>
</div>
</div>

<p class="header">{{ now }} — {{ count }} appareil(s) — Scan #{{ stats.total_scans }} — ⏱ {{ uptime }} — ARP: {{ arp_suspects }} — Mode: {{ 'PAUSE' if paused else 'ACTIF' }}</p>

<div class="stats-grid">
<div class="stat-box"><div class="stat-val">{{ count }}</div><div class="stat-label">Appareils</div></div>
<div class="stat-box"><div class="stat-val" style="color:#ff4444">{{ stats.total_blocages }}</div><div class="stat-label">Blocages</div></div>
<div class="stat-box"><div class="stat-val" style="color:var(--accent)">{{ stats.total_scans }}</div><div class="stat-label">Scans</div></div>
<div class="stat-box"><div class="stat-val" style="color:#aa88ff">{{ stats.total_nouveaux }}</div><div class="stat-label">Total nouveaux</div></div>
<div class="stat-box"><div class="stat-val" style="color:#ff8800">{{ critiques }}</div><div class="stat-label">Critiques</div></div>
</div>

<div class="ctrl-bar">
<form method="POST" action="/pause" style="display:inline">
<button class="btn" style="background:{% if paused %}#00ff88;color:black{% else %}#ff8800;color:black{% endif %}">
{% if paused %}▶ Reprendre{% else %}⏸ Pause{% endif %}</button>
</form>
<form method="POST" action="/scan-now" style="display:inline">
<button class="btn" style="background:#00ccff;color:black">⚡ Scanner maintenant</button>
</form>
<form method="POST" action="/alerte-custom" style="display:inline">
<select name="type" style="background:#111;border:1px solid #333;color:var(--text);font-family:monospace;font-size:10px;padding:3px">
<option value="score">Score ≥</option>
<option value="port">Port =</option>
</select>
<input class="input-sm" type="text" name="valeur" placeholder="valeur">
<button class="btn btn-tag">+ Alerte</button>
</form>
<span style="font-size:10px;color:#555">Intervalle:</span>
<form method="POST" action="/set-interval" style="display:inline">
<input class="input-sm" type="number" name="intervalle" value="{{ intervalle }}" min="10" max="300">
<button class="btn btn-debloquer">✓</button>
</form>
</div>

{% if alertes_custom %}
<div style="font-size:9px;color:#888;margin-bottom:5px">
Alertes actives: {% for a in alertes_custom %}<span class="tag">{{ a.type }}={{ a.valeur }}</span>{% endfor %}
</div>
{% endif %}

{% if apparus or disparus %}
<div class="comp-box">
📊 vs scan précédent —
{% if apparus %}<span class="apparu">▲ {{ apparus|join(', ') }}</span>{% endif %}
{% if disparus %} <span class="disparu">▼ {{ disparus|join(', ') }}</span>{% endif %}
</div>
{% endif %}

<div class="nav">
<input class="search-bar" type="text" id="srch" placeholder="🔍 Filtrer..." onkeyup="filtrer()">
<select onchange="trier(this.value)">
<option value="">Trier...</option>
<option value="score">Score</option>
<option value="ip">IP</option>
<option value="os">OS</option>
<option value="statut">Statut</option>
<option value="risque">Risque</option>
</select>
<select onchange="filtrerOS(this.value)">
<option value="">Tous OS</option>
<option>Windows</option><option>Apple</option><option>Android</option>
<option>Linux</option><option>Routeur</option><option>Inconnu</option>
</select>
<a class="btn-export" href="/export/csv">📥 CSV</a>
<a class="btn-export" href="/export/pdf">📄 PDF</a>
<a class="btn-export" href="/export/json">{ } JSON</a>
<a class="btn-export" href="/api/appareils" target="_blank">🔌 API</a>
<a class="btn-export" href="/logs/full" target="_blank">📋 Logs</a>
</div>

<table id="tab">
<tr><th>Score/Risque</th><th>IP</th><th>Nom/Tags</th><th>MAC</th><th>Fabricant</th><th>Hôte</th><th>OS</th><th>Géo</th><th>Latence</th><th>Ports/Vulns</th><th>Statut</th><th>Actions</th></tr>
{% for a in appareils %}
<tr class="{{ 'bloque' if a.bloque else 'deconnecte' if a.deconnecte else 'whitelisted' if a.whitelist else '' }}"
    data-ip="{{ a.ip }}" data-mac="{{ a.mac }}" data-os="{{ a.os }}" data-statut="{{ a.statut }}" data-risque="{{ a.risque }}" data-score="{{ a.score }}">
<td>
<div style="color:{{ a.couleur_score }};font-weight:bold;font-size:11px">{{ a.score }}/100</div>
<div class="score-bar" style="background:{{ a.couleur_score }};width:{{ a.score }}%"></div>
<div class="risque-{{ a.risque }}" style="font-size:9px">{{ a.risque }}</div>
</td>
<td style="font-size:10px;white-space:nowrap">{{ a.ip }}</td>
<td style="font-size:9px">
<div style="color:#aaa">{{ a.nom if a.nom else '—' }}</div>
{% for tag in a.tags %}<span class="tag">{{ tag }}</span>{% endfor %}
</td>
<td style="font-size:9px">
{{ a.mac }}{% if a.mac_aleatoire %} <span class="mac-rand">⚠MAC</span>{% endif %}
</td>
<td style="font-size:10px">{{ a.fabricant }}</td>
<td style="font-size:9px">{{ a.hostname }}</td>
<td style="font-size:10px">
{{ a.os }}
{% if a.iot %}<span class="iot">📡</span>{% endif %}
{% if a.vpn %}<span class="vpn-b">VPN</span>{% endif %}
{% if a.tor %}<span class="tor-b">🧅TOR</span>{% endif %}
</td>
<td class="geo-i">{{ a.geo }}</td>
<td style="font-size:10px;text-align:center">{{ a.ping }}</td>
<td style="font-size:9px">
<div style="color:#ff8800">{{ a.ports }}</div>
{% for v in a.vulns %}<span class="vuln">{{ v }}</span>{% endfor %}
{% for port, banner in a.banners.items() %}<span class="banner-i">{{ port }}: {{ banner[:30] }}</span>{% endfor %}
</td>
<td class="{{ 'nouveau' if a.statut == 'NOUVEAU' else 'connu' }}" style="font-size:9px">{{ a.statut }}</td>
<td style="min-width:180px">
{% if a.bloque %}
<form method="POST" action="/debloquer" style="display:inline"><input type="hidden" name="ip" value="{{ a.ip }}"><button class="btn btn-debloquer">✅Débloquer</button></form>
{% else %}
<form method="POST" action="/bloquer" style="display:inline"><input type="hidden" name="ip" value="{{ a.ip }}"><button class="btn btn-bloquer">🚫Bloquer</button></form>
{% endif %}
{% if a.deconnecte %}
<form method="POST" action="/reconnecter" style="display:inline"><input type="hidden" name="ip" value="{{ a.ip }}"><button class="btn btn-reconnecter">🔌</button></form>
{% else %}
<form method="POST" action="/deconnecter" style="display:inline"><input type="hidden" name="ip" value="{{ a.ip }}"><button class="btn btn-deconnecter">⚡</button></form>
{% endif %}
{% if not a.whitelist %}
<form method="POST" action="/whitelist" style="display:inline"><input type="hidden" name="ip" value="{{ a.ip }}"><button class="btn btn-whitelist">✓WL</button></form>
{% endif %}
<form method="POST" action="/renommer" style="display:inline">
<input type="hidden" name="ip" value="{{ a.ip }}">
<input class="input-sm" type="text" name="nom" placeholder="nom" style="width:55px">
<button class="btn" style="background:#444;color:white">✏</button>
</form>
<form method="POST" action="/tag" style="display:inline">
<input type="hidden" name="ip" value="{{ a.ip }}">
<input class="input-sm" type="text" name="tag" placeholder="tag" style="width:45px">
<button class="btn btn-tag">#</button>
</form>
<form method="POST" action="/note" style="display:inline">
<input type="hidden" name="ip" value="{{ a.ip }}">
<input class="input-sm" type="text" name="note" placeholder="note" style="width:60px">
<button class="btn btn-note">📝</button>
</form>
<a class="btn btn-export" href="/detail/{{ a.ip }}" style="padding:3px 5px">🔎</a>
</td>
</tr>
{% endfor %}
</table>

<div class="chart-container"><canvas id="g"></canvas></div>

<h2>📅 Timeline</h2>
<div class="logs">
{% for t in timeline[-40:]|reverse %}
<div class="t-item {{ t.type }}">{{ t.heure }} — {{ t.event }}</div>
{% endfor %}
</div>

<h2>🔒 Historique blocages</h2>
<div class="logs">
{% for b in blocages %}
<div class="log-line action">[{{ b[3] }}] {{ b[2] }} — {{ b[1] }}</div>
{% endfor %}
</div>

<h2>📋 Logs ({{ logs|length }})</h2>
<div class="logs">
{% for log in logs[-100:]|reverse %}
<div class="log-line {% if '⚠' in log or '🚨' in log %}alerte{% elif '🚫' in log or '⚡' in log or '🤖' in log or '📴' in log %}action{% elif '🔍' in log %}scan{% endif %}">{{ log }}</div>
{% endfor %}
</div>

<script>
const ctx=document.getElementById('g').getContext('2d');
new Chart(ctx,{type:'line',data:{labels:{{ labels|safe }},datasets:[{label:'Appareils',data:{{ data|safe }},borderColor:'{{ theme.accent }}',backgroundColor:'{{ theme.accent }}22',borderWidth:2,pointBackgroundColor:'{{ theme.text }}',tension:0.4,fill:true}]},
options:{responsive:true,plugins:{legend:{labels:{color:'{{ theme.text }}'}}},scales:{x:{ticks:{color:'#555'},grid:{color:'#0f0f0f'}},y:{ticks:{color:'#555'},grid:{color:'#0f0f0f'},beginAtZero:true}}}});

function filtrer(){
    var q=document.getElementById('srch').value.toLowerCase();
    document.querySelectorAll('#tab tr:not(:first-child)').forEach(r=>r.style.display=r.innerText.toLowerCase().includes(q)?'':'none');
}
function trier(col){
    var t=document.getElementById('tab');
    var rows=[...t.querySelectorAll('tr:not(:first-child)')];
    rows.sort((a,b)=>{
        var va=col==='score'?parseInt(a.dataset.score||0):a.dataset[col]||'';
        var vb=col==='score'?parseInt(b.dataset.score||0):b.dataset[col]||'';
        return col==='score'?vb-va:va.toString().localeCompare(vb.toString());
    });
    rows.forEach(r=>t.appendChild(r));
}
function filtrerOS(os){
    document.querySelectorAll('#tab tr:not(:first-child)').forEach(r=>{
        r.style.display=(!os||r.dataset.os===os)?'':'none';
    });
}
</script>
</body></html>"""

DETAIL_HTML = """<!DOCTYPE html><html><head><title>Détail {{ ip }}</title>
<style>body{background:#0a0a0a;color:#00ff88;font-family:monospace;padding:20px}
h1{color:#00ccff}table{border-collapse:collapse;width:100%}
th,td{border:1px solid #222;padding:8px;text-align:left;font-size:11px}
th{background:#111;color:#00ccff}.back{color:#00ccff;text-decoration:none}</style></head><body>
<a class="back" href="/">← Retour</a>
<h1>🔎 Détail — {{ ip }}</h1>
<h2 style="color:#555;font-size:12px;margin:10px 0">Historique des scans</h2>
<table><tr><th>Timestamp</th><th>Ports</th><th>Score</th></tr>
{% for h in historique_appareil %}
<tr><td>{{ h[0] }}</td><td>{{ h[1] }}</td><td>{{ h[2] }}/100</td></tr>
{% endfor %}
</table>
<h2 style="color:#555;font-size:12px;margin:10px 0">Notes</h2>
<table><tr><th>Note</th><th>Date</th></tr>
{% for n in notes %}
<tr><td>{{ n[0] }}</td><td>{{ n[1] }}</td></tr>
{% endfor %}
</table>
</body></html>"""

@app.route('/')
def index():
    if not session.get('logged_in'): return redirect('/login')
    labels = [h['heure'] for h in historique]
    data = [h['count'] for h in historique]
    uptime = str(datetime.datetime.now() - heure_debut).split('.')[0]
    blocages = get_historique_blocages()
    apparus, disparus = comparer_scans(scan_precedent, derniers_appareils)
    critiques = sum(1 for a in derniers_appareils if a['score'] >= 70)
    theme = get_theme()
    return render_template_string(HTML,
        appareils=derniers_appareils, now=datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        count=len(derniers_appareils), labels=labels, data=data, logs=logs,
        nouveaux=len(nouveaux_appareils) > 0, nouveaux_count=len(nouveaux_appareils),
        stats=stats, uptime=uptime, timeline=timeline, blocages=blocages,
        apparus=apparus, disparus=disparus, arp_suspects=arp_suspects,
        critiques=critiques, theme=theme, theme_name=themes["current"],
        alertes_custom=alertes_custom, intervalle=scan_schedule_interval,
        paused=scan_paused
    )

@app.route('/detail/<ip>')
def detail(ip):
    if not session.get('logged_in'): return redirect('/login')
    h = get_historique_appareil(ip)
    n = get_notes(ip)
    return render_template_string(DETAIL_HTML, ip=ip, historique_appareil=h, notes=n)

@app.route('/login', methods=['GET','POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        if request.form.get('password') == MOT_DE_PASSE_DASHBOARD:
            session['logged_in'] = True
            ajouter_log(f"🔐 Connexion dashboard depuis {request.remote_addr}")
            return redirect('/')
        ajouter_log(f"❌ Tentative connexion échouée depuis {request.remote_addr}")
        return render_template_string(LOGIN_HTML, erreur=True)
    return render_template_string(LOGIN_HTML, erreur=False)

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect('/login')

@app.route('/theme', methods=['POST'])
def set_theme():
    if not session.get('logged_in'): return redirect('/login')
    themes["current"] = request.form.get('theme', 'dark')
    return redirect('/')

@app.route('/pause', methods=['POST'])
def toggle_pause():
    global scan_paused
    if not session.get('logged_in'): return redirect('/login')
    scan_paused = not scan_paused
    ajouter_log(f"⏸ Scanner {'mis en pause' if scan_paused else 'repris'}")
    return redirect('/')

@app.route('/scan-now', methods=['POST'])
def scan_now():
    if not session.get('logged_in'): return redirect('/login')
    threading.Thread(target=lambda: None, daemon=True).start()
    ajouter_log("⚡ Scan manuel déclenché")
    return redirect('/')

@app.route('/set-interval', methods=['POST'])
def set_interval():
    global scan_schedule_interval
    if not session.get('logged_in'): return redirect('/login')
    try:
        scan_schedule_interval = max(10, min(300, int(request.form.get('intervalle', 30))))
        ajouter_log(f"⏱ Intervalle scan : {scan_schedule_interval}s")
    except:
        pass
    return redirect('/')

@app.route('/alerte-custom', methods=['POST'])
def add_alerte_custom():
    if not session.get('logged_in'): return redirect('/login')
    t = request.form.get('type')
    v = request.form.get('valeur','').strip()
    if t and v:
        alertes_custom.append({'type': t, 'valeur': v})
        ajouter_log(f"🔔 Alerte custom : {t}={v}")
    return redirect('/')

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
        stats["total_deconnexions"] += 1
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
    nom = request.form.get('nom','').strip()
    if ip and nom:
        noms_personnalises[ip] = nom
        ajouter_log(f"✏️ {ip} → {nom}")
    return redirect('/')

@app.route('/tag', methods=['POST'])
def add_tag():
    if not session.get('logged_in'): return redirect('/login')
    ip = request.form.get('ip')
    tag = request.form.get('tag','').strip()
    if ip and tag:
        if ip not in tags_appareils: tags_appareils[ip] = []
        if tag not in tags_appareils[ip]:
            tags_appareils[ip].append(tag)
            ajouter_log(f"🏷 Tag '{tag}' → {ip}")
    return redirect('/')

@app.route('/note', methods=['POST'])
def add_note():
    if not session.get('logged_in'): return redirect('/login')
    ip = request.form.get('ip')
    note = request.form.get('note','').strip()
    if ip and note:
        sauvegarder_note(ip, note)
        ajouter_log(f"📝 Note → {ip}: {note}")
    return redirect('/')

@app.route('/export/csv')
def export_csv():
    if not session.get('logged_in'): return redirect('/login')
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['IP','MAC','Nom','Fabricant','Hostname','OS','Géo','Latence','Ports','Score','Risque','IoT','VPN','TOR','Vulns','Statut'])
    for a in derniers_appareils:
        writer.writerow([a['ip'],a['mac'],a['nom'],a['fabricant'],a['hostname'],a['os'],a['geo'],a['ping'],a['ports'],a['score'],a['risque'],a['iot'],a['vpn'],a['tor'],'; '.join(a['vulns']),a['statut']])
    output.seek(0)
    return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition':'attachment;filename=blueteam.csv'})

@app.route('/export/json')
def export_json():
    if not session.get('logged_in'): return redirect('/login')
    export_data = [{k:v for k,v in a.items() if k != 'banners'} for a in derniers_appareils]
    return Response(json.dumps(export_data, ensure_ascii=False, indent=2), mimetype='application/json', headers={'Content-Disposition':'attachment;filename=blueteam.json'})

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
    c.drawString(50,h-58,f"Généré: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')} | Appareils: {len(derniers_appareils)} | Scans: {stats['total_scans']} | Blocages: {stats['total_blocages']}")
    c.drawString(50,h-70,f"Uptime: {str(datetime.datetime.now()-heure_debut).split('.')[0]} | ARP suspects: {arp_suspects} | Critiques: {sum(1 for a in derniers_appareils if a['score']>=70)}")
    y = h-95
    c.setFillColorRGB(0,0.8,1)
    c.setFont("Helvetica-Bold",8)
    c.drawString(50,y,f"{'IP':<16} {'OS':<10} {'Score':<7} {'Risque':<10} {'Ports':<22} Vulns")
    y-=10
    c.setFont("Helvetica",7)
    for a in derniers_appareils:
        if y < 40:
            c.showPage()
            y = h-40
        s = a['score']
        if s>=70: c.setFillColorRGB(1,0.3,0.3)
        elif s>=40: c.setFillColorRGB(1,0.5,0)
        else: c.setFillColorRGB(0,0.9,0.5)
        vulns_str = (' | '.join(a['vulns']))[:25] if a['vulns'] else 'OK'
        c.drawString(50,y,f"{a['ip']:<16} {a['os']:<10} {s}/100  {a['risque']:<10} {a['ports'][:22]:<22} {vulns_str}")
        y-=10
    c.save()
    buffer.seek(0)
    return Response(buffer.getvalue(), mimetype='application/pdf', headers={'Content-Disposition':'attachment;filename=blueteam.pdf'})

@app.route('/logs/full')
def logs_full():
    if not session.get('logged_in'): return redirect('/login')
    return Response('\n'.join(logs), mimetype='text/plain')

@app.route('/api/appareils')
def api_appareils():
    if not session.get('logged_in'): return jsonify({'error':'non autorisé'}),401
    return jsonify([{k:v for k,v in a.items() if k!='banners'} for a in derniers_appareils])

@app.route('/api/stats')
def api_stats():
    if not session.get('logged_in'): return jsonify({'error':'non autorisé'}),401
    return jsonify({**stats,'appareils':len(derniers_appareils),'arp_suspects':arp_suspects,'critiques':sum(1 for a in derniers_appareils if a['score']>=70)})

@app.route('/api/logs')
def api_logs():
    if not session.get('logged_in'): return jsonify({'error':'non autorisé'}),401
    return jsonify(logs[-100:])

@app.route('/api/timeline')
def api_timeline():
    if not session.get('logged_in'): return jsonify({'error':'non autorisé'}),401
    return jsonify(timeline[-50:])

init_db()
threading.Thread(target=scanner, daemon=True).start()
threading.Thread(target=run_schedule, daemon=True).start()
threading.Thread(target=capturer_arp, daemon=True).start()
threading.Thread(target=charger_tor, daemon=True).start()

app.run(host='0.0.0.0', port=5000, debug=False)