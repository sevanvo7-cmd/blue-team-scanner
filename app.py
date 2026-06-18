from flask import Flask, render_template_string, request, redirect, session, jsonify, Response
from scapy.all import ARP, Ether, srp, send
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
from email.mime.text import MIMEText
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.lib.pagesizes import A4

app = Flask(__name__)
app.secret_key = "blueteam2026"

# CONFIG
EMAIL = "sevanvo7@gmail.com"
MOT_DE_PASSE_EMAIL = "xrlnscdlyzrlaiev"
MOT_DE_PASSE_DASHBOARD = "blueteam2026"
TELEGRAM_TOKEN = "8800824706:AAGh6KgKCtpD1gr-ItC79LdET52wNUo0HvI"
TELEGRAM_CHAT_ID = "5455515480"
RESEAU = "192.168.10.0/24"
GATEWAY = "192.168.10.1"

# STATE
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

# DB SQLite
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

# TELEGRAM
def telegram_alert(message):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        requests.post(url, data={"chat_id": TELEGRAM_CHAT_ID, "text": message}, timeout=5)
    except:
        pass

# FONCTIONS RÉSEAU
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
    if mac.startswith(("02:", "06:", "0a:", "0e:")):
        return True
    if mac[1] in ['2', '6', 'a', 'e']:
        return True
    return False

def score_menace(a):
    score = 0
    if a['statut'] == 'NOUVEAU': score += 30
    if a['os'] == 'Inconnu': score += 10
    if '22/SSH' in a['ports']: score += 20
    if '23/Telnet' in a['ports']: score += 30
    if '3389/RDP' in a['ports']: score += 20
    if a.get('mac_aleatoire'): score += 25
    if a['fabricant'] == 'Inconnu': score += 15
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
        msg = MIMEText(f"⚠ NOUVEL APPAREIL\nIP: {ip}\nMAC: {mac}\nFabricant: {fabricant}\nNom: {hostname}\nHeure: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        msg['Subject'] = f"⚠ Blue Team — Nouvel appareil : {ip}"
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
    ajouter_log(f"🚫 IP BLOQUÉE : {ip}")
    sauvegarder_blocage(ip, "BLOQUÉE")
    stats["total_blocages"] += 1
    telegram_alert(f"🚫 Blue Team — IP bloquée : {ip}")

def debloquer_ip(ip):
    os.system(f'netsh advfirewall firewall delete rule name="BLOCK_{ip}"')
    ajouter_log(f"✅ IP DÉBLOQUÉE : {ip}")
    sauvegarder_blocage(ip, "DÉBLOQUÉE")

def arp_spoof(ip_cible, duree=300):
    def _spoof():
        ajouter_log(f"⚡ ARP SPOOF : {ip_cible}")
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
        ajouter_log(f"🔌 ARP SPOOF terminé : {ip_cible}")
    threading.Thread(target=_spoof, daemon=True).start()

def rapport_hebdo():
    ajouter_log("📊 Rapport hebdomadaire envoyé")
    try:
        msg = MIMEText(f"""
📊 RAPPORT HEBDOMADAIRE BLUE TEAM

Appareils actuels : {len(derniers_appareils)}
Total scans : {stats['total_scans']}
Total blocages : {stats['total_blocages']}
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
    except:
        pass

def scanner():
    global derniers_appareils, historique, nouveaux_appareils
    while True:
        heure = datetime.datetime.now().hour
        intervalle = 60 if (heure >= 23 or heure < 7) else 30

        arp = ARP(pdst=RESEAU)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        try:
            resultat = srp(ether/arp, timeout=3, verbose=0)[0]
        except:
            time.sleep(intervalle)
            continue

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
            nom = noms_personnalises.get(ip, "")
            nouveau = mac not in appareils_connus

            a = {
                'ip': ip, 'mac': mac, 'fabricant': fabricant,
                'hostname': hostname, 'ping': ping(ip),
                'statut': 'NOUVEAU' if nouveau else 'Connu',
                'bloque': ip in ip_bloquees,
                'deconnecte': ip in ip_deconnectees,
                'ports': ', '.join(ports),
                'os': os_detecte,
                'iot': iot,
                'mac_aleatoire': mac_aleatoire,
                'nom': nom,
                'whitelist': ip in whitelist
            }
            a['score'] = score_menace(a)
            a['couleur_score'] = couleur_score(a['score'])

            if nouveau:
                appareils_connus[mac] = ip
                nouveaux_appareils.append(ip)
                envoyer_alerte_email(ip, mac, fabricant, hostname)
                telegram_alert(f"⚠ NOUVEL APPAREIL\nIP: {ip}\nMAC: {mac}\nFabricant: {fabricant}\nOS: {os_detecte}\nPorts: {', '.join(ports)}")
                ajouter_log(f"⚠ NOUVEAU — {ip} | {fabricant} | {os_detecte} | Score: {a['score']}/100")
                sauvegarder_appareil(a)
                timeline.append({'heure': datetime.datetime.now().strftime("%H:%M:%S"), 'event': f"Connexion: {ip}", 'type': 'connexion'})

                if ip in blacklist_auto:
                    blacklist_auto[ip] += 1
                else:
                    blacklist_auto[ip] = 1

                if blacklist_auto[ip] >= 3 and ip not in ip_bloquees:
                    ip_bloquees.append(ip)
                    bloquer_ip(ip)
                    ajouter_log(f"🤖 AUTO-BLOQUÉ (3 tentatives) : {ip}")

            appareils.append(a)

        derniers_appareils = sorted(appareils, key=lambda x: x['score'], reverse=True)
        historique.append({'heure': datetime.datetime.now().strftime("%H:%M:%S"), 'count': len(appareils)})
        if len(historique) > 50:
            historique.pop(0)

        stats["total_scans"] += 1
        ajouter_log(f"🔍 Scan #{stats['total_scans']} — {len(appareils)} appareil(s)")
        time.sleep(intervalle)

# SCHEDULE rapport hebdo
schedule.every().monday.at("08:00").do(rapport_hebdo)
def run_schedule():
    while True:
        schedule.run_pending()
        time.sleep(60)

LOGIN_HTML = """<!DOCTYPE html><html><head><title>Blue Team</title>
<style>body{background:#0a0a0a;color:#00ff88;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.box{background:#111;border:1px solid #222;padding:40px;border-radius:5px;text-align:center;min-width:300px}
h1{color:#00ccff}input{background:#0a0a0a;border:1px solid #333;color:#00ff88;padding:10px;width:200px;font-family:monospace;margin:10px 0;display:block;margin:10px auto}
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
h1{color:#00ccff;text-align:center;font-size:1.5em}
h2{color:#00ccff;margin-top:30px;font-size:1.1em}
table{width:100%;border-collapse:collapse;margin-top:10px;font-size:11px}
th{background:#111;color:#00ccff;padding:8px;border:1px solid #222}
td{padding:6px 8px;border:1px solid #1a1a1a}
tr:hover{background:#0f0f0f}
.nouveau{color:#ff4444;font-weight:bold}.connu{color:#00ff88}
.actif{color:#00ff88}.inactif{color:#ff4444}
.header{text-align:center;color:#555;margin-bottom:10px;font-size:11px}
.chart-container{width:100%;max-width:800px;margin:20px auto}
.btn{border:none;padding:3px 7px;cursor:pointer;border-radius:3px;font-family:monospace;font-size:10px;margin:1px}
.btn-bloquer{background:#ff4444;color:white}
.btn-debloquer{background:#00ff88;color:black}
.btn-deconnecter{background:#ff8800;color:black}
.btn-reconnecter{background:#00ccff;color:black}
.btn-whitelist{background:#aa88ff;color:black}
.btn-nom{background:#555;color:white}
.btn-export{background:#333;color:#00ff88;border:1px solid #555;padding:5px 10px;text-decoration:none;font-family:monospace;font-size:11px;margin:3px}
.bloque{background:#1a0000}
.deconnecte{background:#1a0a00}
.whitelisted{background:#001a00}
.iot{color:#ff88ff}
.mac-rand{color:#ffff00}
.logs{background:#050505;border:1px solid #222;padding:10px;max-height:250px;overflow-y:auto;margin-top:10px}
.log-line{color:#555;font-size:10px;margin:2px 0}
.log-line.alerte{color:#ff4444}
.log-line.action{color:#ff8800}
.log-line.scan{color:#00ccff}
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:15px 0}
.stat-box{background:#111;border:1px solid #222;padding:15px;text-align:center;border-radius:5px}
.stat-val{font-size:1.8em;color:#00ccff;font-weight:bold}
.stat-label{font-size:10px;color:#555;margin-top:5px}
.deconnexion{background:#333;color:#00ff88;border:1px solid #555;padding:5px 15px;cursor:pointer;font-family:monospace;font-size:11px}
.search-bar{background:#111;border:1px solid #333;color:#00ff88;padding:8px;font-family:monospace;width:250px;margin:5px}
.score-bar{height:8px;border-radius:4px;margin-top:3px}
.timeline-item{font-size:10px;color:#555;margin:2px 0;padding:3px 5px;border-left:2px solid #222}
.timeline-item.connexion{border-left-color:#00ff88}
.timeline-item.deconnexion{border-left-color:#ff4444}
select{background:#111;border:1px solid #333;color:#00ff88;padding:5px;font-family:monospace}
.nav{display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap;align-items:center}
@media(max-width:768px){.stats-grid{grid-template-columns:repeat(2,1fr)}.btn{padding:5px 8px;font-size:11px}table{font-size:10px}}
</style></head><body>

<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap">
<h1>🔵 BLUE TEAM — SCANNER RÉSEAU</h1>
<form method="POST" action="/logout"><button class="deconnexion">🔓 Déco</button></form>
</div>

<p class="header">{{ now }} — {{ count }} appareil(s) — Scan #{{ stats.total_scans }} — {{ uptime }}</p>

{% if nouveaux %}
<script>window.onload=function(){try{var a=new AudioContext();var o=a.createOscillator();o.connect(a.destination);o.frequency.value=880;o.start();setTimeout(function(){o.stop()},800)}catch(e){}}</script>
{% endif %}

<div class="stats-grid">
<div class="stat-box"><div class="stat-val">{{ count }}</div><div class="stat-label">Appareils actifs</div></div>
<div class="stat-box"><div class="stat-val" style="color:#ff4444">{{ stats.total_blocages }}</div><div class="stat-label">Total blocages</div></div>
<div class="stat-box"><div class="stat-val" style="color:#00ccff">{{ stats.total_scans }}</div><div class="stat-label">Total scans</div></div>
<div class="stat-box"><div class="stat-val" style="color:#aa88ff">{{ nouveaux_count }}</div><div class="stat-label">Nouveaux ce scan</div></div>
</div>

<div class="nav">
<input class="search-bar" type="text" id="search" placeholder="🔍 Filtrer par IP, MAC, OS..." onkeyup="filtrer()">
<select onchange="trierTable(this.value)">
<option value="">Trier par...</option>
<option value="score">Score menace</option>
<option value="ip">IP</option>
<option value="os">OS</option>
<option value="statut">Statut</option>
</select>
<a class="btn-export" href="/export/csv">📥 CSV</a>
<a class="btn-export" href="/export/pdf">📄 PDF</a>
<a class="btn-export" href="/export/json">{ } JSON</a>
</div>

<table id="tableau">
<tr><th>Score</th><th>IP</th><th>Nom</th><th>MAC</th><th>Fabricant</th><th>Hôte</th><th>OS</th><th>Ports</th><th>Ping</th><th>Statut</th><th>Actions</th></tr>
{% for a in appareils %}
<tr class="{{ 'bloque' if a.bloque else 'deconnecte' if a.deconnecte else 'whitelisted' if a.whitelist else '' }}" data-ip="{{ a.ip }}" data-mac="{{ a.mac }}" data-os="{{ a.os }}" data-statut="{{ a.statut }}">
<td>
<div style="color:{{ a.couleur_score }};font-weight:bold">{{ a.score }}/100</div>
<div class="score-bar" style="background:{{ a.couleur_score }};width:{{ a.score }}%"></div>
</td>
<td>{{ a.ip }}</td>
<td style="color:#aaa">{{ a.nom if a.nom else '—' }}</td>
<td style="font-size:10px">{{ a.mac }}{% if a.mac_aleatoire %} <span class="mac-rand" title="MAC aléatoire détectée">⚠</span>{% endif %}</td>
<td>{{ a.fabricant }}</td>
<td>{{ a.hostname }}</td>
<td>{{ a.os }}{% if a.iot %} <span class="iot">📡IoT</span>{% endif %}</td>
<td style="color:#ff8800;font-size:10px">{{ a.ports }}</td>
<td>{{ a.ping }}</td>
<td class="{{ 'nouveau' if a.statut == 'NOUVEAU' else 'connu' }}">{{ a.statut }}</td>
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
<form method="POST" action="/whitelist" style="display:inline"><input type="hidden" name="ip" value="{{ a.ip }}"><button class="btn btn-whitelist">✓WL</button></form>
{% endif %}
<form method="POST" action="/renommer" style="display:inline">
<input type="hidden" name="ip" value="{{ a.ip }}">
<input type="text" name="nom" placeholder="nom" style="width:60px;background:#0a0a0a;border:1px solid #333;color:#00ff88;font-family:monospace;font-size:10px;padding:2px">
<button class="btn btn-nom">✏️</button>
</form>
</td>
</tr>
{% endfor %}
</table>

<div class="chart-container"><canvas id="g"></canvas></div>

<h2>📅 Timeline</h2>
<div class="logs">
{% for t in timeline[-20:]|reverse %}
<div class="timeline-item {{ t.type }}">{{ t.heure }} — {{ t.event }}</div>
{% endfor %}
</div>

<h2>🔒 Historique des blocages</h2>
<div class="logs">
{% for b in blocages %}
<div class="log-line action">[{{ b[3] }}] {{ b[2] }} — {{ b[1] }}</div>
{% endfor %}
</div>

<h2>📋 Logs temps réel</h2>
<div class="logs">
{% for log in logs[-100:]|reverse %}
<div class="log-line {% if '⚠' in log %}alerte{% elif '🚫' in log or '⚡' in log or '🤖' in log %}action{% elif '🔍' in log %}scan{% endif %}">{{ log }}</div>
{% endfor %}
</div>

<script>
const ctx=document.getElementById('g').getContext('2d');
new Chart(ctx,{type:'line',data:{labels:{{ labels|safe }},datasets:[{label:'Appareils',data:{{ data|safe }},borderColor:'#00ccff',backgroundColor:'rgba(0,204,255,0.1)',borderWidth:2,pointBackgroundColor:'#00ff88',tension:0.4,fill:true}]},
options:{responsive:true,plugins:{legend:{labels:{color:'#00ff88'}}},scales:{x:{ticks:{color:'#555'},grid:{color:'#111'}},y:{ticks:{color:'#555'},grid:{color:'#111'},beginAtZero:true}}}});

function filtrer(){
    var q=document.getElementById('search').value.toLowerCase();
    var rows=document.querySelectorAll('#tableau tr:not(:first-child)');
    rows.forEach(function(r){
        var txt=r.innerText.toLowerCase();
        r.style.display=txt.includes(q)?'':'none';
    });
}

function trierTable(col){
    var tbody=document.getElementById('tableau');
    var rows=Array.from(tbody.querySelectorAll('tr:not(:first-child)'));
    rows.sort(function(a,b){
        var va=a.dataset[col]||'';
        var vb=b.dataset[col]||'';
        return va.localeCompare(vb);
    });
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
    return render_template_string(HTML,
        appareils=derniers_appareils,
        now=datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        count=len(derniers_appareils),
        labels=labels, data=data, logs=logs,
        nouveaux=len(nouveaux_appareils) > 0,
        nouveaux_count=len(nouveaux_appareils),
        stats=stats, uptime=uptime,
        timeline=timeline, blocages=blocages
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
        ajouter_log(f"✏️ RENOMMÉ {ip} → {nom}")
    return redirect('/')

@app.route('/export/csv')
def export_csv():
    if not session.get('logged_in'): return redirect('/login')
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['IP','MAC','Fabricant','Hostname','OS','Ports','Ping','Statut','Score'])
    for a in derniers_appareils:
        writer.writerow([a['ip'],a['mac'],a['fabricant'],a['hostname'],a['os'],a['ports'],a['ping'],a['statut'],a['score']])
    output.seek(0)
    return Response(output.getvalue(), mimetype='text/csv',
        headers={'Content-Disposition': 'attachment;filename=blueteam_scan.csv'})

@app.route('/export/json')
def export_json():
    if not session.get('logged_in'): return redirect('/login')
    return Response(json.dumps(derniers_appareils, ensure_ascii=False, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment;filename=blueteam_scan.json'})

@app.route('/export/pdf')
def export_pdf():
    if not session.get('logged_in'): return redirect('/login')
    buffer = io.BytesIO()
    c = rl_canvas.Canvas(buffer, pagesize=A4)
    w, h = A4
    c.setFillColorRGB(0, 0.8, 0.5)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, h-50, "BLUE TEAM — RAPPORT RÉSEAU")
    c.setFont("Helvetica", 10)
    c.setFillColorRGB(0.5, 0.5, 0.5)
    c.drawString(50, h-70, f"Généré le {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    y = h - 110
    c.setFillColorRGB(0, 0.8, 1)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(50, y, f"{'IP':<18} {'OS':<12} {'Score':<8} {'Ports':<30} Statut")
    y -= 15
    c.setFont("Helvetica", 9)
    for a in derniers_appareils:
        if y < 50:
            c.showPage()
            y = h - 50
        score = a['score']
        if score >= 70: c.setFillColorRGB(1, 0.3, 0.3)
        elif score >= 40: c.setFillColorRGB(1, 0.5, 0)
        else: c.setFillColorRGB(0, 1, 0.5)
        ligne = f"{a['ip']:<18} {a['os']:<12} {score}/100    {a['ports'][:30]:<30} {a['statut']}"
        c.drawString(50, y, ligne)
        y -= 13
    c.save()
    buffer.seek(0)
    return Response(buffer.getvalue(), mimetype='application/pdf',
        headers={'Content-Disposition': 'attachment;filename=blueteam_rapport.pdf'})

@app.route('/api/appareils')
def api_appareils():
    if not session.get('logged_in'): return jsonify({'error': 'non autorisé'}), 401
    return jsonify(derniers_appareils)

@app.route('/api/stats')
def api_stats():
    if not session.get('logged_in'): return jsonify({'error': 'non autorisé'}), 401
    return jsonify(stats)

init_db()
threading.Thread(target=scanner, daemon=True).start()
threading.Thread(target=run_schedule, daemon=True).start()

app.run(host='0.0.0.0', port=5000, debug=False)