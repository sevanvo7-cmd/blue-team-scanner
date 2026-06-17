from flask import Flask, render_template_string, request, redirect
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
historique = []
ip_bloquees = []

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

def bloquer_ip(ip):
    os.system(f'netsh advfirewall firewall add rule name="BLOCK_{ip}" dir=in action=block remoteip={ip}')
    os.system(f'netsh advfirewall firewall add rule name="BLOCK_{ip}" dir=out action=block remoteip={ip}')

def debloquer_ip(ip):
    os.system(f'netsh advfirewall firewall delete rule name="BLOCK_{ip}"')

def scanner():
    global derniers_appareils, historique
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
                'statut': 'NOUVEAU' if nouveau else 'Connu',
                'bloque': ip in ip_bloquees
            })
        derniers_appareils = appareils
        historique.append({
            'heure': datetime.datetime.now().strftime("%H:%M:%S"),
            'count': len(appareils)
        })
        if len(historique) > 20:
            historique.pop(0)
        time.sleep(30)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Blue Team Scanner</title>
    <meta http-equiv="refresh" content="30">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
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
        .chart-container { width: 100%; max-width: 900px; margin: 40px auto; }
        .btn-bloquer { background: #ff4444; color: white; border: none; padding: 5px 10px; cursor: pointer; border-radius: 3px; font-family: monospace; }
        .btn-debloquer { background: #00ff88; color: black; border: none; padding: 5px 10px; cursor: pointer; border-radius: 3px; font-family: monospace; }
        .bloque { background: #1a0000; }
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
            <th>Action</th>
        </tr>
        {% for a in appareils %}
        <tr class="{{ 'bloque' if a.bloque else '' }}">
            <td>{{ a.ip }}</td>
            <td>{{ a.mac }}</td>
            <td>{{ a.fabricant }}</td>
            <td>{{ a.hostname }}</td>
            <td class="{{ 'actif' if '🟢' in a.ping else 'inactif' }}">{{ a.ping }}</td>
            <td class="{{ 'nouveau' if a.statut == 'NOUVEAU' else 'connu' }}">{{ a.statut }}</td>
            <td>
                {% if a.bloque %}
                <form method="POST" action="/debloquer">
                    <input type="hidden" name="ip" value="{{ a.ip }}">
                    <button class="btn-debloquer">✅ Débloquer</button>
                </form>
                {% else %}
                <form method="POST" action="/bloquer">
                    <input type="hidden" name="ip" value="{{ a.ip }}">
                    <button class="btn-bloquer">🚫 Bloquer</button>
                </form>
                {% endif %}
            </td>
        </tr>
        {% endfor %}
    </table>

    <div class="chart-container">
        <canvas id="graphique"></canvas>
    </div>

    <script>
        const ctx = document.getElementById('graphique').getContext('2d');
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: {{ labels | safe }},
                datasets: [{
                    label: 'Appareils connectés',
                    data: {{ data | safe }},
                    borderColor: '#00ccff',
                    backgroundColor: 'rgba(0, 204, 255, 0.1)',
                    borderWidth: 2,
                    pointBackgroundColor: '#00ff88',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { labels: { color: '#00ff88' } } },
                scales: {
                    x: { ticks: { color: '#555' }, grid: { color: '#111' } },
                    y: { ticks: { color: '#555' }, grid: { color: '#111' }, beginAtZero: true }
                }
            }
        });
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    labels = [h['heure'] for h in historique]
    data = [h['count'] for h in historique]
    return render_template_string(HTML,
        appareils=derniers_appareils,
        now=datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        count=len(derniers_appareils),
        labels=labels,
        data=data
    )

@app.route('/bloquer', methods=['POST'])
def bloquer():
    ip = request.form.get('ip')
    if ip and ip not in ip_bloquees:
        ip_bloquees.append(ip)
        bloquer_ip(ip)
    return redirect('/')

@app.route('/debloquer', methods=['POST'])
def debloquer():
    ip = request.form.get('ip')
    if ip and ip in ip_bloquees:
        ip_bloquees.remove(ip)
        debloquer_ip(ip)
    return redirect('/')

t = threading.Thread(target=scanner, daemon=True)
t.start()

app.run(host='0.0.0.0', port=5000, debug=False)