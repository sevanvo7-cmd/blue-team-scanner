from scapy.all import ARP, Ether, srp
from colorama import Fore, Style, init
import requests
import datetime
import time
import os

init()

LOG_FILE = "scan_log.txt"
appareils_connus = {}

def get_fabricant(mac):
    try:
        url = f"https://api.macvendors.com/{mac}"
        r = requests.get(url, timeout=2)
        if r.status_code == 200:
            return r.text
        return "Inconnu"
    except:
        return "Inconnu"

def scanner(ip):
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    paquet = ether/arp
    resultat = srp(paquet, timeout=3, verbose=0)[0]
    appareils = []
    for envoi, reponse in resultat:
        appareils.append({
            'ip': reponse.psrc,
            'mac': reponse.hwsrc
        })
    return appareils

def afficher(appareils):
    os.system('cls')
    now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    print(Fore.CYAN + f"""
╔══════════════════════════════════════════════╗
║         BLUE TEAM — SCANNER RÉSEAU           ║
║              {now}             ║
╚══════════════════════════════════════════════╝
""" + Style.RESET_ALL)

    print(Fore.WHITE + f"{'IP':<20} {'MAC':<20} {'FABRICANT':<25} {'STATUT'}" + Style.RESET_ALL)
    print("─" * 80)

    with open(LOG_FILE, "a") as log:
        for a in appareils:
            fabricant = get_fabricant(a['mac'])
            nouveau = a['mac'] not in appareils_connus

            if nouveau:
                statut = Fore.RED + "⚠ NOUVEAU" + Style.RESET_ALL
                print('\a')
                log.write(f"[{now}] NOUVEAU APPAREIL — IP: {a['ip']} MAC: {a['mac']} Fabricant: {fabricant}\n")
                appareils_connus[a['mac']] = a['ip']
            else:
                statut = Fore.GREEN + "✅ Connu" + Style.RESET_ALL

            print(f"{Fore.YELLOW}{a['ip']:<20}{Style.RESET_ALL} {a['mac']:<20} {Fore.BLUE}{fabricant:<25}{Style.RESET_ALL} {statut}")

    print(f"\n{Fore.CYAN}✅ {len(appareils)} appareil(s) — Prochain scan dans 30 secondes...{Style.RESET_ALL}")

print(Fore.GREEN + "🚀 Démarrage du scanner Blue Team..." + Style.RESET_ALL)
reseau = "192.168.10.0/24"

while True:
    appareils = scanner(reseau)
    afficher(appareils)
    time.sleep(30)