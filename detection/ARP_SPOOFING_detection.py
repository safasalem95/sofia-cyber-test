import scapy.all as scapy
import time

# Liste pour stocker les adresses IP et MAC connues
known_devices = {}

# Fonction pour afficher la table ARP actuelle
def display_arp_table():
    print("Adresse IP\t\tAdresse MAC")
    print("------------------------------------------")
    for ip, mac in known_devices.items():
        print(ip + "\t\t" + mac)

# Fonction pour détecter l'ARP Spoofing
def detect_arp_spoof(packet):
    if packet.haslayer(scapy.ARP):
        arp_packet = packet[scapy.ARP]
        # Ignorer les requêtes ARP (ARP Request)
        if arp_packet.op == 1:
            return
        device_ip = arp_packet.psrc
        device_mac = arp_packet.hwsrc
        if device_ip in known_devices:
            if known_devices[device_ip] != device_mac:
                print("[WARNING] ARP Spoofing detected! IP: " + device_ip + ", MAC: " + device_mac)
        else:
            known_devices[device_ip] = device_mac

# Démarrer la détection ARP Spoofing en écoutant le trafic ARP
try:
    print("Démarrage de la détection ARP Spoofing...")
    while True:
        sniffed_packet = scapy.sniff(iface="votre_interface_reseau", filter="arp", count=1)
        detect_arp_spoof(sniffed_packet[0])
except KeyboardInterrupt:
    print("Arrêt de la détection ARP Spoofing...")