import scapy.all as scapy
import time

from PyQt5.QtCore import QObject, QThread, pyqtSignal, QWaitCondition, QMutex

# Liste pour stocker les adresses IP et MAC connues
known_devices = {}

class SofiaArpSpoofingDetect(QObject):

    finished = pyqtSignal()

    def __init__(self, append_log, loop) -> None:
        super().__init__()
        
        self.loop = loop
        self.done = False
        self.append_log = append_log

    # Fonction pour afficher la table ARP actuelle
    def display_arp_table(self):
        self.append_log("[Detection ARP] Adresse IP\t\tAdresse MAC")
        self.append_log("[Detection ARP] ------------------------------------------")
        for ip, mac in known_devices.items():
            self.append_log("[Detection ARP]" + ip + "\t\t" + mac)

    # Fonction pour détecter l'ARP Spoofing
    def detect_arp_spoof(self, packet):
        if packet.haslayer(scapy.ARP):
            arp_packet = packet[scapy.ARP]
            # Ignorer les requêtes ARP (ARP Request)
            if arp_packet.op == 1:
                return
            device_ip = arp_packet.psrc
            device_mac = arp_packet.hwsrc
            if device_ip in known_devices:
                if known_devices[device_ip] != device_mac:
                    self.append_log("[Detection ARP][WARNING] ARP Spoofing detected! IP: " + device_ip + ", MAC: " + device_mac)
            else:
                known_devices[device_ip] = device_mac

    def run(self):
        # Démarrer la détection ARP Spoofing en écoutant le trafic ARP
        try:
            self.append_log("[Detection ARP] Démarrage de la détection ARP Spoofing...")
            while self.loop:
                sniffed_packet = scapy.sniff(iface="wlan0", filter="arp", count=1)
                self.detect_arp_spoof(sniffed_packet[0])
            self.finished.emit()
            self.done = True
        except KeyboardInterrupt:
            self.append_log("[Detection ARP] Arrêt de la détection ARP Spoofing...")