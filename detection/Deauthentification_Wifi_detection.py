from scapy.all import *

# Fonction pour traiter les paquets Wi-Fi
def wifi_packet_handler(pkt):
    if pkt.haslayer(Dot11Deauth):
        # Si un paquet de déauthentification est détecté, affichez les informations pertinentes.
        print("Détection d'un paquet de déauthentification :")
        print("Adresse MAC source : " + pkt.addr2)
        print("Adresse MAC de destination : " + pkt.addr1)
        print("BSSID : " + pkt.addr3)
        print("Canal : " + str(ord(pkt[Dot11Elt:3].info)))
        print("============================")

# Fonction principale pour démarrer la capture de paquets
def main():
    interface = input("Entrez le nom de votre interface Wi-Fi (ex : wlan0) : ")
    print("Démarrage de la capture de paquets Wi-Fi sur l'interface " + interface + "...")
    sniff(iface=interface, prn=wifi_packet_handler, store=False)

if __name__ == "__main__":
    main()  