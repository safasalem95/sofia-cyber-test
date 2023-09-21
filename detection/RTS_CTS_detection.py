from scapy.all import *

def detect_rts_cts_attack(packet):
    if packet.haslayer(Dot11RTS):
        print("RTS Frame Detected: Possible RTS/CTS Attack")
    elif packet.haslayer(Dot11CTS):
        print("CTS Frame Detected: Possible RTS/CTS Attack")

def main(interface):
    sniff(iface=interface, prn=detect_rts_cts_attack)

if __name__ == "__main__":
    interface = "votre_interface_wifi"  # Remplacez par le nom de votre interface Wi-Fi (par exemple, "wlan0" sous Linux)
    main(interface)