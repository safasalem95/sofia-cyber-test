import socket

# Paramètres
HOST = 'votre_ip'  # Votre adresse IP
PORT = 80          # Le port que vous souhaitez surveiller
SEUIL_TRAFIC = 1000  # Seuil de trafic (à ajuster selon vos besoins)

# Créer une socket pour écouter le trafic entrant
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))

trafic_total = 0

while True:
    data, addr = sock.recvfrom(1024)
    trafic_total += len(data)

    if trafic_total > SEUIL_TRAFIC:
        print(f"Attaque DDoS possible détectée depuis {addr[0]}!")
        # Ici, vous pouvez mettre en place des actions en réponse à l'attaque, comme bloquer l'adresse IP.

# Fermer la socket (Cela ne sera pas atteint dans cet exemple)
sock.close()


