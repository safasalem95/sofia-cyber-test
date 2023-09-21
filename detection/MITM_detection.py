import time
import subprocess

def get_gateway_mac():
    try:
        # Exécute la commande 'arp -n' pour obtenir la table ARP
        result = subprocess.check_output(["arp", "-n"])
        result = result.decode("utf-8")
        # Recherche de la ligne contenant la passerelle par défaut (0.0.0.0)
        gateway_line = [line for line in result.splitlines() if "0.0.0.0" in line]
        if gateway_line:
            gateway_info = gateway_line[0].split()
            if len(gateway_info) >= 3:
                return gateway_info[2]
    except Exception as e:
        print(f"Erreur lors de la récupération de l'adresse MAC de la passerelle : {e}")
    return None

def detect_mitm():
    while True:
        # Obtenir l'adresse MAC actuelle de la passerelle
        current_gateway_mac = get_gateway_mac()
        
        if current_gateway_mac:
            # Vérifier si l'adresse MAC de la passerelle a changé
            if current_gateway_mac != previous_gateway_mac:
                print("Alerte : Changement dans l'adresse MAC de la passerelle ! Possible attaque MITM.")
                # Vous pouvez prendre des mesures supplémentaires ici, comme avertir l'administrateur.
            
            # Mettre à jour l'adresse MAC précédente
            previous_gateway_mac = current_gateway_mac
        
        # Attendre un certain temps avant de vérifier à nouveau
        time.sleep(60)

if __name__ == "__main__":
    previous_gateway_mac = get_gateway_mac()
    if previous_gateway_mac:
        print(f"Adresse MAC de la passerelle initiale : {previous_gateway_mac}")
        detect_mitm()
    else:
        print("Impossible de récupérer l'adresse MAC de la passerelle.")

