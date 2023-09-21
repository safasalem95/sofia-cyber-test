import socket

def dns_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return None

def check_dns_spoofing(domain, authentic_ip):
    resolved_ip = dns_lookup(domain)
    
    if resolved_ip is None:
        print(f"Impossible de résoudre le domaine {domain}.")
    elif resolved_ip == authentic_ip:
        print(f"Le domaine {domain} a résolu correctement avec l'IP {resolved_ip}.")
    else:
        print(f"Alerte ! Le domaine {domain} a résolu avec l'IP {resolved_ip}, mais l'IP attendue était {authentic_ip}. Possible DNS spoofing.")

if __name__ == "__main__":
    domain_to_check = "example.com"
    authentic_ip = "93.184.216.34"  # L'IP authentique de example.com

    check_dns_spoofing(domain_to_check, authentic_ip)