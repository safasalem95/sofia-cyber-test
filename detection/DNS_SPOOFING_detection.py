import socket

from PyQt5.QtCore import QObject, QThread, pyqtSignal, QWaitCondition, QMutex

class SofiaDnsSpoofingDetect(QObject):
    finished = pyqtSignal()
      
    def __init__(self, append_log, loop) -> None:
        super().__init__()
        self.loop = loop
        self.done = False
        self.append_log = append_log

    def dns_lookup(self, domain):
        try:
            ip = socket.gethostbyname(domain)
            return ip
        except socket.gaierror:
            return None

    def check_dns_spoofing(self, domain, authentic_ip):
        resolved_ip = self.dns_lookup(domain)

        if resolved_ip is None:
            self.append_log(f"[DNS DETECT] Impossible de résoudre le domaine {domain}.")
        elif resolved_ip != authentic_ip:
            self.append_log(f"[DNS DETECT] Alerte ! Le domaine {domain} a résolu avec l'IP {resolved_ip}, mais l'IP attendue était {authentic_ip}. Possible DNS spoofing.")

    def run(self):
        import time
        self.append_log("[DNS DETECTION] Starting ...")
        while self.loop:
            domain_to_check = "google.com"
            authentic_ip = "142.251.209.46"  # L'IP authentique de example.com
            self.check_dns_spoofing(domain_to_check, authentic_ip)
            time.sleep(2)
        self.finished.emit()
        self.done = True
