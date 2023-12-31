################################################################################
#      _____  _       _        __                                _             #
#     |  __ \| |     | |      / _|                              | |            #
#     | |__) | | __ _| |_ ___| |_ ___  _ __ _ __ ___   ___    __| | ___        #
#     |  ___/| |/ _` | __/ _ \  _/ _ \| '__| '_ ` _ \ / _ \  / _` |/ _ \       #
#     | |    | | (_| | ||  __/ || (_) | |  | | | | | |  __/ | (_| |  __/       #
#     |_|    |_|\__,_|\__\___|_| \___/|_|  |_| |_| |_|\___|  \__,_|\___|       #
#                                                                              #
#                                                                              #
#               _____           _            _   _                             #
#              |  __ \         | |          | | (_)                            #
#              | |__) |__ _ __ | |_ ___  ___| |_ _ _ __   __ _                 #
#              |  ___/ _ \ '_ \| __/ _ \/ __| __| | '_ \ / _` |                #
#              | |  |  __/ | | | ||  __/\__ \ |_| | | | | (_| |                #
#              |_|   \___|_| |_|\__\___||___/\__|_|_| |_|\__, |                #
#                                                         __/ |                #
#                                                        |___/                 #
################################################################################

"""
['dark_amber.xml',
 'dark_blue.xml',
 'dark_cyan.xml',
 'dark_lightgreen.xml',
 'dark_pink.xml',
 'dark_purple.xml',
 'dark_red.xml',
 'dark_teal.xml',
 'dark_yellow.xml',
 'light_amber.xml',
 'light_blue.xml',
 'light_cyan.xml',
 'light_cyan_500.xml',
 'light_lightgreen.xml',
 'light_pink.xml',
 'light_purple.xml',
 'light_red.xml',
 'light_teal.xml',
 'light_yellow.xml']
 """

import sys
import threading

from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
import subprocess
from qt_material import *
from attack.ARP_SPOOFING_attack import SofiaArpSpoofAttack
from attack.DNS_SPOOFING import SofiaDnsSpoofingAttack
from detection.ARP_SPOOFING_detection import SofiaArpSpoofingDetect
from detection.DNS_SPOOFING_detection import SofiaDnsSpoofingDetect
from attack.Deauthentification_Wifi_attack import SofiaDeauthAttack
from attack.rts import SofiaRTSAttack

class WorkerRunnable(QRunnable):
    def __init__(self, worker):
        super().__init__()
        self.worker = worker

    def run(self):
        self.worker.finished.connect(self.on_finished)
        self.worker.run()

    def on_finished(self):
        self.worker.finished.disconnect(self.on_finished)
        self.worker = None

class SofiaCyberTest:
   def __init__(self) -> None:

      self.log = "Cliquez sur n'importe quel bouton pour détecter l'attaque ou pour lancer l'attaque."
      self.app = QApplication(sys.argv)
      self.widget = QWidget()
      self.terminal= QTextEdit(self.widget)
      self.terminal.setReadOnly(True)
      self.terminal.setAlignment(Qt.AlignTop)
      self.first_row=100
      self.first_colomn=[50,150,250,350,450]
      self.second_row=1030
      self.second_column=[50,150,250,350,450]
      self.column_offset = 50

      for i in range(5):
         self.first_colomn[i] += self.column_offset
         self.second_column[i] += self.column_offset

      apply_stylesheet(self.app, theme='dark_amber.xml')
      self.attacks_title = QLabel(self.widget)  #Création des zones pour les labels
      self.detections_title = QLabel(self.widget) #Création des zones pour les labels
      self.logo_sofia = QLabel(self.widget) #Création des zones pour les labels
      self.application_title = QLabel(self.widget) #Création des zones pour les labels
      self.attacks_title.setStyleSheet("QLabel{font-size: 12pt;font:bold}") #Caractéristiques
      self.detections_title.setStyleSheet("QLabel{font-size: 12pt;font:bold}")
      self.logo_sofia.setStyleSheet("QLabel{font-size: 12pt;}")
      self.application_title.setStyleSheet("QLabel{font-size: 28pt;font:bold}")
      self.terminal.setStyleSheet("QTextEdit{font-size:10;font:bold/italic}")
      self.palette = QPalette()
      self.palette.setColor(QPalette.Window,Qt.blue)
      self.attacks_title.setPalette(self.palette)
      self.attacks_title.setAlignment(Qt.AlignCenter)
      self.detections_title.setPalette(self.palette)
      self.detections_title.setAlignment(Qt.AlignCenter)
      self.application_title.setPalette(self.palette)
      self.application_title.setAlignment(Qt.AlignCenter)
      self.attacks_title.setText("Attaques")
      self.attacks_title.resize(150, 50)
      self.attacks_title.move(self.first_row,(self.first_colomn[0])-50)
      self.detections_title.setText("Détections")
      self.detections_title.resize(150, 50)
      self.detections_title.move(self.second_row,(self.first_colomn[0])-50)
      self.application_title.setText("Plateforme de 'Pentesting' ")
      self.application_title.resize(550, 350)
      self.application_title.move(365,(self.first_colomn[0])-220)

      self.logo_sofia.setPixmap(QPixmap("logo.png"))
      self.logo_sofia.resize(370, 80)
      self.logo_sofia.move(480,600)

      self.attack_dns_spoofing = QPushButton(self.widget)
      self.attack_dns_spoofing.setText("DNS SPOOFING")
      self.attack_dns_spoofing.resize(150, 50)
      self.attack_dns_spoofing.move(self.first_row, self.first_colomn[1])
      self.attack_dns_spoofing.clicked.connect(self.dns_spoofing_attack)

      self.attack_arp_spoofing = QPushButton(self.widget)
      self.attack_arp_spoofing.setText("ARP SPOOFING")
      self.attack_arp_spoofing.resize(150, 50)
      self.attack_arp_spoofing.move(self.first_row, self.first_colomn[0])
      self.attack_arp_spoofing.clicked.connect(self.arp_spoofing_attack)

      self.deuath_attack_wifi = QPushButton(self.widget)
      self.deuath_attack_wifi.setText("Deauthentication\nWifi")
      self.deuath_attack_wifi.resize(160, 50)
      self.deuath_attack_wifi.move(self.first_row, self.first_colomn[2])
      self.deuath_attack_wifi.clicked.connect(self.Deauthentification_Wifi_attack)

      self.rts_cts_attack_wifi = QPushButton(self.widget)
      self.rts_cts_attack_wifi.setText("RTS/CTS")
      self.rts_cts_attack_wifi.resize(150, 50)
      self.rts_cts_attack_wifi.move(self.first_row, self.first_colomn[3])
      self.rts_cts_attack_wifi.clicked.connect(self.RTS_CTS_attack)

      self.detection_dns_spoofing = QPushButton(self.widget)
      self.detection_dns_spoofing.setText("DNS SPOOFING")
      self.detection_dns_spoofing.resize(150, 50)
      self.detection_dns_spoofing.move(self.second_row, self.second_column[1])
      self.detection_dns_spoofing.clicked.connect(self.dns_spoofing_detection)

      self.detection_arp_spoofing = QPushButton(self.widget)
      self.detection_arp_spoofing.setText("ARP SPOOFING")
      self.detection_arp_spoofing.resize(150, 50)
      self.detection_arp_spoofing.move(self.second_row, self.second_column[0])
      self.detection_arp_spoofing.clicked.connect(self.arp_spoofing_detection)

      self.terminal.setText(self.log)
      self.terminal.resize(700,450)
      self.terminal.move(self.first_row+190, self.second_column[0])

      self.widget.setGeometry(50,50,1100,600)
      self.widget.setWindowTitle("Plateforme de Penetration d'Attaque")
      self.widget.setFixedWidth(1280)
      self.widget.setFixedHeight(700)

      # Define attacks
      self.threadpool = QThreadPool()
      self.arp_attack_worker = None
      self.dns_attack_worker = None
      self.arp_attack_detector = None
      self.dns_attack_detector = None

      self.hostDict = {b"google.com.": "192.168.43.201", b"facebook.com.": "192.168.43.201"}
      self.queueNum = 1

   def refresh(self):
      self.app.processEvents()

   def append_log(self, text):
      self.terminal.append(text)
      self.refresh()
      self.terminal.verticalScrollBar().setValue(self.terminal.verticalScrollBar().maximum())

   def run(self):
      self.widget.show()
      sys.exit(self.app.exec_())

   def dns_spoofing_attack(self):
      if not self.arp_attack_worker:
         self.append_log("[DNS] You need to start ARP Spoofing first!")
      else:
         if not self.dns_attack_worker:
            self.dns_attack_worker = SofiaDnsSpoofingAttack(self.hostDict, self.queueNum, self.append_log, True)
            runnable = WorkerRunnable(self.dns_attack_worker)
            self.threadpool.start(runnable)
            self.attack_dns_spoofing.setText("STOP DNS")
         else:
            self.stop("DNS Spoofing", self.dns_attack_worker, self.attack_dns_spoofing, "DNS SPOOFING")
            self.dns_attack_worker = None

   def dns_spoofing_detection(self):
      self.append_log(f"Worker: {self.dns_attack_detector}")
      if not self.dns_attack_detector:
         self.terminal.clear()

         self.dns_attack_detector = SofiaDnsSpoofingDetect(self.append_log, True)
         runnable = WorkerRunnable(self.dns_attack_detector)
         self.threadpool.start(runnable)

         self.detection_dns_spoofing.setText("STOP")
      else:
         self.stop("DNS Detection", self.dns_attack_detector, self.detection_dns_spoofing, "DNS SPOOFING")
         self.dns_attack_detector = None

   def arp_spoofing_attack(self):
      if not self.arp_attack_worker:
         self.terminal.clear()

         self.arp_attack_worker = SofiaArpSpoofAttack(self.append_log, True)
         runnable = WorkerRunnable(self.arp_attack_worker)
         self.threadpool.start(runnable)

         self.attack_arp_spoofing.setText("STOP ARP")
      else:
         self.stop("ARP Attack", self.arp_attack_worker, self.attack_arp_spoofing, "ARP SPOOFING")
         self.arp_attack_worker = None
         if self.dns_attack_worker:
            self.stop("DNS Spoofing", self.dns_attack_worker, self.attack_dns_spoofing, "DNS SPOOFING")
            self.dns_attack_worker = None

   def stop(self, job, worker, button, text):
      worker.loop = False
      self.append_log(f"Waiting for the {job} to finish ...")
      import time
      while not worker.done:
         time.sleep(1)
      button.setText(text)
      self.append_log(f"{job} is done")

   def arp_spoofing_detection(self):
      self.append_log(f"Worker: {self.arp_attack_detector}")
      if not self.arp_attack_detector:
         self.terminal.clear()

         self.arp_attack_detector = SofiaArpSpoofingDetect(self.append_log, True)
         runnable = WorkerRunnable(self.arp_attack_detector)
         self.threadpool.start(runnable)

         self.detection_arp_spoofing.setText("STOP")
      else:
         self.stop("ARP Detection", self.arp_attack_detector, self.detection_arp_spoofing, "ARP SPOOFING")
         self.arp_attack_detector = None

   def Deauthentification_Wifi_attack(self):
      deauth = SofiaDeauthAttack(self.append_log)
      deauth.run()

   def RTS_CTS_attack(self):
      rts_attack = SofiaRTSAttack(self.append_log)
      rts_attack.main()
   
if __name__ == '__main__':
   sofia_app = SofiaCyberTest()
   sofia_app.run()