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

class SofiaCyberTestSingleton:
   def __new__(cls):
    if not hasattr(cls, 'instance'):
      cls.instance = super(SofiaCyberTestSingleton, cls).__new__(cls)
    return cls.instance

   def __init__(self) -> None:

      self.arp_attack_loop = True

      self.log = "Cliquez sur n'importe quel bouton pour détecter l'attaque ou pour lancer l'attaque."
      self.app = QApplication(sys.argv)
      self.widget = QWidget()
      self.terminal= QTextEdit(self.widget)
      self.terminal.setReadOnly(True)
      self.terminal.setAlignment(Qt.AlignTop)
      self.first_row=100
      self.first_colomn=[50,150,250,350,450,550]
      self.second_row=1030
      self.second_column=[50,150,250,350,450,550]
      self.column_offset = 50

      for i in range(6):
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
      self.attack_dos = QPushButton(self.widget)
      self.attack_dos.setText("DOS")
      self.attack_dos.resize(150, 50)
      self.attack_dos.move(self.first_row, self.first_colomn[3])
      self.attack_dos.clicked.connect(self.DOS_attack)
      self.attack_men_in_the_middle = QPushButton(self.widget)
      self.attack_men_in_the_middle.setText("MITM")
      self.attack_men_in_the_middle.resize(150, 50)
      self.attack_men_in_the_middle.move(self.first_row, self.first_colomn[2])
      self.attack_men_in_the_middle.clicked.connect(self.men_in_the_middle_attack)
      self.first_attack_wifi = QPushButton(self.widget)
      self.first_attack_wifi.setText("Deauthentication\nWifi")
      self.first_attack_wifi.resize(160, 50)
      self.first_attack_wifi.move(self.first_row, self.first_colomn[4])
      self.first_attack_wifi.clicked.connect(self.Deauthentification_Wifi_attack)
      self.second_attack_wifi = QPushButton(self.widget)
      self.second_attack_wifi.setText("RTS/CTS")
      self.second_attack_wifi.resize(150, 50)
      self.second_attack_wifi.move(self.first_row, self.first_colomn[5])
      self.second_attack_wifi.clicked.connect(self.RTS_CTS_attack)
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
      self.detection_first_wifi = QPushButton(self.widget)
      self.detection_first_wifi.setText("Deauthentication\nWifi")
      self.detection_first_wifi.resize(160, 50)
      self.detection_first_wifi.move(self.second_row, self.second_column[4])
      self.detection_first_wifi.clicked.connect(self.Deauthentification_Wifi_detection)
      self.detection_second_wifi = QPushButton(self.widget)
      self.detection_second_wifi.setText("RTS/CTS")
      self.detection_second_wifi.resize(150, 50)
      self.detection_second_wifi.move(self.second_row, self.second_column[5])
      self.detection_second_wifi.clicked.connect(self.RTS_CTS_detection)
      self.detection_dos = QPushButton(self.widget)
      self.detection_dos.setText("DOS")
      self.detection_dos.resize(150, 50)
      self.detection_dos.move(self.second_row, self.second_column[3])
      self.detection_dos.clicked.connect(self.DOS_detection)
      self.detection_men_in_the_middle = QPushButton(self.widget)
      self.detection_men_in_the_middle.setText("MITM")
      self.detection_men_in_the_middle.resize(150, 50)
      self.detection_men_in_the_middle.move(self.second_row, self.second_column[2])
      self.detection_men_in_the_middle.clicked.connect(self.men_in_the_middle_detection)
      self.terminal.setText(self.log)
      self.terminal.resize(700,450)
      self.terminal.move(self.first_row+190, self.second_column[0])
      self.widget.setGeometry(50,50,1100,600)
      self.widget.setWindowTitle("Plateforme de Penetration d'Attaque")
      self.widget.setFixedWidth(1280)
      self.widget.setFixedHeight(700)

      # Define attacks
      self.arp_attack = SofiaArpSpoofAttack(self.append_log, True)
      self.hostDict = {b"google.com.": "192.168.56.1", b"facebook.com.": "192.168.56.1"}
      self.queueNum = 1
      self.dns_attack = SofiaDnsSpoofingAttack(self.hostDict, self.queueNum, self.append_log)

   def refresh(self):
      self.app.processEvents()

   def append_log(self, text):
      self.terminal.append(text)
      self.refresh()

   def run(self):
      self.widget.show()
      sys.exit(self.app.exec_())

   def dns_spoofing_attack(self):
      import time
      if self.attack_dns_spoofing.text() == "DNS SPOOFING":
         if self.attack_arp_spoofing.text() != "STOP":
            self.append_log("You need to start ARP attack first !")
         else:
            self.attack_dns_spoofing.setText("STOP")
            self.append_log("[+] Starting ARP Spoofing attack for MITM ..")
            self.dns_attack.run()
            #threading.Thread(target=self.dns_attack.run(), args=()).start()

      elif self.attack_dns_spoofing.text() == "STOP":
         self.append_log("Stopping DNS attack ......")
         self.attack_dns_spoofing.setText("DNS SPOOFING")
         # Stop ARP first
         self.arp_attack.stop()
         # Stop DNS

   def dns_spoofing_detection(self):
      print("START DNS SPOOFING")
      #cmd = "python3 ./dns_attack.py"
      #log=subprocess.run(cmd, shell=True)
      cmd=subprocess.Popen('python3 ./detection/DNS_SPOOFING_detection.py', shell=True, stdout=subprocess.PIPE, )
      log=cmd.communicate()[0]
      log=log.decode("utf-8")
      print(log)
      terminal.setText(log)
      
   def arp_spoofing_attack(self):
      if self.attack_arp_spoofing.text() == "ARP SPOOFING":
         self.arp_attack.set_loop(True)
         self.attack_arp_spoofing.setText("STOP")
         self.terminal.clear()
         threading.Thread(target=self.arp_attack.run(), args=()).start()

      elif self.attack_arp_spoofing.text() == "STOP":
         self.attack_arp_spoofing.setText("ARP SPOOFING")
         self.arp_attack.stop()

   def arp_spoofing_detection(self):
      print("START DNS SPOOFING")
      #cmd = "python3 ./ARP_SPOOFING_detection.py"
      #log=subprocess.run(cmd, shell=True)
      cmd=subprocess.Popen('python3 ./detection/ARP_SPOOFING_detection.py', shell=True, stdout=subprocess.PIPE, )
      log=cmd.communicate()[0]
      log=log.decode("utf-8")
      print(log)
      terminal.setText(log)

   def Deauthentification_Wifi_attack(self):
      print("DOS")

      cmd=subprocess.Popen('python3 ./attack/Deauthentification_Wifi_attack.py', shell=True, stdout=subprocess.PIPE, )
      log=cmd.communicate()[0]
      log=log.decode("utf-8")
      terminal.setText(log)

   def Deauthentification_Wifi_detection(self):
      print("DOS")

      cmd=subprocess.Popen('python3 ./detection/Deauthentification_Wifi_detection.py', shell=True, stdout=subprocess.PIPE, )
      log=cmd.communicate()[0]
      log=log.decode("utf-8")
      terminal.setText(log)

   def RTS_CTS_attack(self):

      cmd=subprocess.Popen('python3 ./attack/RTS_CTS_attack.py', shell=True, stdout=subprocess.PIPE, )
      log=cmd.communicate()[0]
      log=log.decode("utf-8")
      terminal.setText(log)

   def RTS_CTS_detection(self):
      
      cmd=subprocess.Popen('python3 ./detection/RTS_CTS_detection.py', shell=True, stdout=subprocess.PIPE, )
      log=cmd.communicate()[0]
      log=log.decode("utf-8")
      terminal.setText(log)

   def DOS_attack(self):

      cmd=subprocess.Popen('python3 ./attack/DOS_attack.py', shell=True, stdout=subprocess.PIPE, )
      log=cmd.communicate()[0]
      log=log.decode("utf-8")
      terminal.setText(log)

   def DOS_detection(self):
      print("DDOS")
      #cmd = "python3 ./ddos_attack.py"
      cmd=subprocess.Popen('python3 ./detection/DOS_detection.py', shell=True, stdout=subprocess.PIPE, )
      log=cmd.communicate()[0]
      log=log.decode("utf-8")
      terminal.setText(log)

   def men_in_the_middle_attack(self):
      print("MEN in the middle")
      #cmd = "python3 ./middle_attack.py"
      cmd=subprocess.Popen('python3 ./attack/MITM_attack.py', shell=True, stdout=subprocess.PIPE, )
      log=cmd.communicate()[0]
      log=log.decode("utf-8")
      terminal.setText(log)

   def men_in_the_middle_detection(self):
      print("MEN in the middle")
      #cmd = "python3 ./middle_attack.py"
      cmd=subprocess.Popen('python3 ./detection/MITM_detection.py', shell=True, stdout=subprocess.PIPE, )
      log=cmd.communicate()[0]
      log=log.decode("utf-8")
      terminal.setText(log)
   
if __name__ == '__main__':
   sofia_app = SofiaCyberTestSingleton()
   sofia_app.run()