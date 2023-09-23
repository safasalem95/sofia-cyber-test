import argparse
import sys
import os 
import time 
import random
import scapy.all
import threading

from PyQt5.QtCore import QObject, QThread, pyqtSignal, QWaitCondition, QMutex

from scapy.all import *

class rtsJob(threading.Thread):

    def __init__(self, target, source, nicDevice):
        threading.Thread.__init__(self)
        self.setDaemon = True
        self.nicDevice = nicDevice
        self.source = source
        self.target = target
        self.packet = None
        self.plock = threading.Lock()

    def getInfo(self):
        self.info = []
        self.info.append(self.source)
        self.info.append(self.target)
        return self.info

    def run(self):
        self.channel = 0
        while self.channel < 14:
            self.channel += 1
            os.system('sudo iwconfig %s channel %d' %(self.nicDevice, self.channel))
            self.packet = RadioTap()/Dot11(type=1, subtype=11, addr1=self.target, addr2=self.source)
            for y in range(5):
                sendp(self.packet, iface=self.nicDevice, verbose=0)
            time.sleep(0.2)

class SofiaRTSAttack(QObject):

    def __init__(self, append_log):
        super().__init__()

        self.append_log = append_log
        self.foundDevices = []
        self.nicDevice = "wlan1"
        self.newThread = None
        self.mlist = []
        self.onetarget = None
        self.loopTime = 1
        self.allThreads = []

        self.target = "14:d1:69:6f:26:c1"
        self.randomSource = self.getrandomMAC()
        # Set the target and it's corresponded random MAC into the MAC dictionary, len(macDic)=1
        self.macDictionnary = {}
        self.macDictionnary[self.target] = self.randomSource

    def getValue(self, random):
        for k,v in self.macDictionnary.items():
            if v == random:
                return k

    def goodRandomMac(self, random):
        test = False
        for k,v in self.macDictionnary.items():
            if v == random:
                test = True
        return test

    def lookingForCts(self, ppp):
        if ppp.haslayer(Dot11):
            ptype = ppp.getlayer(Dot11).type
            stype = ppp.getlayer(Dot11).subtype
            adone = ppp.getlayer(Dot11).addr1
            if ptype == 1 and stype == 12:
                if self.goodRandomMac(adone) and self.getValue(adone) not in self.foundDevices:
                    self.foundDevices.append(self.getValue(adone))

    def getrandomMAC(self):
        return "52:54:00:%02x:%02x:%02x" % (
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            )

    def allDead(self):
        tt = True
        for u in self.allThreads:
            if u.is_alive():
                tt = False
        return tt


    def sniffing(self):
        while not self.allDead():
            sniff(iface=self.nicDevice, prn=self.lookingForCts)

    def main(self):
        
        self.append_log(f"[RTS] Looking for: {self.target}")
        j = 0
        while j < self.loopTime:
            self.append_log("[+] Loop <%d>" %(j+1))
            j += 1

            for target, source in self.macDictionnary.items():
                time.sleep(1)
                self.allThreads.append(rtsJob(target, source, self.nicDevice))
                
            for rr in self.allThreads:
                rr.start()

            sniffThread = threading.Thread(target=self.sniffing, args=())
            sniffThread.setDaemon(True)
            sniffThread.start()

            for rr in self.allThreads:
                rr.join()
        
        if len(self.foundDevices) == 0:
            self.append_log("[RTS][-] Nothing FOUND")
        else:
            for ll in self.foundDevices:
                self.append_log("[RTS][+] Found: %s" %ll)