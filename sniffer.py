#!/usr/bin/python
from scapy.all import *

def dnsMonitorCallBack(pkt):
    print("packet received")
    if pkt.haslayer(DNS):
        pkt.show()
sniff(prn=dnsMonitorCallBack)