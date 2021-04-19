#! /usr/bin/env python
import scapy.all as scapy

# function sniff has three parameters. Iface will be added each time function is called. Store=false is saying that no
# packets should be stored in memory. Last parameter is prc which is calling function process_sniffed_packet for each
# packet received

def sniff(interface):
    scapy.sniff(iface=interface,store=False, prn=process_sniffed_packet)
# function which will print packet for now
def process_sniffed_packet(packet):
    print(packet)

sniff("en0")