#! /usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

# function sniff has three parameters. Iface will be added each time function is called. Store=false is saying that no
# packets should be stored in memory. Last parameter is prc which is calling function process_sniffed_packet for each
# packet received

def sniff(interface):
    scapy.sniff(iface=interface,store=False, prn=process_sniffed_packet)


# function which will check if there is a HTTP Request in it, if yes it will
# also check RAW layer which was shown by packet.show and its the layer which contain username and password information
# if this condition is also met it will be printed. Its ising scapy.layers

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw].load)
            #print(packet.show())
sniff("en0")