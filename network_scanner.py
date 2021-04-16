#!/usr/bin/env python

import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="ip_address", help="specify targets to scan")
    (options) = parser.parse_args()
    if not options.ip_address:
        print("You have to add address")
        exit(1)
    return options.ip_address


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"IP": element[1].psrc, "MAC": element[1].hwsrc}
        clients_list.append(client_dict)

    return clients_list


def print_result(result_list):
    print("IP\t\t\tMAC Address\n---------------------------------------")
    for client in result_list:
        print(client["IP"] + "\t\t" + client["MAC"])


scan_result = scan(get_arguments())

print_result(scan_result)
