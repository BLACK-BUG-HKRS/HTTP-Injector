from scapy.all import *
from colorama import init, Fore
import netfilterqueue
import re

init()

GREEN = Fore.GREEN
REST = Fore.RESET


def process_packet(packet):
    # executed whenever the packet is sniffed

    # convert the netfilterqueue packet into scapy packet
    spacket = IP(packet.get_payload())

    if spacket.haslayer(Raw) and spacket.haslayer(TCP):

        if spacket[TCP].dport == 80:

            print(f"[*] Detected HTTP Request from {spacket[IP]}")