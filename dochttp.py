from scapy.all import *
from colorama import init, Fore
import netfilterqueue
import re

init()

GREEN = Fore.GREEN
REST = Fore.RESET


def process_packet(packet):
    