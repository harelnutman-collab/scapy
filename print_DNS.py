from scapy.all import *
from scapy.layers.dns import DNSRR

my_face = conf.route.route("8.8.8.8")[0]
my_ip = conf.route.route("8.8.8.8")[1]

def DNSFilter(p):
    """
    the func check if all is valid
    :param p: the packet
    :return: True if it valid False if not
    """
    return DNS in p and IP in p and p[IP].dst == my_ip and p[DNS].qr == 1 and p[DNS].opcode == 0 and p[DNS].ancount > 0

def DNSPrint(p):
    print(p[DNSRR].rdata)


p = sniff(iface=my_face,count=10, lfilter=DNSFilter, prn=DNSPrint)