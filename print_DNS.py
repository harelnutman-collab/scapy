from scapy.all import *
from scapy.layers.dns import DNSRR

my_face = conf.route.route("8.8.8.8")[0]
my_ip = conf.route.route("8.8.8.8")[1]

def DNSFilter(p):
    return DNS in p and IP in p and p[IP].dst == my_ip and p[DNS].qr == 1 and p[DNS].opcode == 0 and p[DNS].ancount > 0

def DNSPrint(p):
    for i in range(p[DNS].ancount):
        answer = p[DNS].an[i]
        if answer.type == 1:
            print(answer.rdata)


p = sniff(iface=my_face,count=10, lfilter=DNSFilter, prn=DNSPrint)