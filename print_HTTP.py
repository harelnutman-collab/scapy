from scapy.all import *

my_face = conf.route.route("8.8.8.8")[0]

def HTTPFilter(p):
    return TCP in p and Raw in p and p[Raw].load.startswith(b'GET ')

def HTTPrint(p):
    first = p[Raw].load.split(b"GET ")[1]
    print(first.split(b" HTTP/")[0].decode())
p = sniff(iface=my_face,count=10, lfilter=HTTPFilter, prn=HTTPrint)