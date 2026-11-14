from scapy.all import *

my_face = conf.route.route("8.8.8.8")[0]

def HTTPFilter(p):
    """
    the func check if the packet is valid
    :param p: the packet
    :return: True if valid False if not
    """
    return TCP in p and Raw in p and p[Raw].load.startswith(b'GET ')

def HTTPrint(p):
    """
    the func print the url
    :param p: the packet
    :return: None
    """
    first = p[Raw].load.split(b"GET ")[1]
    print(first.split(b" HTTP/")[0].decode())
p = sniff(iface=my_face,count=10, lfilter=HTTPFilter, prn=HTTPrint)