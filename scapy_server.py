from scapy.all import *

my_port = 2000
my_IP = "10.0.0.8"


def IP_UDP_Filetr(p):
    """
    the func check if the IP is mine and the port
    :param p: the packet
    :return: True if same IP False if not
    """
    return IP in p and p[IP].dst == my_IP and UDP in p and p[UDP].dport == my_port


def RawFilter(p):
    """
    the func print the data
    :param p: the packet
    :return: None
    """
    print(p[0][Raw].load.decode())

word = ""
while word != "exit!":
    p = sniff(count = 1, lfilter = IP_UDP_Filetr, prn = RawFilter)
    word = p[0][Raw].load.decode()