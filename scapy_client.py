from scapy.all import *

while True:
    msg = input("enter word with exactly five letters ")

    if not len(msg) != 5:
        packet = IP(dst="10.0.0.8") / UDP(dport=2000) / Raw(load=msg)
        send(packet, verbose=False)
        if msg == "exit!":
            break
    else:
        print("not five letters")
