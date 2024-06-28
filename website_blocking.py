import scapy.all as scapy
from collections import Counter
from scapy.all import sniff
from scapy.all import DNS, DNSQR, IP, sr1, UDP
import socket
import dns.resolver, dns.reversename
from socket import socket as socki
from threading import Thread
from tcp_by_size import send_with_size, recv_by_size
from urllib.parse import urlparse


ip_list = []  # an ip list of all the ip adresses of websites I want to block
queue = []

def add_text_in_first_empty_line(file_path, text_to_add):
    # Read the contents of the file
    with open(file_path, 'r') as file:
        lines = file.readlines()

    # Find the index of the first empty line
    first_empty_line_index = None
    for i, line in enumerate(lines):
        if not line.strip():
            first_empty_line_index = i
            break

    # If no empty line is found, append the text to the end of the file
    if first_empty_line_index is None:
        with open(file_path, 'a') as file:
            file.write('\n' + text_to_add + '\n')
    else:
        # Otherwise, insert the text into the first empty line
        lines[first_empty_line_index] = text_to_add + '\n'
        with open(file_path, 'w') as file:
            file.writelines(lines)

def get_all_ip():  # at the start of the run this will get al the ip adresses of the sites we want to block
    file = open("websites.txt", "r")
    for line in file:
        url = line.split(",")[0]
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        ip_add = socket.gethostbyname_ex(domain)
        if len(ip_add) == 3:
            for i in range(len(ip_add[2])):
                print(i)
                ip_address = ip_add[2][i]
                print(ip_address)
                ip_list.append(str(ip_address))

def getHost(ip):
    """
    This method returns the 'True Host' name for a
    given IP address
    """
    try:
        data = socket.gethostbyaddr(ip)
        host = repr(data[0])
        return host
    except Exception:
        # fail gracefully
        return False


def get_ip(url):
    # Parse the URL to extract the domain name
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    ip_add = socket.gethostbyname(domain)
    print(ip_add)
    file = "websites.txt"
    to_write = (str(url))
    add_text_in_first_empty_line(file, to_write)
    return ip_add


def get_domain_name(ip_address):
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except socket.herror:
        return "No domain name found"

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    return answered_list[0][1].hwsrc


## Create a Packet Counter
packet_counts = Counter()


## Define our Custom Action function
packet_dst = get_mac("172.16.255.254")
i = 0
def custom_action(packet):

    for p in packet:
        # Create tuple of Src/Dst in sorted order
        key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
        packet_counts.update([key])


        #name = scapy.all.sr1(IP(dst="8.8.8.8") / UDP() / DNS(rd=1, qd=DNSQR(qname="211.196.59.69.in-addr.arpa", qtype='PTR')))
        #print(str(name))
        ip_address = (packet[0][1].dst)
        #domain_name = get_domain_name(ip_address)
        #addrs = dns.reversename.from_address(str(ip_address))
        #print(str(dns.resolver.resolve(addrs, "PTR")[0]))
        #print(f"The domain name for {ip_address} is {addrs}")

        #domain_name = socket.gethostbyaddr(ip_address)[0]

        #print(getHost(ip_address))

        packet.dst = packet_dst
        if ip_address == "104.26.0.194":
            print("nigga")

        if ip_address not in ip_list:  # getHost(ip_address) == '022.co.il':
            scapy.sendp(packet, verbose=0)
            return(packet)
            #return f"Packet #{sum(packet_counts.values())}: {packet[0][1].src} ==> {packet[0][1].dst}"
        else:
            print("jj")


def main():
    ## Setup sniff, filtering for IP traffic
    sniff(filter="ip and src 172.16.13.27", lfilter=lambda packet: custom_action(packet))
    print("niff")
    ## Print out packet count per A <--> Z address pair
     #print("\n".join(f"{f'{key[0]} <--> {key[1]}'}: {count}" for key, count in packet_counts.items()))


def get_websites_to_block():
    sock = socki()
    sock.bind(("0.0.0.0", 5000))
    try:
        sock.listen(4)
        print('Server started.')

        while 'connected':
            conn, addr = sock.accept()
            print('Client connected IP:', addr)
            url = ""
            got_all = False
            url = recv_by_size(conn).decode()
            websites_ip = get_ip(url)
            ip_list.append(str(websites_ip))
            get_all_ip()

    finally:
        sock.close()


if __name__ == '__main__':
    thread = Thread(target=get_websites_to_block, args=())
    thread.start()
    get_all_ip()
    main()