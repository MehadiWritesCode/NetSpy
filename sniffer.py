import socket
from scapy.all import sniff, IP, UDP, TCP,ICMP,ARP

def get_my_IP():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8",80))

        ip= s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

MY_IP = get_my_IP()

def start_packet_sniffing(gui_callback,stop_check):
    def packet_callback(packet):
        protocol = "Other"
        src_ip = "N/A"
        dest_ip = "N/A"
        direction = ""

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dest_ip = packet[IP].dst

            if src_ip == MY_IP:
                direction ="OUT >>"
            elif dest_ip == MY_IP:
                direction ="<< IN"
            elif dest_ip.startswith("224.") or dest_ip.startswith("239."):
                direction = "MULTI"
            elif dest_ip == "255.255.255.255":
                direction = "BCAST"
            else:
                direction="OTHER"

            if packet.haslayer(TCP):
                protocol = "TCP"
            elif packet.haslayer(UDP):
                protocol = "UDP"
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
            else:
                protocol = "IP-OTHER"

        elif packet.haslayer(ARP):
            protocol = "ARP"
            src_ip = packet[ARP].psrc  # Source Hardware/Protocol address
            dest_ip = packet[ARP].pdst

        size = len(packet)

        log_data =f"{protocol:<10} | {direction:<6} | {src_ip:<18} | {dest_ip:<20} | {size}B"
        gui_callback({"display":log_data,"raw":packet})


    # Function to call for each packet captured
    sniff(
        prn=packet_callback,  # prn= Packet RenderingNetwork
        store=0,              # Don't keep packets in memory

                    # anonymous function
        stop_filter=lambda x: stop_check()  # stop_check true then stop sniffing
)

