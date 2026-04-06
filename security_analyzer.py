import time
from scapy.all import IP, DNS, DNSQR
class security_engine:
    def __init__(self, alert_callback, table_callback):
        self.alert_callback = alert_callback
        self.table_callback = table_callback
        self.status = {}

        self.upload_limit = 5 * 1024 * 1024
        self.request_alert = 30


    def analyze_packet(self,pkt):
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            pkt_size = len(pkt)

            if src_ip not in self.status:
                self.status[src_ip] = {'upload': 0, 'dns': 0, 'risk': 'LOW'}

            self.status[src_ip]['upload'] += pkt_size

            if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
                self.status[src_ip]['dns'] += 1


            self.check_threats(src_ip)
            self.table_callback(src_ip,self.status[src_ip])

    def check_threats (self,src_ip):
        data = self.status[src_ip]

        if data['upload'] >= self.upload_limit and data['risk'] !=  'CRITICAL':
            data['risk'] = 'CRITICAL'
            self.alert_callback(f"Heavy Data Leakage! {src_ip} sent > 5MB")

        if data['dns'] > self.request_alert:
            self.alert_callback(f"Potential DNS Tunneling from {src_ip}!")
            data['dns'] = 0
