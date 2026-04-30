# ===========================================================================
# NetSpy - Network Traffic Monitor & Security Analyzer
# Copyright (C) 2026 Mehadi Hasan
# Licensed under GNU GPL v3
# ===========================================================================

import time
import ipaddress
import requests
from scapy.all import IP, DNS, DNSQR


class SecurityEngine:
    def __init__(self, alert_callback, table_callback):
        self.alert_callback = alert_callback
        self.table_callback = table_callback
        self.location_cache = {}
        self.status = {}

        self.upload_limit = 5 * 1024 * 1024  # 5MB
        self.request_alert = 50

        self.whitelist = [
            # Search & AI
            "google.com", "google.com.bd", "bing.com", "openai.com", "chatgpt.com",
            "anthropic.com", "perplexity.ai", "gemini.google.com",

            # Cloud & Storage
            "drive.google.com", "dropbox.com", "icloud.com", "supabase.com", "supabase.co",
            "amazon.com", "aws.amazon.com", "netlify.com", "netlify.app",

            # Productivity & Education
            "classroom.google.com", "microsoft.com", "office.com", "teams.microsoft.com",
            "live.com", "zoom.us", "github.com", "gitlab.com",

            # Social & Media
            "youtube.com", "googlevideo.com", "facebook.com", "fbcdn.net", "instagram.com",

            # Local & Others
            "startech.com.bd", "daraz.com.bd", "gmail.com", "outlook.com",
            ".local", "google-analytics.com", "gvt2.com", "clients6.google.com",
            "clients4.google.com", "safebrowsing.google.com", "vercel.com",
            "ip-api.com",
        ]

    def get_location(self, ip):
        if ipaddress.ip_address(ip).is_private:
            return "Local Network"

        if ip in self.location_cache:
            return self.location_cache[ip]

        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,countryCode",
                timeout=2
            ).json()
            if response.get('status') == 'success':
                location = f"{response['country']} {response['countryCode']}"
                self.location_cache[ip] = location
                return location
        except:
            pass

        return "Unknown"

    def analyze_packet(self, pkt):
        if not pkt or not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        pkt_size = len(pkt)

        if src_ip not in self.status:
            self.status[src_ip] = {
                'upload': 0,
                'dns': 0,
                'risk': 'LOW',
                'last_reset': time.time()
            }

        # DNS counter প্রতি ৬০ সেকেন্ডে reset
        current_time = time.time()
        if current_time - self.status[src_ip]['last_reset'] > 60:
            self.status[src_ip]['dns'] = 0
            self.status[src_ip]['last_reset'] = current_time

        self.status[src_ip]['upload'] += pkt_size

        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
            try:
                qname = pkt[DNSQR].qname.decode()
                if not any(domain in qname for domain in self.whitelist):
                    self.status[src_ip]['dns'] += 1
                    if len(qname) > 60:
                        self.alert_callback(f"⚠️ High Entropy DNS: {qname[:30]}... from {src_ip}")
            except:
                pass

        self.check_threats(src_ip)
        self.table_callback(src_ip, self.status[src_ip])

    def check_threats(self, src_ip):
        data = self.status[src_ip]

        if data['upload'] >= self.upload_limit and data['risk'] != 'CRITICAL':
            data['risk'] = 'CRITICAL'
            self.alert_callback(f"Heavy Data Leakage! {src_ip} sent > 5MB")

        if data['dns'] > self.request_alert:
            data['risk'] = 'HIGH'
            self.alert_callback(f"Potential DNS Tunneling from {src_ip}!")
            data['dns'] = 0