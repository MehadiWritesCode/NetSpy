import os
import subprocess
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt

def get_available_interface():

    try:
        interfaces = os.listdir('/sys/class/net/')
        return [iface for iface in interfaces if iface != 'lo']
    except Exception as e:
        print(f"Error fetching interfaces: {e}")
        return ["wlan0"]

def check_monitor_mode():
    try:
        result = subprocess.run(["iw","list"],capture_output=True,text=True)
        return "monitor" in result.stdout.lower()

    except Exception:
        return  False

def activate_monitor_mode(interface):

    try:
        os.system("sudo airmon-ng check kill")

        os.system(f"sudo ip link set {interface} down")
        os.system(f"sudo iw {interface} set monitor control")
        os.system(f"sudo ip link set {interface} up")

        return True, interface

    except Exception as e:
        print(f"Activation Error: {e}")
        return False, None

def deactivate_monitor_mode(mon_interface):
    try:
        os.system(f"sudo ip link set {mon_interface} down")
        os.system(f"sudo iw {mon_interface} set type managed")

        os.system(f"sudo airmon-ng stop {mon_interface}")
        original_iface = mon_interface.replace("mon","")


        os.system(f"sudo ip link set {original_iface} up")

        os.system("sudo systemctl restart NetworkManager")
        os.system("sudo nmcli networking on")

        return  True

    except Exception as e:
        print(f"Deviation Error: {e}")
        return  False

def start_live_capture(interface,callback,stop_events):
    found_ssids = set()
    found_clients =set()

    def process_packet(pkt):
        if stop_events.is_set(): return True
        new_data_found = False

        #finding ssid
        if pkt.haslayer(Dot11Beacon):
            try:
                ssid = pkt[Dot11Elt].info.decode(errors="ignore")
                if ssid and ssid not in found_ssids:
                    found_ssids.add(ssid)
                    new_data_found=True

            except: pass

        # Finding MAC
        if pkt.haslayer(Dot11) and pkt.type == 2:
            client_mac = pkt.addr2
            if client_mac and client_mac not in found_clients:
                found_clients.add(client_mac)
                new_data_found=True

        #stats for UI
        if new_data_found:
            stats = (
                f"📡 SCANNING AIRWAVES: {interface}\n"
                f"{'=' * 35}\n"
                f"Total Routers  : {len(found_ssids)}\n"
                f"Active Devices : {len(found_clients)}\n"
                f"{'=' * 35}\n"
                f"Last SSID: {ssid if 'ssid' in locals() else '...'}\n"
            )
            callback(stats)

    sniff(iface=interface, prn=process_packet, store=0, stop_filter=lambda x: stop_events.is_set())