# ===========================================================================
# NetSpy - Network Traffic Monitor & Security Analyzer
# Copyright (C) 2026 Mehadi Hasan

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
# ===============================================================================


import os
import subprocess
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt
from scapy.layers.dot11 import RadioTap
from utils import VENDOR_DB
from scapy.layers.dhcp import DHCP
from scapy.layers.l2 import Ether


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
        os.system(f"sudo airmon-ng start {interface}")
        mon_iface = f"{interface}mon"

        if os.path.exists(f"/sys/class/net/{mon_iface}"):
            return True, mon_iface
        else:
            return True, interface

    except Exception as e:
        print(f"Activation Error: {e}")
        return False, None

def deactivate_monitor_mode(mon_interface):
    try:
        os.system(f"sudo airmon-ng stop {mon_interface}")
        os.system(f"sudo iw {mon_interface} set type managed")

        os.system("sudo systemctl restart NetworkManager")
        os.system("sudo nmcli networking on")

        return  True

    except Exception as e:
        print(f"Deactivation Error: {e}")
        return  False

def start_live_capture(interface,callback,stop_events):
    found_ssids = {}
    found_clients = {}
    router_clients = {}

    host_names = {}
    def process_packet(pkt):

        if stop_events.is_set(): return True
        new_data_found = False

        power = -100
        channel = 0
        enc, cipher, auth = "OPN", "----", "----"

        if pkt.haslayer(DHCP):
            options = pkt[DHCP].options

            dhcp_mac = pkt.addr2 if pkt.haslayer(Dot11) else (pkt[Ether].src if pkt.haslayer(Ether) else None)

            if not dhcp_mac and pkt.haslayer(Dot11):
                dhcp_mac = pkt.addr3

            if dhcp_mac:
                for opt in options:
                    if isinstance(opt,tuple) and opt[0] == 'hostname':
                        try:
                            host_name = opt[1].decode(errors="ignore")
                            host_names[dhcp_mac.lower()] = host_name

                        except:
                            pass

        #FINDING SIGNAL STRENGTH
        try:
            if pkt.haslayer(RadioTap):
                power = pkt[RadioTap].dBm_AntSignal
            else:
                power = -100
        except:
            power = -100

        #FINDING CHANNEL
        try:
            if pkt.haslayer(Dot11Beacon):
                enc, cipher, auth = get_encryption_info(pkt)
                dot11_elt = pkt.getlayer(Dot11Elt, ID=3)

                if dot11_elt:
                    byte_data = dot11_elt.info
                    channel = ord(byte_data)  # byte into number

                else:
                    if pkt.haslayer(RadioTap):
                        freq = pkt[RadioTap].ChannelFrequency
                        channel = frequency_to_channel(freq)

        except:
            channel = 0

        #finding ssid
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt.addr3
            try:
                if pkt.info:
                    ssid = pkt.info.decode(errors="ignore").strip()
                    count_clients = len(router_clients.get(bssid,[]))
                    if bssid not in found_ssids or found_ssids[bssid][1] != power:
                        found_ssids[bssid] = [ssid, power, channel, enc, cipher, auth,count_clients]
                        new_data_found = True
            except:
                pass

        # Finding MAC
        if pkt.haslayer(Dot11) and pkt.type == 2:
            router_mac = pkt.addr3
            client_mac = pkt.addr2 if pkt.addr1 == router_mac else pkt.addr1

            if router_mac and client_mac and router_mac != client_mac:

                if (client_mac not in found_clients) or (found_clients.get(client_mac) != power):

                    if client_mac in found_clients:
                        found_clients[client_mac][0] = power
                        found_clients[client_mac][1] += 1
                    else:
                        found_clients[client_mac] = [power, 1]

                    new_data_found = True

                if router_mac not in router_clients:
                    router_clients[router_mac] = set()

                if client_mac not in router_clients[router_mac]:
                    router_clients[router_mac].add(client_mac)

                    if router_mac in found_ssids:
                        found_ssids[router_mac][6] = len(router_clients[router_mac])
                        new_data_found = True

        #stats for UI
        if new_data_found:
            router_data=""

            for b_id, info in found_ssids.items():
                router_prefix = b_id[:8].upper()
                router_brand = VENDOR_DB.get(router_prefix,"Unknown")
                router_data += f"{'Router':<12} | {b_id:<20} | {info[0]:^25} | {info[1]:^6} | {router_brand:^12} | {info[2]:^4} | {info[3]:^15} | {info[4]:^6} | {info[5]:^5} | {info[6]:^5}\n"

            device_data = ""
            for m_adr,data in found_clients.items():

                pwr = data[0]
                mac_addr_lwr =  m_adr.lower()
                host_name = host_names.get(mac_addr_lwr,"")

                device_prefix = m_adr[:8].upper()
                device_brand = VENDOR_DB.get(device_prefix,"Randomized")

                if host_name:
                    display_name =  host_name

                else:
                    display_name = device_brand

                device_data += f"{'Device':<12} | {m_adr:<20} | {' ':<25} | {pwr:^6} | {display_name:^12} |\n"

            summary = f"Routers: {len(found_ssids)} | Devices: {len(found_clients)}"
            callback(router_data,device_data,summary,found_ssids,router_clients,host_names,found_clients)

    sniff(iface=interface, prn=process_packet, store=0, stop_filter=lambda x: stop_events.is_set())


def get_encryption_info(pkt):
    encryption = "OPN"
    auth = ""
    cipher = ""

    if pkt.haslayer(Dot11Beacon):
        stats = pkt[Dot11Beacon].network_stats()
        crypto = stats.get('crypto')

        if crypto:
            full_crypto = list(crypto)[0]

            full_crypto = list(crypto)[0]
            if '/' in full_crypto:
                encryption, auth = full_crypto.split('/')
            else:
                encryption = full_crypto

            cipher = "CCMP" if "WPA2" in encryption else "TKIP"

    return encryption,cipher,auth

def frequency_to_channel(freq):
    if freq == 2484: return 14  #channel 13-14 difference 12Mhz & 1-13 5Mhz
    if 2407 <=  freq < 2484:
        return (freq - 2407) // 5
    if 5030 <= freq <= 5900:
        return (freq - 5000) // 5
    return 0
