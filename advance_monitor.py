import customtkinter as ctk
import os
import re #RegEx
from utils import VENDOR_DB
class advance_monitor_ui(ctk.CTkToplevel):
    def __init__(self, parent, interface, update_log):
        super().__init__(parent)

        self.interface = interface
        self.update_log = update_log

        self.title(f"NetSpy - Advanced Inspector ({self.interface})")
        self.geometry("1000x800")
        self.configure(fg_color="#0a0a0a")
        self.attributes("-topmost", True)

        #Header
        self.header = ctk.CTkLabel(
            self,
            text=f"📡 OFFENSIVE MODE: {self.interface}",
            font=("Consolas", 22, "bold"),
            text_color="#00FF00"
        )
        self.header.pack(pady=15)

        #Top Section Update (Manual Channel Selector)
        self.top_frame = ctk.CTkFrame(self, fg_color="#151515", border_width=1, border_color="#333")
        self.top_frame.pack(fill="x", padx=20, pady=10)

        # Router Selector
        ctk.CTkLabel(self.top_frame, text="Target Router:", font=("Roboto", 12, "bold")).grid(row=0, column=0, padx=5,pady=15)
        self.network_selector = ctk.CTkComboBox(
            self.top_frame,
            values=["Select Target..."],
            width=220
        )
        self.network_selector.grid(row=0, column=1, padx=5)

        # CHANNEL SELECT
        self.chan_frame = ctk.CTkFrame(self.top_frame, fg_color="transparent")
        self.chan_frame.grid(row=0, column=3, padx=10)

        ctk.CTkLabel(self.top_frame, text="Channel:", font=("Roboto", 12, "bold")).grid(row=0, column=2, padx=5)

        all_channels = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
            36, 40, 44, 48, 52, 56, 60, 64,
            100, 104, 108, 112, 149, 153, 157, 161, 165
        ]

        self.channel_dropdown = ctk.CTkComboBox(
            self.chan_frame,
            values=[str(ch) for ch in all_channels],
            width=90,
            justify="center"
        )
        self.channel_dropdown.set("1")
        self.channel_dropdown.pack(side="left")

        #Lock BUTTON
        self.lock_btn = ctk.CTkButton(
            self.top_frame,
            text="🔒 LOCK CHANNEL",
            fg_color="#2980b9",
            width=120,
            command=self.manual_lock_event
        )
        self.lock_btn.grid(row=0, column=4, padx=10)

        # Middle Section: LIVE CLIENT TABLE
        self.client_label = ctk.CTkLabel(self, text="🎯 CONNECTED CLIENTS (Target identification)",font=("Roboto", 14, "bold"), text_color="#3498db")
        self.client_label.pack(anchor="w", padx=25, pady=(10, 0))

        self.client_table = ctk.CTkTextbox(
            self,
            height=200,
            fg_color="#000",
            text_color="#00FF00",
            font=("Consolas", 12),
            wrap="none",
            border_width=1,
        )

        self.client_table.pack(fill="x", padx=20, pady=10)
        self.client_table.configure(state="disabled")

        #Action Section: Attack Buttons
        self.action_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.action_frame.pack(pady=15)

        # Kick/Deauth Button
        self.kick_btn = ctk.CTkButton(
            self.action_frame, text="💥 KICK DEVICE (DEAUTH)",
            fg_color="#c0392b", hover_color="#e74c3c", width=200, height=45, font=("Roboto", 13, "bold")
        )
        self.kick_btn.grid(row=0, column=0, padx=10)

        # Handshake Button
        self.handshake_btn = ctk.CTkButton(
            self.action_frame, text="📥 CAPTURE HANDSHAKE",
            fg_color="#d35400", hover_color="#e67e22", width=200, height=45, font=("Roboto", 13, "bold")
        )
        self.handshake_btn.grid(row=0, column=1, padx=10)

        # Identity Reveal Button
        self.reveal_btn = ctk.CTkButton(
            self.action_frame, text="🔍 REVEAL IDENTITY",
            fg_color="#8e44ad", hover_color="#9b59b6", width=200, height=45, font=("Roboto", 13, "bold")
        )
        self.reveal_btn.grid(row=0, column=2, padx=10)

        # Bottom Section: Terminal Output
        self.terminal_label = ctk.CTkLabel(self, text="📜 ATTACK LOG / TERMINAL", font=("Roboto", 14, "bold"),text_color="#f1c40f")
        self.terminal_label.pack(anchor="w", padx=25)

        self.terminal_display = ctk.CTkTextbox(
            self, height=250, fg_color="#000", text_color="#00FF00", font=("Consolas", 12), border_width=1,
            border_color="#444"
        )
        self.terminal_display.pack(fill="both", expand=True, padx=20, pady=10)

    def write_to_terminal(self, message):
        self.terminal_display.configure(state="normal")
        self.terminal_display.insert("end", f"> {message}\n")
        self.terminal_display.see("end")
        self.terminal_display.configure(state="disabled")


    def on_router_select(self, selection):
        target_channel = 6
        self.chan_label.configure(text=f"Ch: {target_channel}")
        self.write_to_terminal(f"Target selected: {selection} on Channel {target_channel}")

    def lock_target_channel(self):
        self.lock_btn.configure(text="🔓 UNLOCK", fg_color="#c0392b")
        self.write_to_terminal(f"Channel locked on {self.interface}. Ready for Attack!")

    def manual_lock_event(self):
        ch = self.channel_dropdown.get()
        self.write_to_terminal(f"Attempting to lock {self.interface} on Channel {ch}...")

        # কমান্ড চালানোর সময় এরর হ্যান্ডলিং
        res = os.system(f"iwconfig {self.interface} channel {ch}")

        if res == 0:
            self.write_to_terminal(f"Success! Card is now monitoring Channel {ch}")
            self.lock_btn.configure(text="🔓 UNLOCK", fg_color="#c0392b")
        else:
            self.write_to_terminal(f"FAILED! Does your card support Channel {ch}?")

    def receive_raw_data(self, found_ssids, router_clients, host_names,found_clients):
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
                self.refresh_client_table(target_bssid, router_clients, host_names,found_clients)


        except Exception as e:
            self.write_to_terminal(f"Sync Error: {e}")

    def refresh_client_table(self, target_bssid, router_clients, host_names,found_clients):
        self.client_table.configure(state="normal")
        self.client_table.delete("1.0", "end")

        header = f"{'ID':<4} | {'MAC Address':<18} | {'DEVICE':<20} | {'Signal':<15} | {'Status':<8}\n"
        self.client_table.insert("end", header + "-" * 85 + "\n")

        clients = list(set(router_clients.get(target_bssid, [])))

        if not clients:
            self.client_table.insert("end", "\n   No active clients detected...\n")
        else:
            for i, c_mac in enumerate(clients, start=1):
                c_mac = str(c_mac).strip()
                h_name = str(host_names.get(c_mac.lower(), "")).strip()

                prefix = c_mac[:8].upper()
                brand = VENDOR_DB.get(prefix, "Private")

                if h_name:
                    display_name = h_name
                else:
                    display_name = brand

                sig = found_clients.get(c_mac, -100)
                sig_display = f"{sig} dBm"

                line = f"{i:<4} | {c_mac:<18} | {display_name:<20} | {sig_display:<15} | {'Active':<8}\n"
                self.client_table.insert("end", line)

        self.client_table.configure(state="disabled")

