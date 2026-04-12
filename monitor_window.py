import threading

import customtkinter as ctk
import advance_monitor
import time
import os
import wifi_monitor
# ---------------------------------------
# Copyright (c) 2026 Mehadi Hasan
# Project: NetSpy - Network Security Analyzer
# License: MIT License
# ---------------------------------------
class monitor_window_ui(ctk.CTkToplevel):
    def __init__(self, parent, update_log):
        super().__init__(parent)

        self.update_log = update_log

        # --- Window Configuration ---
        self.title("NetSpy - Wireless Setup")
        self.geometry("1200x950")
        self.attributes("-topmost", True)
        self.configure(fg_color="#121212")  # Deep dark background

        # --- Header Section ---
        self.header_frame = ctk.CTkFrame(self, fg_color="#1a1a1a", height=80, corner_radius=0)
        self.header_frame.pack(fill="x", side="top")

        self.title_label = ctk.CTkLabel(
            self.header_frame,
            text="📡 MONITOR MODE SETUP",
            font=("Roboto", 20, "bold"),
            text_color="#3498db"
        )
        self.title_label.place(relx=0.5, rely=0.4, anchor="center")

        self.subtitle_label = ctk.CTkLabel(
            self.header_frame,
            text="Configure your wireless adapter for packet injection",
            font=("Roboto", 11),
            text_color="#888888"
        )
        self.subtitle_label.place(relx=0.5, rely=0.7, anchor="center")

        # --- Main Content Frame ---
        self.content_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.content_frame.pack(fill="both", expand=True, padx=30, pady=20)

        # 1. Interface Selection
        ctk.CTkLabel(self.content_frame, text="Select Network Interface:", font=("Roboto", 13, "bold")).pack(anchor="w",pady=(10,5))

        ifaces = wifi_monitor.get_available_interface()
        self.iface_dropdown = ctk.CTkComboBox(
            self.content_frame,
            values=ifaces,
            width=400,
            height=40,
            fg_color="#1a1a1a",
            border_color="#333333",
            button_color="#3498db",
            dropdown_fg_color="#1a1a1a"
        )
        self.iface_dropdown.pack(pady=(0, 20))
        if "wlan0" in ifaces: self.iface_dropdown.set("wlan0")

        # 2. Status Terminal
        ctk.CTkLabel(self.content_frame, text="System Status:", font=("Roboto", 13, "bold")).pack(anchor="w",pady=(0, 5))

        self.status_box = ctk.CTkFrame(self.content_frame, fg_color="#000000", height=70, border_width=1,border_color="#333333")
        self.status_box.pack(fill="x")
        self.status_box.pack_propagate(False)

        self.status_text = ctk.CTkLabel(
            self.status_box,
            text="> Waiting for user action...",
            font=("Consolas", 12),
            text_color="#00FF00",
            anchor="w",
            padx=15
        )
        self.status_text.pack(fill="both", expand=True)


        # LIVE STATS BOX
        # --LIVE STATS HEADER ---
        self.stats_header_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.stats_header_frame.pack(fill="x", padx=10, pady=(10, 0))

        ctk.CTkLabel(
            self.stats_header_frame,
            text="LIVE NETWORK TRAFFIC",
            font=("Roboto", 12, "bold"),
            text_color="#3498db"
        ).pack(side="left")

        self.counter_label = ctk.CTkLabel(
            self.stats_header_frame,
            text="Routers: 0 | Devices: 0",
            font=("Consolas", 12, "bold"),
            text_color="#e67e22"
        )
        self.counter_label.pack(side="right")


        self.live_stats_box = ctk.CTkTextbox(
            self.content_frame,
            height=380,
            fg_color="#050505",
            text_color="#00FF00",
            font=("Consolas", 13),
            border_width=1,
            border_color="#222222"
        )
        self.live_stats_box.pack(fill="both", expand=True, padx=10, pady=10)

        self.live_stats_box._textbox.tag_config("router_color", foreground="#3498db")
        self.live_stats_box._textbox.tag_config("device_color", foreground="#2ecc71")
        self.live_stats_box._textbox.tag_config("header_color", foreground="#888888")

        # Action Button Container
        self.btn_container = ctk.CTkFrame(self, fg_color="transparent")
        self.btn_container.pack(pady=(0, 30), expand=True)

        self.activate_btn = ctk.CTkButton(
            self.btn_container,
            text="ACTIVATE MONITOR MODE",
            font=("Roboto", 14, "bold"),
            height=50,
            width=300,
            fg_color="#27ae60",
            hover_color="#2ecc71",
            corner_radius=8,
            command=self.do_active
        )
        self.activate_btn.grid(row=0, column=0, padx=10)

        # Deactivate Button
        self.deactivate_btn = ctk.CTkButton(
            self.btn_container,
            text="STOP & RESET",
            font=("Roboto", 13, "bold"),
            height=45,
            width=180,
            fg_color="#c0392b",
            hover_color="#e74c3c",
            command=self.do_deactivate
        )
        self.deactivate_btn.grid(row=0, column=1, padx=10)

        #advanced button
        self.advanced_btn = ctk.CTkButton(
            self.content_frame,
            text="🔍 OPEN ADVANCED INSPECTOR",
            font=("Roboto", 14, "bold"),
            height=45,
            fg_color="#3498db",
            hover_color="#2980b9",
           command=self.open_advanced_menu
        )


    def do_active(self):
        interface = self.iface_dropdown.get()
        self.stop_events = threading.Event()
        self.stop_events.clear()

        # ethernet check
        if "eth" in interface.lower():
            self.status_text.configure(text="> ERROR: Ethernet (eth0) cannot enter monitor mode!", text_color="#FF3131")
            return

        # check_monitor_mode
        self.status_text.configure(text="> Diagnosing hardware support...", text_color="cyan")
        self.update_idletasks()

        if wifi_monitor.check_monitor_mode():
            self.status_text.configure(text=f"> Support Confirmed! Activating {interface}...", text_color="yellow")
            self.update_idletasks()

            success, new_name = wifi_monitor.activate_monitor_mode(interface)

            if success:
                self.iface_dropdown.set(new_name)

                self.status_text.configure(text=f"> SUCCESS: {new_name} is active!", text_color="#00FF00")
                self.update_log(f"[SYSTEM] Switched to Monitor Mode: {new_name}")

                hopper_thread = threading.Thread(
                target=self.run_channel_hopper,
                args=(new_name,),
                daemon=True
                )
                hopper_thread.start()

                self.advanced_btn.pack(pady=10)

                if hasattr(self.master, "update_interface_status"):
                    self.master.update_interface_status(new_name)

                self.activate_btn.configure(state="disabled", text="MONITORING...")
                capture_thread = threading.Thread(
                    target=wifi_monitor.start_live_capture,
                    args=(new_name, self.update_live_status, self.stop_events),
                    daemon=True
                )
                capture_thread.start()
            else:
                self.status_text.configure(text="> ERROR: Activation failed. Check Sudo permissions.",text_color="#FF3131")

        else:
            self.status_text.configure(text="> ERROR: Hardware does NOT support monitor mode!", text_color="#FF3131")
            self.update_log(f"[ERROR] Hardware incompatible for {interface}")


    def do_deactivate(self):

        if hasattr(self, 'stop_events'):
            self.stop_events.set()

        interface = self.iface_dropdown.get()

        self.advanced_btn.pack_forget()

        interface = self.iface_dropdown.get()
        #interface = current if "mon" in current else f"{current}mon"

        self.status_text.configure(text=f"> Stopping {interface} and restarting NetworkManager...", text_color="yellow")
        self.update_idletasks() #UI Refresh

        if wifi_monitor.deactivate_monitor_mode(interface):

            import time
            time.sleep(1)

            self.status_text.configure(text="> SUCCESS: Network restored to Managed mode.", text_color="#00FF00")
            self.update_log("[SYSTEM] Monitor mode disabled. NetworkManager restarted.")

            original_name = interface.replace("mon", "")

            self.iface_dropdown.set(original_name)
            self.activate_btn.configure(state="normal", text="ACTIVATE MONITOR MODE")

            if hasattr(self.master, "update_interface_status"):
                self.master.update_interface_status(original_name,is_active=False)

        else:
            self.status_text.configure(text="> ERROR: Reset failed.", text_color="#FF3131")

    def update_live_status(self, router_msg,device_msg,summary_msg,found_ssids,router_clients,host_names,found_clients):
        self.live_stats_box.configure(state="normal")
        self.live_stats_box.delete("1.0", "end")

        self.counter_label.configure(text=summary_msg)

        header = f"{'TYPE':^12} | {'MAC ADDRESS':^20} | {'SSID ':^25} | {'PWR':^6} | {'DEVICE':^12} | {'CH':^4} | {'ENC':^15} | {'CIPHER':^6} | {'AUTH':^5} | {'CONN':^5}\n"
        separator = "-" * 136 + "\n"

        header_start = self.live_stats_box.index("end-1c")
        self.live_stats_box.insert("end", header + separator)
        header_end = self.live_stats_box.index("end-1c")
        self.live_stats_box._textbox.tag_add("header_color", header_start, header_end)

        if router_msg.strip():
            r_start = self.live_stats_box.index("end-1c")  #finding each line start and end index
            self.live_stats_box.insert("end", router_msg)
            r_end = self.live_stats_box.index("end-1c")
            self.live_stats_box._textbox.tag_add("router_color", r_start, r_end)

        if device_msg.strip():
            d_start = self.live_stats_box.index("end-1c")
            self.live_stats_box.insert("end", device_msg)
            d_end = self.live_stats_box.index("end-1c")
            self.live_stats_box._textbox.tag_add("device_color", d_start, d_end)

        self.live_stats_box.configure(state="disabled")

        self.last_data = (found_ssids, router_clients, host_names,found_clients)

        #CHEKCK WINDOW OPEN OR NOT
        if hasattr(self, 'advanced_window') and self.advanced_window.winfo_exists():
            try:
                self.advanced_window.receive_raw_data(found_ssids, router_clients, host_names,found_clients)
            except Exception as e:
                print(f"Update error: {e}")

        self.live_stats_box.see("end") # auto scroll

    def open_advanced_menu(self):
        interface = self.iface_dropdown.get()

        if hasattr(self, 'advanced_window') and self.advanced_window.winfo_exists():
            self.advanced_window.lift()  # উইন্ডোটি সামনে নিয়ে আসবে
            return

        self.advanced_window = advance_monitor.advance_monitor_ui(self, interface, self.update_log)

        self.update_log(f"[UI] Advanced Inspector launched for {interface}")
        self.status_text.configure(text="> Advanced Inspector is now running.", text_color="cyan")

    def run_channel_hopper(self, interface):

        channels = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,  # 2.4GHz
            36, 40, 44, 48, 52, 56, 60, 64,  # 5GHz (UNII-1 & 2)
            100, 104, 108, 112, 149, 153, 157, 161, 165  # 5GHz (UNII-2 Ext & 3)
        ]
        index = 0

        self.is_hopping = True

        while not self.stop_events.is_set():

            if self.is_hopping:
                try:
                    current_channel = channels[index]
                    os.system(f"sudo iw dev {interface} set channel {current_channel}")
                    index = (index + 1) % len(channels)

                except:
                    pass

            time.sleep(0.3)
