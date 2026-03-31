import threading

import customtkinter as ctk
import advance_monitor
import time
import os
import wifi_monitor

class monitor_window_ui(ctk.CTkToplevel):
    def __init__(self, parent, update_log):
        super().__init__(parent)

        self.update_log = update_log

        # --- Window Configuration ---
        self.title("NetSpy - Wireless Setup")
        self.geometry("1200x900")
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

        #live stats box
        self.live_stats_box = ctk.CTkTextbox(
            self,
            width=750,
            height=350,
            state="disabled",
            font=("Courier New", 13),
            border_width=1,
            border_color="#333333"
        )

        self.live_stats_box.pack(pady=20, padx=20, expand=True)

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

    def update_live_status(self, stats_msg):
        self.live_stats_box.configure(state="normal")
        self.live_stats_box.delete("1.0", "end")
        self.live_stats_box.insert("end", stats_msg)
        self.live_stats_box.configure(state="disabled")

    def open_advanced_menu(self):
        interface = self.iface_dropdown.get()
        self.advanced_window = advance_monitor.advance_monitor_ui(self, interface, self.update_log)
        self.update_log(f"[UI] Advanced Inspector launched for {interface}")
        self.status_text.configure(text="> Advanced Inspector is now running.", text_color="cyan")

    def run_channel_hopper(self, interface):
        current_channel = 1
        while not self.stop_events.is_set():
            os.system(f"sudo iw dev {interface} set channel {current_channel}")
            time.sleep(0.5)
            current_channel = current_channel + 1

            if current_channel > 13:
                current_channel = 1