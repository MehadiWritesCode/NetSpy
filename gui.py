import threading
from string import printable

import sniffer
import customtkinter as ctk
import security_analyzer_ui
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")
from monitor_window import monitor_window_ui

class NetSpyGUI(ctk.CTk):  # It means Child of CustomTkinter

    def __init__(self):
        super().__init__()

        # windows title
        self.title("NetSpy - Network Traffic Monitor")
        self.geometry("1200x900")

        #interface track
        import wifi_monitor
        available_ifaces = wifi_monitor.get_available_interface()

        if available_ifaces:
            self.current_interface = "wlan0" if "wlan0" in available_ifaces else available_ifaces[0]
            status_color = "#e74c3c"
            status_text = f"🌐 Interface: {self.current_interface} (Managed)"
        else:
            self.current_interface = "None"
            status_color = "#e74c3c"
            status_text = "⚠️ No Interface Found!"

        self.status_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.status_frame.place(relx=0.02, rely=0.05, anchor="nw")

        self.iface_label = ctk.CTkLabel(
            self.status_frame,
            text=f"🌐 Interface: {self.current_interface}",
            font=("Roboto", 13, "bold"),
            text_color="#e74c3c"
        )
        self.iface_label.pack()

        # Label
        self.title_label = ctk.CTkLabel(
            self,
            text="Welcome to NetSpy",
            font=("Roboto", 24, "bold"),
            text_color="white"
        )
        self.title_label.pack(pady=(30, 10))

        #slogan
        self.slogan_label = ctk.CTkLabel(
            self,
            text=" -- See the Unseen --",
            font=("Roboto", 20, "italic"),
            text_color="#AAAAAA"
        )
        self.slogan_label.pack(pady=(0, 20))

        # Monitor Mode Button (Top Right Corner)
        self.monitor_btn = ctk.CTkButton(
            self,
            text="📡 Monitor Mode",
            width=140,
            height=32,
            fg_color="#2c3e50",
            hover_color="#34495e",
            command=self.open_monitor_window,
            font=("Roboto", 12, "bold")
        )
        self.monitor_btn.place(relx=0.98, rely=0.05, anchor="ne")

        self.line = ctk.CTkFrame(self, height=2, width=400, fg_color="gray")
        self.line.pack(pady=10)

        # middle main container
        self.middle_container = ctk.CTkFrame(self, fg_color="transparent")
        self.middle_container.pack(fill="both", expand=True, padx=20, pady=10)

        #left side elog area
        self.left_frame = ctk.CTkFrame(self.middle_container, fg_color="transparent")
        self.left_frame.pack(side="left", fill="both", expand=True, padx=(0, 10))

        header_text = f"{'PROTOCOL':<11} | {'DIR':<7} | {'SOURCE IP':<22} | {'DESTINATION IP':<22} | {'SIZE'}"

        self.header_label = ctk.CTkLabel(self.left_frame, text= header_text, font=("Consolas", 12, "bold"), text_color="#3498db")
        self.header_label.pack(anchor="w", padx=(15, 0))

        self.log_area = ctk.CTkTextbox(self.left_frame, width=550, font=("Consolas", 13), border_width=2)
        self.log_area.pack(fill="both", expand=True)
        self.log_area.configure(state="disabled")
        self.log_area.configure(cursor="hand2")

        #Right side stats area
        self.stats_frame = ctk.CTkFrame(self.middle_container, width=480, fg_color="#212121")
        self.stats_frame.pack(side="right", fill="y")
        self.stats_frame.pack_propagate(False)

        ctk.CTkLabel(self.stats_frame, text="Top Traffic Sources", font=("Roboto", 14, "bold"),text_color="#3498db").pack(pady=5)
        self.stats_area = ctk.CTkTextbox(self.stats_frame, width=460, font=("Consolas", 11), fg_color="#1a1a1a",border_width=1, wrap="none")
        self.stats_area.pack(padx=10, pady=5, fill="both", expand=True)
        self.stats_area.configure(state="disabled")

        # Security Analyzer Button Section
        self.security_btn_frame = ctk.CTkFrame(self.stats_frame, fg_color="transparent")
        self.security_frame_line = ctk.CTkFrame(self.stats_frame, height=2, fg_color="#333")
        self.security_frame_line.pack(fill="x", pady=10)
        self.security_btn_frame.pack(side="bottom", fill="x", padx=10, pady=(0, 20))

        self.security_analyzer_btn = ctk.CTkButton(
            self.security_btn_frame,
            text="🛡️ SECURITY ANALYZER",
            font=("Roboto", 13, "bold"),
            fg_color="#c0392b",
            hover_color="#a93226",
            height=45,
            command=self.open_security_analyzer
        )
        self.security_analyzer_btn.pack(fill="x")

        #packet list
        self.packet_list = []

        # for stats frame
        self.ip_stats = {} #Format: {"IP": {"count": 0, "size": 0}}

        self.log_area.bind("<Button-1>", self.highlight_line)
        self.log_area.bind("<Double-1>",self.show_details) #double click

        # color row
        self.log_area.tag_config("tcp", foreground="#5DADE2")
        self.log_area.tag_config("udp", foreground="#AF7AC5")
        self.log_area.tag_config("icmp", foreground="#F4D03F")
        self.log_area.tag_config("arp", foreground="#EB984E")
        self.log_area.tag_config("other", foreground="#95A5A6")
        # Incoming
        self.log_area.tag_config("incoming", foreground="#00FF00")
        # Outgoing
        self.log_area.tag_config("outgoing", foreground="#FF3131")
        self.log_area.tag_config("highlight", background="#3d3d3d")  # Click highlight color
        #MULTICAST
        self.log_area.tag_config("multi", foreground="#8E44AD")
        # BCAST
        self.log_area.tag_config("bcast", foreground="#7F8C8D")

        status_colors = [
            "#00FF00", "#2ECC71", "#27AE60", "#16A085", "#52BE80",
            "#3498DB", "#5DADE2", "#85C1E9", "#AED6F1", "#D6EAF8",
            "#F4D03F", "#F7DC6F", "#F9E79F", "#FCF3CF", "#95A5A6"
        ]

        for i, color in enumerate(status_colors):
            self.stats_area.tag_config(f"rank_{i}", foreground=color)

        self.stats_area.tag_config("header", foreground="#FFFFFF")

        #Button Frame
        self.is_sniffing = False

        self.button_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.button_frame.pack(fill="x", side="bottom", pady=(10, 30))

        self.button_container = ctk.CTkFrame(self.button_frame, fg_color="transparent")
        self.button_container.pack(expand=True)

        # Start Button
        self.start_btn = ctk.CTkButton(
            self.button_container,
            text="▶  Start Sniffing",
            font=("Roboto", 14, "bold"),
            width=170,
            height=42,
            corner_radius=10,
            command=self.start_sniffing
        )
        self.start_btn.pack(side="left", padx=15)

        # Stop Button
        self.stop_btn = ctk.CTkButton(
            self.button_container,
            text="⏹  Stop Sniffing",
            font=("Roboto", 14, "bold"),
            width=170,
            height=42,
            corner_radius=10,
            fg_color="#A82424",
            hover_color="#C0392B",
            state="disabled",
            command=self.stop_sniffing
        )
        self.stop_btn.pack(side="left", padx=15)

    def stop_check(self):
        return not self.is_sniffing

    def start_sniffing(self):
        if self.current_interface == "None" or not self.current_interface:
            self.update_log("[!] Error: Interface not detected. Please select one.")
            return

        self.is_sniffing = True
        self.update_log(f"[+] Sniffing started on {self.current_interface}")

        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")

        #creating thread
        sniffer_thread = threading.Thread(
            target = sniffer.start_packet_sniffing,
            args = (self.update_log,self.stop_check,self.current_interface),
            daemon=True
        )
        sniffer_thread.start()

    def stop_sniffing(self):
        self.is_sniffing = False
        self.update_log("[-] Monitoring Stopped.")

        self.start_btn.configure(state="normal", text="Start Sniffing")
        self.stop_btn.configure(state="disabled")

    def highlight_line(self, event):

        self.log_area.tag_remove("highlight", "1.0", "end")
        index = self.log_area.index(f"@{event.x},{event.y}")
        line_start = f"{index.split('.')[0]}.0"
        line_end = f"{index.split('.')[0]}.end"
        self.log_area.tag_add("highlight", line_start, line_end)

    def update_log(self,data):
        self.log_area.configure(state="normal")
        message = str(data)

        if isinstance(data,dict):
            message = data["display"]
            raw_packet = data["raw"]

            if hasattr(self, "security_win") and self.security_win.winfo_exists():
                #If security window open then send data
                self.security_win.engine.analyze_packet(raw_packet)

            self.packet_list.append(raw_packet)

            protocol_tag = "other"
            if "TCP" in message:
                protocol_tag = "tcp"
            elif "UDP" in message:
                protocol_tag = "udp"
            elif "ICMP" in message:
                protocol_tag = "icmp"
            elif "ARP" in message:
                protocol_tag = "arp"

            elif "Monitoring" in message:
                protocol_tag = "default"

            direction_tag = "default"
            if "<< IN" in message:
                direction_tag = "incoming"
            elif "OUT >>" in message:
                direction_tag= "outgoing"
            elif "MULTI" in message:
                direction_tag = "multi"
            elif "BCAST" in message:
                direction_tag = "bcast"
            else:
                direction_tag = "default"

            parts = message.split('|')
            if len(parts) >= 3:
                self.log_area.insert("end", parts[0] + "|", protocol_tag)

                # IN / OUT
                dir_part = parts[1]
                dir_tag = direction_tag
                self.log_area.insert("end", dir_part + "|", dir_tag)

                remaining = "|".join(parts[2:])
                self.log_area.insert("end", remaining + "\n", protocol_tag)
            else:
                self.log_area.insert("end", message + "\n", "default")

            # statistics update logic
            try:
                if raw_packet.haslayer("IP"):
                    src_ip = raw_packet["IP"].src
                    dest_ip = raw_packet["IP"].dst

                    size = len(raw_packet)
                    conn_key = (src_ip,dest_ip)

                    if conn_key not in self.ip_stats:
                        self.ip_stats[conn_key] = {"count": 0, "size": 0}

                    self.ip_stats[conn_key]["count"] += 1
                    self.ip_stats[conn_key]["size"] += size
                    self.refresh_status_ui()

            except Exception as e:
                print(f"Status Error: {e}")

        self.log_area.configure(state="disabled")
        self.log_area.see("end")

    def show_details(self, event):
        self.highlight_line(event)
        index = self.log_area.index(f"@{event.x},{event.y}")
        line_number = int(index.split(".")[0])
        actual_index = line_number - 1

        if 0 <= actual_index < len(self.packet_list):
            pkt = self.packet_list[actual_index]

            detail_window = ctk.CTkToplevel(self)
            detail_window.title("NetSpy Pro - Packet Inspector")
            detail_window.geometry("1100x750")
            detail_window.configure(fg_color="#121212")
            detail_window.attributes("-topmost", True)


            layer_contents = {}
            temp_pkt = pkt

            while temp_pkt:
                lname = temp_pkt.name.upper()
                header = f"  {lname}  \n" + "━" * 40 + "\n"

                fields_body = ""
                for field, val in temp_pkt.fields.items():
                    fields_body += f"  {field:<18} :  {val}\n"

                layer_contents[lname] = (header, fields_body)

                if lname == "RAW" or not temp_pkt.payload or isinstance(temp_pkt.payload, (bytes, str)):

                    p_data = temp_pkt.load if lname == "RAW" else (
                        temp_pkt.payload if isinstance(temp_pkt.payload, (bytes, str)) else None)

                    if p_data:
                        h_header = f"  PAYLOAD / HEX DUMP  \n" + "━" * 40 + "\n"
                        h_body = ""
                        rb = bytes(p_data)

                        for i in range(0, len(rb), 16):

                            chunk = rb[i:i + 16]
                            offset = f"  {i:04x}  "
                            hp = " ".join(f"{b:02x}" for b in chunk)
                            ap = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                            h_body += f"{offset}{hp:<48} | {ap}\n"

                        layer_contents["HEX DUMP"] = (h_header, h_body)
                    break
                temp_pkt = temp_pkt.payload

            # UI
            nav_frame = ctk.CTkFrame(detail_window, width=200, fg_color="#1a1a1a", corner_radius=0)
            nav_frame.pack(side="left", fill="y")
            ctk.CTkLabel(nav_frame, text="📜 LAYERS",font=("Roboto", 15, "bold"),text_color="#3498db").pack(pady=25)

            data_box = ctk.CTkTextbox(detail_window,font=("Consolas", 14), fg_color="#121212", text_color="#d4d4d4",
                                      border_width=0)
            data_box.pack(side="right", fill="both", expand=True, padx=30, pady=30)


            data_box.tag_config("layer_head", foreground="#3498db")
            data_box.tag_config("field_info", foreground="#9cdcfe")
            data_box.tag_config("hex_code", foreground="#2ecc71")
            data_box.tag_config("ascii", foreground="#85929e")
            data_box.tag_config("offset", foreground="#f1c40f")
            data_box.tag_config("msg", foreground="#444444")

            data_box.configure(state="normal")

            data_box.insert("1.0", "\n" * 10)
            data_box.insert("end", "🔍 Select a layer to view details", "msg")
            data_box.tag_config("msg",
                                foreground="#444444",
                                justify="center")
            data_box.configure(state="disabled")

            self.active_button = None
            # Update display
            def update_display(name,current_btn):

                if self.active_button:
                    self.active_button.configure(fg_color="transparent", text_color="#bbbbbb")

                current_btn.configure(fg_color="#3498db", text_color="white")

                self.active_button = current_btn

                data_box.configure(state="normal")
                data_box.delete("1.0", "end")

                header, body = layer_contents[name]

                if name == "HEX DUMP":
                    data_box.insert("end", header, "layer_head")
                    for line in body.splitlines():
                        if "|" in line:
                            parts = line.split("|")
                            offset_hex = parts[0]
                            ascii_part = parts[1]
                            data_box.insert("end", offset_hex[:8], "offset")
                            data_box.insert("end", offset_hex[8:], "hex_code")
                            data_box.insert("end", f"| {ascii_part}\n", "ascii")

                else:
                    data_box.insert("end", header, "layer_head")
                    data_box.insert("end", body, "field_info")

                data_box.configure(state="disabled")

            # Create Button
            for layer_name in layer_contents.keys():

                btn = ctk.CTkButton(
                    nav_frame,
                    text=f"  ➤  {layer_name}",
                    fg_color="transparent",
                    hover_color="#2c3e50",
                    anchor="w",
                    height=40,
                    text_color="#bbbbbb",
                    font=("Roboto", 12),
                )
                btn.configure(command=lambda n=layer_name, b=btn: update_display(n, b))
                btn.pack(fill="x", padx=10, pady=5)

            detail_window.focus_force()
    def refresh_status_ui(self):
        try:
            self.stats_area.configure(state="normal")
            self.stats_area.delete("1.0", "end")

            header = f"{'SOURCE':<16} | {'DESTINATION':<16} | {'PKT':<4} | {'SIZE'}\n"
            self.stats_area.insert("end", header + "-" * 55 + "\n")

            sorted_connections = sorted(self.ip_stats.items(), key=lambda x: x[1]['size'], reverse=True)

            for index,(conn_key, info) in enumerate(sorted_connections[:15]):
                #conn_key Tuple / String
                if isinstance(conn_key, tuple):
                    src, dst = conn_key
                else:
                    src = conn_key
                    dst = "Unknown"

                size_str = f"{info['size'] / 1024:.1f}K" if info['size'] > 1024 else f"{info['size']}B"

                line_tag = f"rank_{index}"

                line = f"{str(src):<16} | {str(dst):<16} | {info['count']:<4} | {size_str}\n"
                self.stats_area.insert("end", line,line_tag)

            self.stats_area.configure(state="disabled")
        except Exception as e:
            print(f"UI Refresh Error: {e}")
    def open_monitor_window(self):
        # If already open
        if hasattr(self, "mon_win") and self.mon_win.winfo_exists():
            self.mon_win.focus()  # open old window
        else:
            from monitor_window import monitor_window_ui
            self.mon_win = monitor_window_ui(self, self.update_log)

    def update_interface_status(self, name, is_active=True):
        self.current_interface = name
        if is_active:
            self.iface_label.configure(
                text=f"📡 Interface: {name} (Monitor)",
                text_color="#2ecc71"
            )
        else:
            self.iface_label.configure(
                text=f"🌐 Interface: {name} (Managed)",
                text_color="#e74c3c"
            )

    def open_security_analyzer(self):
        if hasattr(self, "security_win") and self.security_win.winfo_exists():
            self.security_win.lift()

        else:
            self.security_win = security_analyzer_ui.SecurityAnalyzerUI(self)
            self.update_log("[+] Security Analyzer Module Started.")

# ---------------------------------------------
# Copyright (c) 2026 Mehadi Hasan
# Project: NetSpy - Network Security Analyzer
# License: MIT License
# ---------------------------------------