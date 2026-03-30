import threading
from string import printable

import sniffer
import customtkinter as ctk
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class NetSpyGUI(ctk.CTk):  # It means Child of CustomTkinter

    def __init__(self):
        super().__init__()

        # windows title
        self.title("NetSpy - Network Traffic Monitor")
        self.geometry("1200x900")

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

        self.line = ctk.CTkFrame(self, height=2, width=400, fg_color="gray")
        self.line.pack(pady=10)

        # middle container
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
        self.button_frame.pack(fill="x", pady=20)

        # start button
        self.start_btn = ctk.CTkButton(self.button_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_btn.pack(side="left", expand=True, padx=10)

        # stop button
        self.stop_btn = ctk.CTkButton(self.button_frame, text="Stop Sniffing", command=self.stop_sniffing,state="disabled", fg_color="#A82424")
        self.stop_btn.pack(side="left", expand=True, padx=10)

    def stop_check(self):
        return not self.is_sniffing

    def start_sniffing(self):
        self.is_sniffing = True
        self.update_log("[+] Monitoring Started...")

        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")

        #creating thread
        sniffer_thread = threading.Thread(
            target = sniffer.start_packet_sniffing,
            args = (self.update_log,self.stop_check),
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
        actual_index = line_number - 2

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
