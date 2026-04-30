# ===========================================================================
# NetSpy - Network Traffic Monitor & Security Analyzer
# Copyright (C) 2026 Mehadi Hasan
# Licensed under GNU GPL v3
# ===========================================================================

import threading
import customtkinter as ctk

from core import sniffer
from core import wifi_monitor
from ui.security_ui import SecurityAnalyzerUI
from ui.monitor_window import MonitorWindowUI
from ui.components.main_gui_comp.packet_log_area import PacketLogArea
from ui.components.main_gui_comp.traffic_stats_panel import TrafficStatsPanel
from ui.components.main_gui_comp.sniff_control_buttons import SniffControlButtons


class NetSpyGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("NetSpy - Network Traffic Monitor")
        self.geometry("1200x900")

        available_ifaces = wifi_monitor.get_available_interface()
        self.current_interface = (
            "wlan0" if "wlan0" in available_ifaces else
            (available_ifaces[0] if available_ifaces else "None")
        )

        # ── Interface label (top-left) ───────
        self.iface_label = ctk.CTkLabel(
            self,
            text=f"🌐 Interface: {self.current_interface}",
            font=("Roboto", 13, "bold"), text_color="#e74c3c"
        )
        self.iface_label.place(relx=0.02, rely=0.05, anchor="nw")

        # ── Title ───────────────
        ctk.CTkLabel(
            self, text="Welcome to NetSpy",
            font=("Roboto", 24, "bold"), text_color="white"
        ).pack(pady=(30, 10))

        ctk.CTkLabel(
            self, text=" -- See the Unseen --",
            font=("Roboto", 20, "italic"), text_color="#AAAAAA"
        ).pack(pady=(0, 20))

        # ── Monitor Mode button (top-right) ────────────
        ctk.CTkButton(
            self, text="📡 Monitor Mode", width=140, height=32,
            fg_color="#2c3e50", hover_color="#34495e",
            command=self.open_monitor_window, font=("Roboto", 12, "bold")
        ).place(relx=0.98, rely=0.05, anchor="ne")

        ctk.CTkFrame(self, height=2, width=400, fg_color="gray").pack(pady=10)

        # ── Middle container ───────────────────────
        middle = ctk.CTkFrame(self, fg_color="transparent")
        middle.pack(fill="both", expand=True, padx=20, pady=10)

        self.packet_log = PacketLogArea(
            middle,
            on_click=self._highlight_line,
            on_double_click=self._show_details,
        )
        self.packet_log.pack(side="left", fill="both", expand=True, padx=(0, 10))

        self.stats_panel = TrafficStatsPanel(
            middle, on_open_security=self.open_security_analyzer
        )
        self.stats_panel.pack(side="right", fill="y")

        # ── State ──────────────────────────
        self.packet_list = []
        self.ip_stats: dict = {}
        self.is_sniffing = False

        # ── Bottom buttons ──────────────────────
        self.sniff_buttons = SniffControlButtons(
            self, on_start=self._start_sniffing, on_stop=self._stop_sniffing
        )
        self.sniff_buttons.pack(fill="x", side="bottom", pady=(10, 30))


    # Sniffing


    def _start_sniffing(self):
        if not self.current_interface or self.current_interface == "None":
            self.update_log("[!] Error: Interface not detected.")
            return
        self.is_sniffing = True
        self.update_log(f"[+] Sniffing started on {self.current_interface}")
        self.sniff_buttons.set_sniffing()
        threading.Thread(
            target=sniffer.start_packet_sniffing,
            args=(self.update_log, lambda: not self.is_sniffing, self.current_interface),
            daemon=True
        ).start()

    def _stop_sniffing(self):
        self.is_sniffing = False
        self.update_log("[-] Monitoring Stopped.")
        self.sniff_buttons.set_idle()


    # Log area callbacks


    def _highlight_line(self, event):
        self.packet_log.highlight_line(event)

    def _show_details(self, event):
        self.packet_log.highlight_line(event)
        line_number = self.packet_log.get_line_number(event)
        actual_index = line_number - 1
        if 0 <= actual_index < len(self.packet_list):
            self._open_packet_inspector(self.packet_list[actual_index])


    # Public update_log (called by sniffer + other modules)


    def update_log(self, data):
        if isinstance(data, dict):
            message = data["display"]
            raw_packet = data["raw"]

            if hasattr(self, "security_win") and self.security_win.winfo_exists():
                self.security_win.engine.analyze_packet(raw_packet)

            self.packet_list.append(raw_packet)

            protocol_tag = "other"
            if "TCP" in message:    protocol_tag = "tcp"
            elif "UDP" in message:  protocol_tag = "udp"
            elif "ICMP" in message: protocol_tag = "icmp"
            elif "ARP" in message:  protocol_tag = "arp"

            direction_tag = "default"
            if "<< IN" in message:    direction_tag = "incoming"
            elif "OUT >>" in message: direction_tag = "outgoing"
            elif "MULTI" in message:  direction_tag = "multi"
            elif "BCAST" in message:  direction_tag = "bcast"

            self.packet_log.append(message, protocol_tag, direction_tag)

            try:
                if raw_packet and raw_packet.haslayer("IP"):
                    src = raw_packet["IP"].src
                    dst = raw_packet["IP"].dst
                    size = len(raw_packet)
                    key = (src, dst)
                    if key not in self.ip_stats:
                        self.ip_stats[key] = {"count": 0, "size": 0}
                    self.ip_stats[key]["count"] += 1
                    self.ip_stats[key]["size"] += size
                    self.stats_panel.refresh(self.ip_stats)
            except Exception as e:
                print(f"Stats Error: {e}")
        else:
            self.packet_log.append_plain(str(data))


    # Interface status (called by MonitorWindowUI)


    def update_interface_status(self, name: str, is_active: bool = True):
        self.current_interface = name
        if is_active:
            self.iface_label.configure(
                text=f"📡 Interface: {name} (Monitor)", text_color="#2ecc71"
            )
        else:
            self.iface_label.configure(
                text=f"🌐 Interface: {name} (Managed)", text_color="#e74c3c"
            )


    # Sub-window launchers


    def open_monitor_window(self):
        if hasattr(self, "mon_win") and self.mon_win.winfo_exists():
            self.mon_win.focus()
        else:
            self.mon_win = MonitorWindowUI(self, self.update_log)

    def open_security_analyzer(self):
        if hasattr(self, "security_win") and self.security_win.winfo_exists():
            self.security_win.lift()
        else:
            self.security_win = SecurityAnalyzerUI(self)
            self.update_log("[+] Security Analyzer Module Started.")


    # Packet inspector (detail popup) — unchanged logic


    def _open_packet_inspector(self, pkt):
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
            fields_body = "".join(
                f"  {field:<18} :  {val}\n"
                for field, val in temp_pkt.fields.items()
            )
            layer_contents[lname] = (header, fields_body)

            if lname == "RAW" or not temp_pkt.payload or isinstance(temp_pkt.payload, (bytes, str)):
                p_data = (temp_pkt.load if lname == "RAW" else
                          (temp_pkt.payload if isinstance(temp_pkt.payload, (bytes, str)) else None))
                if p_data:
                    h_header = f"  PAYLOAD / HEX DUMP  \n" + "━" * 40 + "\n"
                    rb = bytes(p_data)
                    h_body = ""
                    for i in range(0, len(rb), 16):
                        chunk = rb[i:i + 16]
                        hp = " ".join(f"{b:02x}" for b in chunk)
                        ap = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                        h_body += f"  {i:04x}  {hp:<48} | {ap}\n"
                    layer_contents["HEX DUMP"] = (h_header, h_body)
                break
            temp_pkt = temp_pkt.payload

        nav_frame = ctk.CTkFrame(detail_window, width=200, fg_color="#1a1a1a", corner_radius=0)
        nav_frame.pack(side="left", fill="y")
        ctk.CTkLabel(nav_frame, text="📜 LAYERS",
                     font=("Roboto", 15, "bold"), text_color="#3498db").pack(pady=25)

        data_box = ctk.CTkTextbox(
            detail_window, font=("Consolas", 14),
            fg_color="#121212", text_color="#d4d4d4", border_width=0
        )
        data_box.pack(side="right", fill="both", expand=True, padx=30, pady=30)
        data_box.tag_config("layer_head", foreground="#3498db")
        data_box.tag_config("field_info", foreground="#9cdcfe")
        data_box.tag_config("hex_code", foreground="#2ecc71")
        data_box.tag_config("ascii", foreground="#85929e")
        data_box.tag_config("offset", foreground="#f1c40f")
        data_box.tag_config("msg", foreground="#444444", justify="center")

        data_box.configure(state="normal")
        data_box.insert("1.0", "\n" * 10)
        data_box.insert("end", "🔍 Select a layer to view details", "msg")
        data_box.configure(state="disabled")

        self.active_button = None

        def update_display(name, current_btn):
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
                        data_box.insert("end", parts[0][:8], "offset")
                        data_box.insert("end", parts[0][8:], "hex_code")
                        data_box.insert("end", f"| {parts[1]}\n", "ascii")
            else:
                data_box.insert("end", header, "layer_head")
                data_box.insert("end", body, "field_info")
            data_box.configure(state="disabled")

        for layer_name in layer_contents:
            btn = ctk.CTkButton(
                nav_frame, text=f"  ➤  {layer_name}",
                fg_color="transparent", hover_color="#2c3e50",
                anchor="w", height=40, text_color="#bbbbbb", font=("Roboto", 12)
            )
            btn.configure(command=lambda n=layer_name, b=btn: update_display(n, b))
            btn.pack(fill="x", padx=10, pady=5)

        detail_window.focus_force()