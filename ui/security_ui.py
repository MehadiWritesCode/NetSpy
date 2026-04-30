# ===========================================================================
# NetSpy - Network Traffic Monitor & Security Analyzer
# Copyright (C) 2026 Mehadi Hasan
# Licensed under GNU GPL v3
# ===========================================================================

import time
import os
import customtkinter as ctk
from core.security_engine import SecurityEngine


class SecurityAnalyzerUI(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)

        self.title("NetSpy - Security Analyzer & Leakage Detector")
        self.geometry("1100x900")
        self.configure(fg_color="#0a0a0a")
        self.attributes("-topmost", True)

        # --- Header ---
        self.header_frame = ctk.CTkFrame(self, fg_color="#1a1a1a", height=60, corner_radius=0)
        self.header_frame.pack(fill="x", side="top")

        self.title_label = ctk.CTkLabel(
            self.header_frame,
            text="🛡️ NETWORK SECURITY ANALYZER",
            font=("Consolas", 18, "bold"),
            text_color="#e74c3c"
        )
        self.title_label.place(relx=0.5, rely=0.5, anchor="center")

        # --- Dashboard Stats ---
        self.dash_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.dash_frame.pack(fill="x", padx=20, pady=20)

        self.create_stat_card(self.dash_frame, "TOTAL UPLOAD", "0.0 MB", "#3498db", 0)
        self.create_stat_card(self.dash_frame, "ACTIVE THREATS", "0", "#e74c3c", 1)
        self.create_stat_card(self.dash_frame, "DNS QUERIES", "0", "#f1c40f", 2)

        # --- Main Layout ---
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.pack(fill="both", expand=True, padx=20)

        ctk.CTkLabel(
            self.main_container,
            text="[ DEVICE TRAFFIC ANALYSIS ]",
            font=("Consolas", 12),
            text_color="#888"
        ).pack(anchor="w")

        self.traffic_table = ctk.CTkTextbox(
            self.main_container, height=250, fg_color="#050505",
            text_color="#00FF00", font=("Consolas", 12),
            border_width=1, border_color="#333"
        )
        self.traffic_table.pack(fill="x", pady=(5, 20))
        self.traffic_table.insert(
            "0.0",
            f"{'IP ADDRESS':<20} | {'LOCATION':<20} | {'UPLOADED':<15} | {'DNS REQS':<10} | {'RISK LEVEL':<10}\n"
            + "-" * 73
        )
        self.traffic_table.configure(state="disabled")

        ctk.CTkLabel(
            self.main_container,
            text="[ SECURITY EVENTS / ALERTS ]",
            font=("Consolas", 12),
            text_color="#888"
        ).pack(anchor="w")

        self.alert_log = ctk.CTkTextbox(
            self.main_container, fg_color="#000", text_color="#e74c3c",
            font=("Consolas", 12), border_width=1, border_color="#444"
        )
        self.alert_log.pack(fill="both", expand=True, pady=(5, 20))

        self.engine = SecurityEngine(
            alert_callback=self.add_alert,
            table_callback=self.update_table_ui
        )

    def create_stat_card(self, parent, title, val, color, col):
        card = ctk.CTkFrame(parent, fg_color="#111", border_width=1, border_color="#222", width=300, height=80)
        card.grid(row=0, column=col, padx=10, sticky="nsew")
        card.grid_propagate(False)

        ctk.CTkLabel(card, text=title, font=("Roboto", 11), text_color="#888").pack(pady=(10, 0))
        lbl = ctk.CTkLabel(card, text=val, font=("Roboto", 20, "bold"), text_color=color)
        lbl.pack()

        if not hasattr(self, 'stat_labels'):
            self.stat_labels = {}
        self.stat_labels[title] = lbl

    def add_alert(self, message):
        self.alert_log.configure(state="normal")
        timestamp = time.strftime("%H:%M:%S")
        self.alert_log.insert("1.0", f"[{timestamp}] 🚨 ALERT: {message}\n")
        self.alert_log.configure(state="disabled")
        os.system(f'notify-send "NetSpy Security Alert!" "{message}"')

    def update_table_ui(self, ip, data):
        self.traffic_table.configure(state="normal")
        self.traffic_table.delete("1.0", "end")

        header = f"{'IP ADDRESS':<20} | {'LOCATION':<20} | {'UPLOADED':<15} | {'DNS REQS':<10} | {'RISK':<10}\n"
        separator = "-" * 81 + "\n"
        self.traffic_table.insert("end", header)
        self.traffic_table.insert("end", separator)

        sorted_stats = sorted(self.engine.status.items(), key=lambda x: x[1]['upload'], reverse=True)

        for target_ip, info in sorted_stats:
            upload_mb = f"{info['upload'] / (1024 * 1024):.2f} MB"
            location = self.engine.get_location(str(target_ip))
            row = (
                f"{str(target_ip):<20} | {location[:20]:<20} | "
                f"{upload_mb:<15} | {info['dns']:<10} | {info['risk']:<10}\n"
            )
            self.traffic_table.insert("end", row)

        self.traffic_table.configure(state="disabled")

        total_upload = sum(i['upload'] for i in self.engine.status.values()) / (1024 * 1024)
        total_dns = sum(i['dns'] for i in self.engine.status.values())
        threats = sum(1 for i in self.engine.status.values() if i['risk'] == 'CRITICAL')

        self.stat_labels["TOTAL UPLOAD"].configure(text=f"{total_upload:.2f} MB")
        self.stat_labels["DNS QUERIES"].configure(text=str(total_dns))
        self.stat_labels["ACTIVE THREATS"].configure(text=str(threats))