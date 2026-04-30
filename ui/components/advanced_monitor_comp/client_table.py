# ===========================================================================
# NetSpy - Network Traffic Monitor & Security Analyzer
# Copyright (C) 2026 Mehadi Hasan
# Licensed under GNU GPL v3
# ===========================================================================

import customtkinter as ctk
from core.utils import VENDOR_DB


class ClientTable(ctk.CTkTextbox):


    _HEADER = (f"{'ID':<4} | {'CLIENT_MAC':<18} | {'STATION_NAME':<20} | "
               f"{'PWR':<8} | {'PKTS':<8} | {'STATUS':<8}\n")
    _SEPARATOR = "-" * 85 + "\n"

    def __init__(self, parent):
        super().__init__(
            parent, height=220, fg_color="#050505",
            text_color="#00FF00", font=("Consolas", 13),
            corner_radius=0, border_width=1, border_color="#222", wrap="none"
        )
        self.configure(state="disabled")

    def refresh(self, target_bssid: str, router_clients: dict,
                host_names: dict, found_clients: dict):
        """Re-render the table for *target_bssid*."""
        self.configure(state="normal")
        self.delete("1.0", "end")
        self.insert("end", self._HEADER + self._SEPARATOR)

        clients = list(set(router_clients.get(target_bssid, [])))
        if not clients:
            self.insert("end", "\n   [!] LIST_EMPTY: SEARCHING_FOR_STATIONS...\n")
        else:
            for i, c_mac in enumerate(clients, start=1):
                c_mac = str(c_mac).strip()
                h_name = str(host_names.get(c_mac.lower(), "")).strip()
                prefix = c_mac[:8].upper()
                brand = VENDOR_DB.get(prefix, "GENERIC")
                display_name = h_name if h_name else brand
                data = found_clients.get(c_mac, [-100, 0])
                line = (f"{i:<4} | {c_mac:<18} | {display_name:<20} | "
                        f"{data[0]:<8} | {data[1]:<8} | {'ACTIVE':<8}\n")
                self.insert("end", line)

        self.configure(state="disabled")