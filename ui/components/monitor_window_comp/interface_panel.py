# ===========================================================================
# NetSpy - Network Traffic Monitor & Security Analyzer
# Copyright (C) 2026 Mehadi Hasan
# Licensed under GNU GPL v3
# ===========================================================================

import customtkinter as ctk


class InterfacePanel(ctk.CTkFrame):

    def __init__(self, parent, ifaces: list):
        super().__init__(parent, fg_color="transparent")

        ctk.CTkLabel(self, text="Select Network Interface:",
                     font=("Roboto", 13, "bold")).pack(anchor="w", pady=(10, 5))

        self.iface_dropdown = ctk.CTkComboBox(
            self, values=ifaces, width=400, height=40,
            fg_color="#1a1a1a", border_color="#333333",
            button_color="#3498db", dropdown_fg_color="#1a1a1a"
        )
        self.iface_dropdown.pack(pady=(0, 20))
        if "wlan0" in ifaces:
            self.iface_dropdown.set("wlan0")

        ctk.CTkLabel(self, text="System Status:",
                     font=("Roboto", 13, "bold")).pack(anchor="w", pady=(0, 5))

        self._status_box = ctk.CTkFrame(
            self, fg_color="#000000", height=70,
            border_width=1, border_color="#333333"
        )
        self._status_box.pack(fill="x")
        self._status_box.pack_propagate(False)

        self.status_text = ctk.CTkLabel(
            self._status_box, text="> Waiting for user action...",
            font=("Consolas", 12), text_color="#00FF00", anchor="w", padx=15
        )
        self.status_text.pack(fill="both", expand=True)

    def get_interface(self) -> str:
        return self.iface_dropdown.get()

    def set_interface(self, name: str):
        self.iface_dropdown.set(name)

    def set_status(self, text: str, color: str = "#00FF00"):
        self.status_text.configure(text=text, text_color=color)