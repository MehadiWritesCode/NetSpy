# ===========================================================================
# NetSpy - Network Traffic Monitor & Security Analyzer
# Copyright (C) 2026 Mehadi Hasan
# Licensed under GNU GPL v3
# ===========================================================================

import customtkinter as ctk


class MonitorControlButtons(ctk.CTkFrame):

    def __init__(self, parent, on_activate: callable, on_deactivate: callable):
        super().__init__(parent, fg_color="transparent")

        self.activate_btn = ctk.CTkButton(
            self, text="ACTIVATE MONITOR MODE",
            font=("Roboto", 14, "bold"), height=50, width=300,
            fg_color="#27ae60", hover_color="#2ecc71", corner_radius=8,
            command=on_activate
        )
        self.activate_btn.grid(row=0, column=0, padx=10)

        ctk.CTkButton(
            self, text="STOP & RESET",
            font=("Roboto", 13, "bold"), height=45, width=180,
            fg_color="#c0392b", hover_color="#e74c3c",
            command=on_deactivate
        ).grid(row=0, column=1, padx=10)

    def set_monitoring(self):
        self.activate_btn.configure(state="disabled", text="MONITORING...")

    def set_idle(self):
        self.activate_btn.configure(state="normal", text="ACTIVATE MONITOR MODE")