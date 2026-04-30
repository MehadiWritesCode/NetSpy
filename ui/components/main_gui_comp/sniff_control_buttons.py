# ===========================================================================
# NetSpy - Network Traffic Monitor & Security Analyzer
# Copyright (C) 2026 Mehadi Hasan
# Licensed under GNU GPL v3
# ===========================================================================

import customtkinter as ctk

class SniffControlButtons(ctk.CTkFrame):

    def __init__(self, parent, on_start: callable, on_stop: callable):
        super().__init__(parent, fg_color="transparent")

        self._container = ctk.CTkFrame(self, fg_color="transparent")
        self._container.pack(expand=True)

        self.start_btn = ctk.CTkButton(
            self._container, text="▶  Start Sniffing",
            font=("Roboto", 14, "bold"), width=170, height=42,
            corner_radius=10, command=on_start
        )
        self.start_btn.pack(side="left", padx=15)

        self.stop_btn = ctk.CTkButton(
            self._container, text="⏹  Stop Sniffing",
            font=("Roboto", 14, "bold"), width=170, height=42,
            corner_radius=10, fg_color="#A82424", hover_color="#C0392B",
            state="disabled", command=on_stop
        )
        self.stop_btn.pack(side="left", padx=15)

    def set_sniffing(self):
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")

    def set_idle(self):
        self.start_btn.configure(state="normal", text="▶  Start Sniffing")
        self.stop_btn.configure(state="disabled")