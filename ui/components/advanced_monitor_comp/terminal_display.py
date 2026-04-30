# ===========================================================================
# NetSpy - Network Traffic Monitor & Security Analyzer
# Copyright (C) 2026 Mehadi Hasan
# Licensed under GNU GPL v3
# ===========================================================================

import customtkinter as ctk

class TerminalDisplay(ctk.CTkTextbox):

    def __init__(self, parent):
        super().__init__(
            parent, height=250, fg_color="#000",
            text_color="#00FF00", font=("Consolas", 12),
            corner_radius=0, border_width=1, border_color="#222"
        )
        self.configure(state="disabled")

    def write(self, message: str):

        self.configure(state="normal")
        self.insert("end", f"[*] {message}\n")
        self.see("end")
        self.configure(state="disabled")