# ===========================================================================
# NetSpy - Network Traffic Monitor & Security Analyzer
# Copyright (C) 2026 Mehadi Hasan
# Licensed under GNU GPL v3
# ===========================================================================

import customtkinter as ctk


class MonitorHeader(ctk.CTkFrame):

    def __init__(self, parent):
        super().__init__(parent, fg_color="#1a1a1a", height=80, corner_radius=0)

        ctk.CTkLabel(
            self, text="📡 MONITOR MODE SETUP",
            font=("Roboto", 20, "bold"), text_color="#3498db"
        ).place(relx=0.5, rely=0.4, anchor="center")

        ctk.CTkLabel(
            self,
            text="Configure your wireless adapter for packet injection",
            font=("Roboto", 11), text_color="#888888"
        ).place(relx=0.5, rely=0.7, anchor="center")