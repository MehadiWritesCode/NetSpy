# ===========================================================================
# NetSpy - Network Traffic Monitor & Security Analyzer
# Copyright (C) 2026 Mehadi Hasan
# Licensed under GNU GPL v3
# ===========================================================================

import customtkinter as ctk


class LiveStatsBox(ctk.CTkFrame):

    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")

        # Header row
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.pack(fill="x", padx=10, pady=(10, 0))

        ctk.CTkLabel(
            header_frame, text="LIVE NETWORK TRAFFIC",
            font=("Roboto", 12, "bold"), text_color="#3498db"
        ).pack(side="left")

        self.counter_label = ctk.CTkLabel(
            header_frame, text="Routers: 0 | Devices: 0",
            font=("Consolas", 12, "bold"), text_color="#e67e22"
        )
        self.counter_label.pack(side="right")

        # Stats textbox
        self.textbox = ctk.CTkTextbox(
            self, height=380, fg_color="#050505",
            text_color="#00FF00", font=("Consolas", 13),
            border_width=1, border_color="#222222"
        )
        self.textbox.pack(fill="both", expand=True, padx=10, pady=10)
        self.textbox._textbox.tag_config("router_color", foreground="#3498db")
        self.textbox._textbox.tag_config("device_color", foreground="#2ecc71")
        self.textbox._textbox.tag_config("header_color", foreground="#888888")

    def update(self, router_msg: str, device_msg: str, summary_msg: str):
        """Clears and re-renders the stats table."""
        self.counter_label.configure(text=summary_msg)

        self.textbox.configure(state="normal")
        self.textbox.delete("1.0", "end")

        header = (
            f"{'TYPE':^12} | {'MAC ADDRESS':^20} | {'SSID ':^25} | {'PWR':^6} | "
            f"{'DEVICE':^12} | {'CH':^4} | {'ENC':^15} | {'CIPHER':^6} | "
            f"{'AUTH':^5} | {'CONN':^5}\n"
        )
        separator = "-" * 136 + "\n"

        h_start = self.textbox.index("end-1c")
        self.textbox.insert("end", header + separator)
        h_end = self.textbox.index("end-1c")
        self.textbox._textbox.tag_add("header_color", h_start, h_end)

        if router_msg.strip():
            r_start = self.textbox.index("end-1c")
            self.textbox.insert("end", router_msg)
            r_end = self.textbox.index("end-1c")
            self.textbox._textbox.tag_add("router_color", r_start, r_end)

        if device_msg.strip():
            d_start = self.textbox.index("end-1c")
            self.textbox.insert("end", device_msg)
            d_end = self.textbox.index("end-1c")
            self.textbox._textbox.tag_add("device_color", d_start, d_end)

        self.textbox.configure(state="disabled")
        self.textbox.see("end")