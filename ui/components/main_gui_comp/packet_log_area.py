# ===========================================================================
# NetSpy - Network Traffic Monitor & Security Analyzer
# Copyright (C) 2026 Mehadi Hasan
# Licensed under GNU GPL v3
# ===========================================================================

import customtkinter as ctk

class PacketLogArea(ctk.CTkFrame):

    def __init__(self, parent,
                 on_click: callable,
                 on_double_click: callable):
        super().__init__(parent, fg_color="transparent")

        header_text = (f"{'PROTOCOL':<11} | {'DIR':<7} | {'SOURCE IP':<22} | "
                       f"{'DESTINATION IP':<22} | {'SIZE'}")
        ctk.CTkLabel(
            self, text=header_text,
            font=("Consolas", 12, "bold"), text_color="#3498db"
        ).pack(anchor="w", padx=(15, 0))

        self.log_area = ctk.CTkTextbox(
            self, width=550, font=("Consolas", 13), border_width=2
        )
        self.log_area.pack(fill="both", expand=True)
        self.log_area.configure(state="disabled", cursor="hand2")

        # Colour tags
        tags = {
            "tcp":       "#5DADE2",
            "udp":       "#AF7AC5",
            "icmp":      "#F4D03F",
            "arp":       "#EB984E",
            "other":     "#95A5A6",
            "incoming":  "#00FF00",
            "outgoing":  "#FF3131",
            "multi":     "#8E44AD",
            "bcast":     "#7F8C8D",
        }
        for tag, color in tags.items():
            self.log_area.tag_config(tag, foreground=color)
        self.log_area.tag_config("highlight", background="#3d3d3d")

        # Event bindings
        self.log_area.bind("<Button-1>", on_click)
        self.log_area.bind("<Double-1>", on_double_click)

    def append(self, message: str, protocol_tag: str,
               direction_tag: str):
        """Insert a coloured log line."""
        self.log_area.configure(state="normal")
        parts = message.split('|')
        if len(parts) >= 3:
            self.log_area.insert("end", parts[0] + "|", protocol_tag)
            self.log_area.insert("end", parts[1] + "|", direction_tag)
            self.log_area.insert("end", "|".join(parts[2:]) + "\n", protocol_tag)
        else:
            self.log_area.insert("end", message + "\n")
        self.log_area.configure(state="disabled")
        self.log_area.see("end")

    def append_plain(self, message: str):
        self.log_area.configure(state="normal")
        self.log_area.insert("end", message + "\n")
        self.log_area.configure(state="disabled")
        self.log_area.see("end")

    def highlight_line(self, event):
        self.log_area.tag_remove("highlight", "1.0", "end")
        index = self.log_area.index(f"@{event.x},{event.y}")
        row = index.split('.')[0]
        self.log_area.tag_add("highlight", f"{row}.0", f"{row}.end")

    def get_line_number(self, event) -> int:
        index = self.log_area.index(f"@{event.x},{event.y}")
        return int(index.split(".")[0])