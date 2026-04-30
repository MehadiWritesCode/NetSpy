# ===========================================================================
# NetSpy - Network Traffic Monitor & Security Analyzer
# Copyright (C) 2026 Mehadi Hasan
# Licensed under GNU GPL v3
# ===========================================================================

import customtkinter as ctk

class TrafficStatsPanel(ctk.CTkFrame):

    _RANK_COLORS = [
        "#00FF00","#2ECC71","#27AE60","#16A085","#52BE80",
        "#3498DB","#5DADE2","#85C1E9","#AED6F1","#D6EAF8",
        "#F4D03F","#F7DC6F","#F9E79F","#FCF3CF","#95A5A6",
    ]

    def __init__(self, parent, on_open_security: callable):
        super().__init__(parent, width=480, fg_color="#212121")
        self.pack_propagate(False)

        ctk.CTkLabel(
            self, text="Top Traffic Sources",
            font=("Roboto", 14, "bold"), text_color="#3498db"
        ).pack(pady=5)

        self.stats_area = ctk.CTkTextbox(
            self, width=460, font=("Consolas", 11),
            fg_color="#1a1a1a", border_width=1, wrap="none"
        )
        self.stats_area.pack(padx=10, pady=5, fill="both", expand=True)
        self.stats_area.configure(state="disabled")

        for i, color in enumerate(self._RANK_COLORS):
            self.stats_area.tag_config(f"rank_{i}", foreground=color)
        self.stats_area.tag_config("header", foreground="#FFFFFF")

        ctk.CTkFrame(self, height=2, fg_color="#333").pack(fill="x", pady=10)

        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(side="bottom", fill="x", padx=10, pady=(0, 20))

        ctk.CTkButton(
            btn_frame, text="🛡️ SECURITY ANALYZER",
            font=("Roboto", 13, "bold"), fg_color="#c0392b",
            hover_color="#a93226", height=45,
            command=on_open_security
        ).pack(fill="x")

    def refresh(self, ip_stats: dict):

        try:
            self.stats_area.configure(state="normal")
            self.stats_area.delete("1.0", "end")

            header = f"{'SOURCE':<16} | {'DESTINATION':<16} | {'PKT':<4} | {'SIZE'}\n"
            self.stats_area.insert("end", header + "-" * 55 + "\n", "header")

            sorted_conns = sorted(
                ip_stats.items(), key=lambda x: x[1]['size'], reverse=True
            )
            for idx, (conn_key, info) in enumerate(sorted_conns[:15]):
                src, dst = conn_key if isinstance(conn_key, tuple) else (conn_key, "Unknown")
                size_str = (f"{info['size'] / 1024:.1f}K"
                            if info['size'] > 1024 else f"{info['size']}B")
                line = f"{str(src):<16} | {str(dst):<16} | {info['count']:<4} | {size_str}\n"
                self.stats_area.insert("end", line, f"rank_{idx}")

            self.stats_area.configure(state="disabled")
        except Exception as e:
            print(f"UI Refresh Error: {e}")