# ===========================================================================
# NetSpy - Network Traffic Monitor & Security Analyzer
# Copyright (C) 2026 Mehadi Hasan
# Licensed under GNU GPL v3
# ===========================================================================

import customtkinter as ctk


class ActionButtons(ctk.CTkFrame):

    _BTN_STYLE = {
        "font": ("Consolas", 13, "bold"),
        "corner_radius": 0,
        "width": 220,
        "height": 40,
        "border_width": 1,
    }

    def __init__(self, parent, on_deauth: callable):
        super().__init__(parent, fg_color="transparent")

        self.kick_btn = ctk.CTkButton(
            self, text="EXECUTE_DEAUTH",
            fg_color="#000", hover_color="#c0392b",
            border_color="#c0392b", text_color="#c0392b",
            command=on_deauth,
            **self._BTN_STYLE
        )
        self.kick_btn.grid(row=0, column=0, padx=10)

        ctk.CTkButton(
            self, text="CPTR_HANDSHAKE",
            fg_color="#000", hover_color="#d35400",
            border_color="#d35400", text_color="#d35400",
            **self._BTN_STYLE
        ).grid(row=0, column=1, padx=10)

        ctk.CTkButton(
            self, text="PROBE_IDENTITY",
            fg_color="#000", hover_color="#555",
            border_color="#777", text_color="#eee",
            **self._BTN_STYLE
        ).grid(row=0, column=2, padx=10)

    def set_attacking(self):
        self.kick_btn.configure(text="STOP_ATTACK", fg_color="#FF3333")

    def set_idle(self):
        self.kick_btn.configure(text="EXECUTE_DEAUTH", fg_color="#1f1f1f")