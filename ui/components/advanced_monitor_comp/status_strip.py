# ===========================================================================
# NetSpy - Network Traffic Monitor & Security Analyzer
# Copyright (C) 2026 Mehadi Hasan
# Licensed under GNU GPL v3
# ===========================================================================

import customtkinter as ctk


class StatusStrip(ctk.CTkFrame):

    _IDLE_TEXT = "TARGET_STATUS: IDLE | ENC: --- | CH_LOCK: -- | CARD_CH: --"

    def __init__(self, parent):
        super().__init__(parent, fg_color="#1a1a1a", height=30, corner_radius=0)

        self._label = ctk.CTkLabel(
            self, text=self._IDLE_TEXT,
            font=("Consolas", 11), text_color="#888"
        )
        self._label.pack(side="left", padx=15)

    def set_idle(self, message: str = "STATUS: WAITING_FOR_SELECTION"):
        self._label.configure(text=message, text_color="#888")

    def set_target(self, ssid: str, enc: str, tgt_ch: str,
                   cipher: str, auth: str, card_ch: str):

        color = "#00FF00" if card_ch == tgt_ch else "#FF3333"
        text = (f"TARGET: {ssid} | ENC: {enc} | TGT_CH: {tgt_ch} | "
                f"CIPHER: {cipher} | AUTH: {auth} | CARD_CH: {card_ch}")
        self._label.configure(text=text, text_color=color)

    def set_out_of_range(self):
        self._label.configure(text="STATUS: TARGET_NOT_IN_RANGE", text_color="#888")