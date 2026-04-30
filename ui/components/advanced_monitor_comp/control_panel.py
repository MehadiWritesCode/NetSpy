# ===========================================================================
# NetSpy - Network Traffic Monitor & Security Analyzer
# Copyright (C) 2026 Mehadi Hasan
# Licensed under GNU GPL v3
# ===========================================================================

import customtkinter as ctk


class ControlPanel(ctk.CTkFrame):

    def __init__(self, parent, on_lock_channel: callable):
        super().__init__(parent, fg_color="#111", border_width=1,
                         border_color="#222", corner_radius=0)

        self._on_lock_channel = on_lock_channel

        all_channels = [1,2,3,4,5,6,7,8,9,10,11,12,13,
                        36,40,44,48,52,56,60,64,149,161]

        # Row 0 ─ BSSID + Channel
        ctk.CTkLabel(self, text="TARGET_BSSID:", font=("Consolas", 12),
                     text_color="#aaa").grid(row=0, column=0, padx=10, pady=15)

        self.network_selector = ctk.CTkComboBox(
            self, values=["Select Target..."], width=250,
            font=("Consolas", 12), dropdown_font=("Consolas", 12),
            corner_radius=0, fg_color="#000", border_color="#444"
        )
        self.network_selector.grid(row=0, column=1, padx=5)

        ctk.CTkLabel(self, text="CHANNEL:", font=("Consolas", 12),
                     text_color="#aaa").grid(row=0, column=2, padx=(20, 5))

        self.channel_dropdown = ctk.CTkComboBox(
            self, values=[str(ch) for ch in all_channels],
            width=80, font=("Consolas", 12), corner_radius=0,
            fg_color="#000", border_color="#444"
        )
        self.channel_dropdown.set("1")
        self.channel_dropdown.grid(row=0, column=3, padx=5)

        self.lock_btn = ctk.CTkButton(
            self, text="SET_CHANNEL",
            font=("Consolas", 12, "bold"), fg_color="#333", hover_color="#444",
            corner_radius=0, border_width=1, border_color="#555", width=120,
            command=self._on_lock_channel
        )
        self.lock_btn.grid(row=0, column=4, padx=15)

        # Row 1 ─ Client selector
        ctk.CTkLabel(self, text="TARGET_CLIENT:", font=("Consolas", 12),
                     text_color="#aaa").grid(row=1, column=0, padx=10, pady=5)

        self.client_selector = ctk.CTkComboBox(
            self, values=["All Clients (Broadcast)"], width=250,
            font=("Consolas", 12), corner_radius=0,
            fg_color="#000", border_color="#444"
        )
        self.client_selector.grid(row=1, column=1, padx=5)


    # Public helpers

    def get_selected_bssid_raw(self) -> str:
        """Returns the full combo-box text (e.g. 'SSID (Ch: 6) [AA:BB:CC:DD:EE:FF]')."""
        return self.network_selector.get()

    def get_selected_channel(self) -> str:
        return self.channel_dropdown.get()

    def get_selected_client(self) -> str:
        return self.client_selector.get()

    def update_network_list(self, router_list: list):
        if set(router_list) != set(self.network_selector.cget("values")):
            self.network_selector.configure(values=router_list)

    def update_client_list(self, clients: list):
        options = ["All Clients (Broadcast)"] + clients
        if set(options) != set(self.client_selector.cget("values")):
            self.client_selector.configure(values=options)

    def set_lock_btn_locked(self, channel: str):
        self.lock_btn.configure(text="RESUME_HOPPING", fg_color="#c0392b")

    def set_lock_btn_hopping(self):
        self.lock_btn.configure(text="SET_CHANNEL", fg_color="#333",
                                border_color="#555")