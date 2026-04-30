# ===========================================================================
# NetSpy - Network Traffic Monitor & Security Analyzer
# Copyright (C) 2026 Mehadi Hasan
# Licensed under GNU GPL v3
# ===========================================================================

import re
import threading
import customtkinter as ctk

from core.deauth import send_deauth
from ui.components.advanced_monitor_comp.control_panel import ControlPanel
from ui.components.advanced_monitor_comp.status_strip import StatusStrip
from ui.components.advanced_monitor_comp.client_table import ClientTable
from ui.components.advanced_monitor_comp.action_buttons import ActionButtons
from ui.components.advanced_monitor_comp.terminal_display import TerminalDisplay


class AdvanceMonitorUI(ctk.CTkToplevel):
    def __init__(self, parent, interface, update_log):
        super().__init__(parent)

        self.interface = interface
        self.update_log = update_log
        self.is_attacking = False

        self.title(f"NetSpy Advanced - [{self.interface}]")
        self.geometry("1000x800")
        self.configure(fg_color="#0a0a0a")
        self.attributes("-topmost", True)

        # ── Header ─────────────────────
        ctk.CTkLabel(
            self,
            text=f"NETSPY :: INSPECTOR_MODE :: {self.interface.upper()}",
            font=("Consolas", 18), text_color="#00FF00"
        ).pack(pady=(15, 5))

        # ── Components ─────────────────────
        self.control_panel = ControlPanel(self, on_lock_channel=self._on_lock_channel)
        self.control_panel.pack(fill="x", padx=20, pady=10)

        self.status_strip = StatusStrip(self)
        self.status_strip.pack(fill="x", padx=20, pady=(0, 10))

        ctk.CTkLabel(self, text="[ LIVE_CLIENT_STATIONS ]",
                     font=("Consolas", 13), text_color="#666").pack(anchor="w", padx=25)
        self.client_table = ClientTable(self)
        self.client_table.pack(fill="x", padx=20, pady=(5, 10))

        self.action_buttons = ActionButtons(self, on_deauth=self._on_deauth_clicked)
        self.action_buttons.pack(pady=10)

        ctk.CTkLabel(self, text="[ EXECUTION_LOG ]",
                     font=("Consolas", 13), text_color="#666").pack(anchor="w", padx=25)
        self.terminal = TerminalDisplay(self)
        self.terminal.pack(fill="both", expand=True, padx=20, pady=(5, 20))


    # Public API (called by MonitorWindowUI)


    def receive_raw_data(self, found_ssids, router_clients, host_names, found_clients):
        """Sync latest scan data into all sub-components."""
        current_selection = self.control_panel.get_selected_bssid_raw()

        try:
            router_list = [
                f"{info[0]} (Ch: {info[2]}) [{bssid}]"
                for bssid, info in found_ssids.items()
            ]
            self.control_panel.update_network_list(router_list)

            if "[" not in current_selection:
                self.status_strip.set_idle("STATUS: WAITING_FOR_SELECTION")
                return

            target_bssid = re.search(r"\[(.*?)\]", current_selection).group(1)

            if target_bssid not in found_ssids:
                self.status_strip.set_out_of_range()
                return

            target_info = found_ssids[target_bssid]
            tgt_ch = str(target_info[2])
            card_ch = self.control_panel.get_selected_channel()

            self.status_strip.set_target(
                ssid=target_info[0], enc=target_info[3],
                tgt_ch=tgt_ch, cipher=target_info[4],
                auth=target_info[5], card_ch=card_ch
            )

            clients = list(router_clients.get(target_bssid, []))
            self.control_panel.update_client_list(clients)
            self.client_table.refresh(target_bssid, router_clients, host_names, found_clients)

        except Exception as e:
            self.terminal.write(f"Sync Error: {e}")

    # Private callbacks

    def _on_lock_channel(self):
        if self.master.is_hopping:
            channel = self.control_panel.get_selected_channel()
            self.master.is_hopping = False
            result = __import__('os').system(
                f"sudo iw dev {self.interface} set channel {channel}"
            )
            if result == 0:
                self.terminal.write(f"LOCK: Card fixed on CH {channel}. Hopping DISABLED.")
                self.control_panel.set_lock_btn_locked(channel)
            else:
                self.terminal.write("ERROR: Failed to lock channel.")
                self.master.is_hopping = True
        else:
            self.master.is_hopping = True
            self.terminal.write("RESUME: Hopping started across all channels...")
            self.control_panel.set_lock_btn_hopping()

    def _on_deauth_clicked(self):
        if self.master.is_hopping:
            self.terminal.write("ERROR: Lock the channel first before attacking!")
            return

        if self.is_attacking:
            self.is_attacking = False
            self.action_buttons.set_idle()
            self.terminal.write("ATTACK_STOPPED: Sending termination signal...")
            return

        current_router = self.control_panel.get_selected_bssid_raw()
        selected_client = self.control_panel.get_selected_client()

        if "[" not in current_router or "All" in selected_client:
            self.terminal.write("ERROR: Select a specific target first!")
            return

        target_bssid = re.search(r"\[(.*?)\]", current_router).group(1)
        self.is_attacking = True
        self.action_buttons.set_attacking()

        threading.Thread(
            target=send_deauth,
            args=(
                self.interface,
                selected_client,
                target_bssid,
                lambda: self.is_attacking,
                self.terminal.write,
            ),
            daemon=True
        ).start()