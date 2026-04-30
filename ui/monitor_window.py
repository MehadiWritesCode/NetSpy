# ===========================================================================
# NetSpy - Network Traffic Monitor & Security Analyzer
# Copyright (C) 2026 Mehadi Hasan
# Licensed under GNU GPL v3
# ===========================================================================

import time
import threading
import customtkinter as ctk

from core import wifi_monitor
from core.channel import ChannelHopper
from ui.advanced_monitor import AdvanceMonitorUI
from ui.components.monitor_window_comp.monitor_header import MonitorHeader
from ui.components.monitor_window_comp.interface_panel import InterfacePanel
from ui.components.monitor_window_comp.live_stats_box import LiveStatsBox
from ui.components.monitor_window_comp.monitor_control_buttons import MonitorControlButtons


class MonitorWindowUI(ctk.CTkToplevel):
    def __init__(self, parent, update_log):
        super().__init__(parent)

        self.update_log = update_log
        self._hopper: ChannelHopper | None = None
        self.stop_events = threading.Event()

        self.title("NetSpy - Wireless Setup")
        self.geometry("1200x950")
        self.attributes("-topmost", True)
        self.configure(fg_color="#121212")

        # ── Header ───────────────────────────────
        self.header = MonitorHeader(self)
        self.header.pack(fill="x", side="top")

        # ── Content ───────────────────────────────────────
        self.content_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.content_frame.pack(fill="both", expand=True, padx=30, pady=20)

        ifaces = wifi_monitor.get_available_interface()
        self.iface_panel = InterfacePanel(self.content_frame, ifaces)
        self.iface_panel.pack(fill="x")

        self.live_stats = LiveStatsBox(self.content_frame)
        self.live_stats.pack(fill="both", expand=True)

        # Advanced inspector button (hidden until monitor mode is active)
        self.advanced_btn = ctk.CTkButton(
            self.content_frame, text="🔍 OPEN ADVANCED INSPECTOR",
            font=("Roboto", 14, "bold"), height=45,
            fg_color="#3498db", hover_color="#2980b9",
            command=self.open_advanced_menu
        )

        # ── Bottom buttons ───────────────────
        self.control_buttons = MonitorControlButtons(
            self,
            on_activate=self._do_activate,
            on_deactivate=self._do_deactivate,
        )
        self.control_buttons.pack(pady=(0, 30), expand=True)


    # Monitor mode lifecycle


    def _do_activate(self):
        interface = self.iface_panel.get_interface()
        self.stop_events.clear()

        if "eth" in interface.lower():
            self.iface_panel.set_status(
                "> ERROR: Ethernet cannot enter monitor mode!", "cyan"
            )
            return

        self.iface_panel.set_status("> Diagnosing hardware support...", "cyan")
        self.update_idletasks()

        if not wifi_monitor.check_monitor_mode():
            self.iface_panel.set_status(
                "> ERROR: Hardware does NOT support monitor mode!", "#FF3131"
            )
            self.update_log(f"[ERROR] Hardware incompatible for {interface}")
            return

        self.iface_panel.set_status(
            f"> Support Confirmed! Activating {interface}...", "yellow"
        )
        self.update_idletasks()

        success, new_name = wifi_monitor.activate_monitor_mode(interface)

        if not success:
            self.iface_panel.set_status(
                "> ERROR: Activation failed. Check Sudo permissions.", "#FF3131"
            )
            return

        self.iface_panel.set_interface(new_name)
        self.iface_panel.set_status(f"> SUCCESS: {new_name} is active!", "#00FF00")
        self.update_log(f"[SYSTEM] Switched to Monitor Mode: {new_name}")

        # Start channel hopper
        self._hopper = ChannelHopper(new_name, self.stop_events)
        self._hopper.start()
        # Expose is_hopping so AdvanceMonitorUI can read/write it
        self.is_hopping = self._hopper.is_hopping

        self.advanced_btn.pack(pady=10)

        if hasattr(self.master, "update_interface_status"):
            self.master.update_interface_status(new_name)

        self.control_buttons.set_monitoring()

        threading.Thread(
            target=wifi_monitor.start_live_capture,
            args=(new_name, self._on_live_update, self.stop_events),
            daemon=True
        ).start()

    def _do_deactivate(self):
        self.stop_events.set()
        interface = self.iface_panel.get_interface()
        self.advanced_btn.pack_forget()

        self.iface_panel.set_status(f"> Stopping {interface}...", "yellow")
        self.update_idletasks()

        if wifi_monitor.deactivate_monitor_mode(interface):
            time.sleep(1)
            self.iface_panel.set_status(
                "> SUCCESS: Network restored to Managed mode.", "#00FF00"
            )
            self.update_log("[SYSTEM] Monitor mode disabled. NetworkManager restarted.")
            original_name = interface.replace("mon", "")
            self.iface_panel.set_interface(original_name)
            self.control_buttons.set_idle()

            if hasattr(self.master, "update_interface_status"):
                self.master.update_interface_status(original_name, is_active=False)
        else:
            self.iface_panel.set_status("> ERROR: Reset failed.", "#FF3131")


    # Live capture callback


    def _on_live_update(self, router_msg, device_msg, summary_msg,
                        found_ssids, router_clients, host_names, found_clients):
        self.live_stats.update(router_msg, device_msg, summary_msg)
        self.last_data = (found_ssids, router_clients, host_names, found_clients)

        if hasattr(self, 'advanced_window') and self.advanced_window.winfo_exists():
            try:
                self.advanced_window.receive_raw_data(
                    found_ssids, router_clients, host_names, found_clients
                )
            except Exception as e:
                print(f"Update error: {e}")


    # Advanced inspector


    def open_advanced_menu(self):
        if hasattr(self, 'advanced_window') and self.advanced_window.winfo_exists():
            self.advanced_window.lift()
            return

        interface = self.iface_panel.get_interface()
        self.advanced_window = AdvanceMonitorUI(self, interface, self.update_log)
        self.update_log(f"[UI] Advanced Inspector launched for {interface}")
        self.iface_panel.set_status(
            "> Advanced Inspector is now running.", "cyan"
        )

    # is_hopping property (bridges hopper ↔ AdvanceMonitorUI)


    @property
    def is_hopping(self) -> bool:
        return self._hopper.is_hopping if self._hopper else True

    @is_hopping.setter
    def is_hopping(self, value: bool):
        if self._hopper:
            self._hopper.is_hopping = value