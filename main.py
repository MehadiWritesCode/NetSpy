# ===========================================================================
# NetSpy - Network Traffic Monitor & Security Analyzer
# Copyright (C) 2026 Mehadi Hasan
# Licensed under GNU GPL v3
# ===========================================================================

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import customtkinter as ctk

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

from ui.main_window import NetSpyGUI

if __name__ == "__main__":
    app = NetSpyGUI()
    app.mainloop()