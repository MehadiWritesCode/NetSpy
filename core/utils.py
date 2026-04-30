# ===========================================================================
# NetSpy - Network Traffic Monitor & Security Analyzer
# Copyright (C) 2026 Mehadi Hasan
# Licensed under GNU GPL v3
# ===========================================================================

import os

def load_vendor_db():
    vendor_dict = {}

    # data/ folder এ manuf file থাকবে
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    file_path = os.path.join(base_dir, "data", "manuf")

    if not os.path.exists(file_path):
        print("!!! 'manuf' file not found in data/ folder !!!")
        return {}

    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            if len(parts) >= 2:
                raw_prefix = parts[0].strip().upper()
                if len(raw_prefix) >= 8:
                    prefix_key = raw_prefix[:8]
                    vendor_name = parts[1].strip()
                    vendor_dict[prefix_key] = vendor_name

    return vendor_dict


VENDOR_DB = load_vendor_db()