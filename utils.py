# ===========================================================================
# NetSpy - Network Traffic Monitor & Security Analyzer
# Copyright (C) 2026 Mehadi Hasan

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
# ===============================================================================


import os
def load_vendor_db():
    vendor_dict = {}

    base_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(base_dir, "manuf")

    if not os.path.exists(file_path):
        print("!!! 'manuf' file not found in current folder !!!")
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

    return  vendor_dict

VENDOR_DB = load_vendor_db()
