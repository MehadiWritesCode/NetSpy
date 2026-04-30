# ===========================================================================
# NetSpy - Network Traffic Monitor & Security Analyzer
# Copyright (C) 2026 Mehadi Hasan
# Licensed under GNU GPL v3
# ===========================================================================

import os
import time
import threading


_CHANNELS = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 149, 153, 157, 161, 165,
]


class ChannelHopper:

    def __init__(self, interface: str, stop_event: threading.Event):
        self.interface = interface
        self.stop_event = stop_event
        self.is_hopping = True

    def start(self):
        t = threading.Thread(target=self._run, daemon=True)
        t.start()

    def lock_on(self, channel: int) -> bool:

        self.is_hopping = False
        result = os.system(
            f"sudo iw dev {self.interface} set channel {channel}"
        )
        return result == 0

    def resume(self):

        self.is_hopping = True

    # --------------------
    def _run(self):
        index = 0
        while not self.stop_event.is_set():
            if self.is_hopping:
                try:
                    os.system(
                        f"sudo iw dev {self.interface} "
                        f"set channel {_CHANNELS[index]}"
                    )
                    index = (index + 1) % len(_CHANNELS)
                except Exception:
                    pass
            time.sleep(0.3)