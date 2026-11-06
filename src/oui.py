"""Vendor lookup from the MAC prefix (OUI).

The table lives in oui_data.py, generated from the official IEEE MA-L registry
by tools/update_oui.py. To refresh it: python tools/update_oui.py
"""
from oui_data import OUI


def vendor(mac: str) -> str:
    return OUI.get(mac.upper().replace("-", ":")[:8], "")
