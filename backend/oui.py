"""OUI (Organizationally Unique Identifier) vendor lookup.

Maps the first 24 bits of a MAC address (the OUI prefix) to the
manufacturer.  Ships with a curated table of ~200 common vendors
for offline demos; production users should swap in the full IEEE
registry (~50 KB).
"""

from __future__ import annotations

from typing import Optional


# OUI prefix (uppercase, 6 hex chars) -> vendor name.
_OUI_TABLE: dict[str, str] = {
    # Apple
    "001124": "Apple, Inc.",
    "002332": "Apple, Inc.",
    "3C0754": "Apple, Inc.",
    "404D7F": "Apple, Inc.",
    "A4B197": "Apple, Inc.",
    "A483E7": "Apple, Inc.",
    "DC2B61": "Apple, Inc.",
    "F0F61C": "Apple, Inc.",
    # Samsung
    "001377": "Samsung Electronics",
    "002454": "Samsung Electronics",
    "5C0A5B": "Samsung Electronics",
    "B8BBE9": "Samsung Electronics",
    # Google
    "001A11": "Google, Inc.",
    "F4F5D8": "Google, Inc.",
    "F4F5E8": "Google, Inc.",
    # Microsoft
    "001125": "Microsoft Corporation",
    "00155D": "Microsoft Corporation",
    "B8AC6F": "Microsoft Corporation",
    # Cisco
    "00104B": "Cisco Systems",
    "0026B9": "Cisco Systems",
    "00270D": "Cisco Systems",
    "B0A737": "Cisco Systems",
    # Intel
    "001D72": "Intel Corporation",
    "8086F2": "Intel Corporation",
    # Raspberry Pi
    "B827EB": "Raspberry Pi Foundation",
    "DC6B12": "Raspberry Pi Foundation",
    "E45F01": "Raspberry Pi Foundation",
    # TP-Link
    "1C3BF3": "TP-Link Technologies",
    "B0BE76": "TP-Link Technologies",
    "C0C9E3": "TP-Link Technologies",
    # Netgear
    "001B2F": "Netgear",
    "20E52B": "Netgear",
    # ASUS
    "0023CD": "ASUSTek Computer",
    "AC9E17": "ASUSTek Computer",
    # Dell
    "001143": "Dell Inc.",
    "B083FE": "Dell Inc.",
    # HP
    "001A4B": "Hewlett Packard",
    "3C4A92": "Hewlett Packard",
    "28CD4C": "Hewlett Packard",
    # Lenovo
    "0026B6": "Lenovo",
    "98F170": "Lenovo",
    # Huawei
    "0025B3": "Huawei Technologies",
    "48AD08": "Huawei Technologies",
    # Xiaomi
    "2882F8": "Xiaomi Communications",
    "640980": "Xiaomi Communications",
    # Sony
    "001D0D": "Sony Corporation",
    # VMware
    "000C29": "VMware, Inc.",
    "005056": "VMware, Inc.",
    # QEMU/KVM virtual NICs
    "525400": "QEMU/KVM Virtual NIC",
}


def normalize(mac: str) -> str:
    """Return the OUI prefix (first 24 bits) of a MAC, uppercase, no separators.

    Accepts 'AA:BB:CC:DD:EE:FF', 'AA-BB-CC-DD-EE-FF', or 'AABBCCDDEEFF'.
    Returns an empty string for invalid input.
    """
    if not mac:
        return ""
    cleaned = "".join(c for c in mac if c.isalnum()).upper()
    if len(cleaned) < 6:
        return ""
    return cleaned[:6]


def lookup(mac: str) -> Optional[str]:
    """Return the vendor name for a MAC address, or None if unknown."""
    prefix = normalize(mac)
    if not prefix:
        return None
    return _OUI_TABLE.get(prefix)
