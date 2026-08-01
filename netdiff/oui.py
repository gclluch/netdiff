"""MAC prefix to vendor, offline.

The old version called macvendors.com once per device per scan, which meant a
scan needed internet, leaked the local inventory to a third party, and got rate
limited. A prefix lookup is a dict lookup; it does not need a network.

The bundled table covers the vendors that actually show up on a home network.
For full coverage, point NETDIFF_OUI at the IEEE registry file (oui.csv from
standards-oui.ieee.org) and it will be loaded instead.
"""

from __future__ import annotations

import csv
import os
from functools import lru_cache
from pathlib import Path

# Locally administered addresses have a set second-least-significant bit in the
# first octet. Modern phones randomise these per network, so a "new device"
# that is actually a returning phone is expected, not a bug - say so plainly.
_RANDOMISED_NIBBLES = {"2", "6", "a", "e"}

COMMON = {
    "00:17:88": "Philips Hue",
    "00:1a:11": "Google",
    "00:1d:c9": "Ubiquiti",
    "00:23:12": "Apple",
    "00:24:36": "Apple",
    "00:0e:58": "Sonos",
    "00:1c:b3": "Apple",
    "18:b4:30": "Google Nest",
    "24:a4:3c": "Ubiquiti",
    "28:6c:07": "Xiaomi",
    "3c:5a:b4": "Google",
    "40:9f:38": "Sonos",
    "44:65:0d": "Amazon",
    "48:a6:b8": "Sonos",
    "4c:ef:c0": "Amazon",
    "50:c7:bf": "TP-Link",
    "5c:aa:fd": "Sonos",
    "68:54:fd": "Amazon",
    "70:88:6b": "Roku",
    "74:da:88": "TP-Link",
    "78:e1:03": "Sonos",
    "7c:d9:5c": "Google Nest",
    "88:e9:fe": "Apple",
    "8c:85:90": "Apple",
    "94:9f:3e": "Sonos",
    "a4:77:33": "Google",
    "ac:63:be": "Amazon",
    "b0:be:76": "TP-Link",
    "b8:27:eb": "Raspberry Pi",
    "d8:3a:dd": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "ec:fa:bc": "Espressif",
    "f0:ef:86": "Google Nest",
    "fc:fb:fb": "Cisco",
}


def is_randomised(mac: str) -> bool:
    """True if this looks like a privacy-randomised MAC rather than a real one."""
    parts = mac.split(":")
    if len(parts) != 6 or len(parts[0]) != 2:
        return False
    return parts[0][1].lower() in _RANDOMISED_NIBBLES


@lru_cache(maxsize=1)
def _table() -> dict[str, str]:
    path = os.environ.get("NETDIFF_OUI")
    if not path or not Path(path).exists():
        return COMMON
    table = dict(COMMON)
    with open(path, newline="", encoding="utf-8", errors="replace") as handle:
        for row in csv.DictReader(handle):
            assignment = (row.get("Assignment") or "").strip()
            name = (row.get("Organization Name") or "").strip()
            if len(assignment) == 6 and name:
                prefix = ":".join(assignment[i : i + 2] for i in range(0, 6, 2)).lower()
                table[prefix] = name
    return table


def lookup(mac: str) -> str:
    """Vendor for a MAC, or a marker for randomised addresses, or ''."""
    prefix = mac.lower()[:8]
    vendor = _table().get(prefix, "")
    if vendor:
        return vendor
    return "randomised" if is_randomised(mac) else ""
