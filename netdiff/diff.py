"""Compare two scans and describe what changed.

Pure functions over plain data: no database, no network. This is the part worth
getting right, so it is the part that is trivially testable.
"""

from __future__ import annotations

from dataclasses import dataclass

from .scan import Device

# Ordered by how much they should worry you, so a report reads worst-first.
SEVERITY = {
    "appeared": 2,
    "port-opened": 2,
    "vanished": 1,
    "ip-changed": 1,
    "port-closed": 0,
    "hostname-changed": 0,
}


@dataclass(frozen=True)
class Change:
    kind: str
    device: Device
    detail: str = ""

    @property
    def severity(self) -> int:
        return SEVERITY.get(self.kind, 0)

    def __str__(self) -> str:
        label = self.device.hostname or self.device.vendor or self.device.mac
        suffix = f" ({self.detail})" if self.detail else ""
        return f"[{self.kind}] {label} {self.device.ip} {self.device.mac}{suffix}"


def diff(previous, current) -> list[Change]:
    """Changes between two device lists, most significant first.

    Devices are matched by MAC, so a DHCP lease change is reported as
    `ip-changed` on one device rather than as a departure plus an arrival.
    """
    before = {d.key(): d for d in previous}
    after = {d.key(): d for d in current}

    changes: list[Change] = []

    for key, device in after.items():
        if key not in before:
            changes.append(Change("appeared", device))

    for key, device in before.items():
        if key not in after:
            changes.append(Change("vanished", device))

    for key, now in after.items():
        was = before.get(key)
        if was is None:
            continue
        if was.ip != now.ip:
            changes.append(Change("ip-changed", now, f"{was.ip} -> {now.ip}"))
        if was.hostname != now.hostname and (was.hostname or now.hostname):
            changes.append(
                Change(
                    "hostname-changed",
                    now,
                    f"{was.hostname or '-'} -> {now.hostname or '-'}",
                )
            )
        opened = sorted(set(now.ports) - set(was.ports))
        closed = sorted(set(was.ports) - set(now.ports))
        if opened:
            changes.append(
                Change("port-opened", now, ", ".join(str(p) for p in opened))
            )
        if closed:
            changes.append(
                Change("port-closed", now, ", ".join(str(p) for p in closed))
            )

    # Stable secondary sort by IP so identical runs produce identical output,
    # which matters when the output is piped into a diff or an alert.
    changes.sort(key=lambda c: (-c.severity, c.device.ip))
    return changes


def summarise(changes) -> str:
    if not changes:
        return "no changes"
    counts: dict[str, int] = {}
    for change in changes:
        counts[change.kind] = counts.get(change.kind, 0) + 1
    return ", ".join(f"{n} {kind}" for kind, n in sorted(counts.items()))
