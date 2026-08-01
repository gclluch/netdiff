"""Command line interface: scan, inventory, history, watch."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

from . import oui, store
from .diff import diff, summarise
from .scan import discover

DEFAULT_PORTS = (22, 80, 443, 445, 554, 1883, 3389, 5000, 8080, 8443)


def send_webhook(url: str, payload: dict, timeout: float = 10) -> str:
    """POST a JSON payload. Returns '' on success, else a description."""
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status >= 400:
                return f"webhook returned HTTP {response.status}"
    except (urllib.error.URLError, OSError) as exc:
        return f"webhook failed: {exc}"
    return ""


def cmd_scan(args) -> int:
    ports = () if args.no_ports else tuple(args.ports)
    devices = discover(
        args.subnet,
        ports=ports,
        lookup_vendor=oui.lookup,
        resolve_names=not args.no_resolve,
    )
    conn = store.connect(args.db)
    # Read the prior scan before inserting this one, or the "previous" scan
    # would be the one we just wrote and every diff would be empty.
    recent = store.recent_scan_ids(conn, limit=1)
    previous = store.load_scan(conn, recent[0]) if recent else []
    scan_id = store.record_scan(conn, args.subnet, devices)
    changes = diff(previous, devices)

    if args.json:
        print(
            json.dumps(
                {
                    "scan_id": scan_id,
                    "subnet": args.subnet,
                    "devices": [d.__dict__ | {"ports": list(d.ports)} for d in devices],
                    "changes": [
                        {
                            "kind": c.kind,
                            "mac": c.device.mac,
                            "ip": c.device.ip,
                            "detail": c.detail,
                        }
                        for c in changes
                    ],
                },
                indent=2,
            )
        )
    else:
        print(f"scan {scan_id}: {len(devices)} device(s) on {args.subnet}")
        for device in devices:
            label = device.hostname or device.vendor or "unknown"
            open_ports = (
                f"  ports {','.join(str(p) for p in device.ports)}"
                if device.ports
                else ""
            )
            print(f"  {device.ip:<15} {device.mac}  {label}{open_ports}")
        print(f"\nchanges since last scan: {summarise(changes)}")
        for change in changes:
            print(f"  {change}")

    if changes and args.webhook:
        error = send_webhook(
            args.webhook,
            {
                "subnet": args.subnet,
                "summary": summarise(changes),
                "changes": [str(c) for c in changes],
            },
        )
        if error:
            # A failed alert must not look like a clean scan.
            print(error, file=sys.stderr)
            return 2

    if args.fail_on_change and changes:
        return 1
    return 0


def cmd_inventory(args) -> int:
    conn = store.connect(args.db)
    rows = store.inventory(conn)
    if not rows:
        print("no scans recorded yet - run `netdiff scan` first")
        return 0
    if args.json:
        print(json.dumps([r | {"ports": list(r["ports"])} for r in rows], indent=2))
        return 0
    print(f"{len(rows)} device(s) ever seen\n")
    for row in rows:
        label = row["hostname"] or row["vendor"] or "unknown"
        print(f"{row['ip']:<15} {row['mac']}  {label}")
        print(
            f"    first {row['first_seen']}  last {row['last_seen']}  seen {row['times_seen']}x"
        )
    return 0


def cmd_history(args) -> int:
    conn = store.connect(args.db)
    ids = store.recent_scan_ids(conn, limit=args.limit)
    if len(ids) < 2:
        print("need at least two scans to compare")
        return 0
    newest, older = ids[0], ids[1]
    changes = diff(store.load_scan(conn, older), store.load_scan(conn, newest))
    print(f"scan {older} -> {newest}: {summarise(changes)}")
    for change in changes:
        print(f"  {change}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netdiff",
        description="Track what is on your network and alert when it changes.",
    )
    parser.add_argument(
        "--db", default=str(store.DEFAULT_PATH), help="history database path"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a subnet, record it, report changes")
    scan.add_argument("subnet", help="CIDR to scan, e.g. 192.168.1.0/24")
    scan.add_argument("--ports", type=int, nargs="*", default=list(DEFAULT_PORTS))
    scan.add_argument("--no-ports", action="store_true", help="skip the port scan")
    scan.add_argument("--no-resolve", action="store_true", help="skip reverse DNS")
    scan.add_argument("--webhook", help="POST a JSON alert here when anything changed")
    scan.add_argument(
        "--fail-on-change",
        action="store_true",
        help="exit 1 if anything changed, for cron and CI",
    )
    scan.add_argument("--json", action="store_true")
    scan.set_defaults(func=cmd_scan)

    inv = sub.add_parser("inventory", help="every device ever seen")
    inv.add_argument("--json", action="store_true")
    inv.set_defaults(func=cmd_inventory)

    hist = sub.add_parser("history", help="diff the two most recent scans")
    hist.add_argument("--limit", type=int, default=2)
    hist.set_defaults(func=cmd_history)

    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
