"""Command line interface: scan, audit, inventory, history."""

from __future__ import annotations

import argparse
import json
import re
import sys
import textwrap
import urllib.error
import urllib.request

from . import audit as audit_rules
from . import mdns, oui, store, upnp
from .diff import diff, summarise
from .scan import discover, grab_banners

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


def device_label(hostname: str, vendor: str, services: str) -> str:
    """What to call a device, best evidence first.

    A hostname is what a device was named; its mDNS announcement is what it says
    it *is*. Both are worth printing, so the second one goes in parentheses
    beside the first - unless it is the only thing we have, in which case it is
    the label, and "unknown" is left for devices that told us nothing at all.
    """
    main = hostname or vendor or services or "unknown"
    return f"{main}  ({services})" if services and services != main else main


def cmd_scan(args) -> int:
    ports = () if args.no_ports else tuple(args.ports)
    devices = discover(
        args.subnet,
        ports=ports,
        lookup_vendor=oui.lookup,
        resolve_names=not args.no_resolve,
        services={} if args.no_mdns else mdns.discover(),
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
            label = device_label(device.hostname, device.vendor, device.services)
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


def print_field(label: str, text: str, wrap: bool = True) -> None:
    """One labelled block, indented under its finding.

    `verify` is never wrapped: it is meant to be copied into a shell, and
    reflowing a command silently corrupts it.
    """
    pad = " " * 14
    if wrap:
        print(
            textwrap.fill(
                text, 88, initial_indent=f"    {label:<9} ", subsequent_indent=pad
            )
        )
        return
    lines = text.split("\n")
    print(f"    {label:<9} {lines[0]}")
    for line in lines[1:]:
        print(f"{pad}{line}")


def print_headline(finding, is_new: bool = False) -> None:
    """One finding, one line, severity first.

    The default view. Fifteen findings rendered as fifteen full lessons is a
    wall of text people stop reading, and a lesson nobody reads teaches nothing
    - so depth is something you ask for with `-v` rather than something you have
    to wade through. The severity rides on the line rather than in a heading
    above a group, so any single line still says what it is once it has been
    copied somewhere else.
    """
    print_field(finding.severity, f"{finding.title}{'   [NEW]' if is_new else ''}")


def print_lesson(finding, is_new: bool = False) -> None:
    """Render one finding as the lesson it is, not as a severity-coloured row."""
    print(f"  {finding.title}{'   [NEW]' if is_new else ''}")
    print_field("evidence", finding.evidence, wrap=False)
    print_field("why", finding.why)
    print_field("fix", finding.fix)
    print_field("verify", finding.verify, wrap=False)
    print()


def cmd_audit(args) -> int:
    if args.explain:
        spec = audit_rules.RULES.get(args.explain)
        if spec is None:
            known = ", ".join(sorted(audit_rules.RULES))
            print(
                f"unknown rule {args.explain!r}\nknown rules: {known}", file=sys.stderr
            )
            return 2

        # Nothing has fired, so there is no device to name. Show the
        # placeholders as readable stand-ins rather than leaking "{port}".
        def placeholders(text):
            return re.sub(r"\{(\w+)\}", lambda m: m.group(1).upper(), text)

        print(f"{args.explain}  [{spec['severity']}]")
        print(f"  {placeholders(spec['title'])}\n")
        print_field("why", placeholders(spec["why"]))
        print_field("fix", placeholders(spec["fix"]))
        print_field("verify", placeholders(spec["verify"]), wrap=False)
        return 0

    if not args.subnet:
        print(
            "audit needs a subnet, e.g. netdiff audit 192.168.1.0/24", file=sys.stderr
        )
        return 2

    devices = discover(
        args.subnet,
        ports=tuple(args.ports),
        lookup_vendor=oui.lookup,
        resolve_names=not args.no_resolve,
        services={} if args.no_mdns else mdns.discover(),
    )
    banners = grab_banners(
        (device.ip, port) for device in devices for port in device.ports
    )
    gateway = None if args.no_upnp else upnp.probe_gateway(args.subnet)
    findings = audit_rules.audit(devices, gateway, banners)

    conn = store.connect(args.db)
    scan_id = store.record_scan(conn, args.subnet, devices)
    # Compare against the last scan that actually audited, not merely the last
    # scan - otherwise a plain `netdiff scan` in between makes everything look new.
    previous_id = store.last_audited_scan_id(conn, scan_id)
    seen = store.finding_keys(conn, previous_id) if previous_id else set()
    store.record_findings(conn, scan_id, findings)

    # Nothing is "new" on the first audit; everything would be, which is noise.
    annotated = [
        (f, bool(seen) and (f.rule, f.device, f.title) not in seen) for f in findings
    ]

    if args.json:
        print(
            json.dumps(
                {
                    "scan_id": scan_id,
                    "subnet": args.subnet,
                    "summary": audit_rules.summarise(findings),
                    "gateway": gateway.control_url if gateway else None,
                    "mappings": [str(m) for m in gateway.mappings] if gateway else [],
                    "findings": [dict(f.__dict__, is_new=new) for f, new in annotated],
                },
                indent=2,
            )
        )
        return 0

    print(f"audit {scan_id}: {args.subnet} - {audit_rules.summarise(findings)}")
    if gateway is None and not args.no_upnp:
        print("no UPnP gateway answered - nothing here admits to forwarding ports")
    print()
    severity = ""
    for finding, is_new in annotated:
        if not args.verbose:
            print_headline(finding, is_new)
            continue
        if finding.severity != severity:
            severity = finding.severity
            print(severity.upper())
        print_lesson(finding, is_new)

    if not findings:
        print("nothing to report - no devices answered, or none had open ports")
    elif args.verbose:
        print("Every finding above quotes the observation it rests on. Run the verify")
        print("command yourself - do not take a scanner's word for anything.")
    else:
        print()
        print("-v adds the evidence each line rests on, why it matters, how to fix it,")
        print("and a command you can run yourself to confirm it.")

    serious = any(f.severity in ("critical", "high") for f in findings)
    return 1 if args.fail_on_finding and serious else 0


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
        label = device_label(row["hostname"], row["vendor"], row["services"])
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
    scan.add_argument(
        "--no-mdns", action="store_true", help="skip asking devices what they are"
    )
    scan.add_argument("--webhook", help="POST a JSON alert here when anything changed")
    scan.add_argument(
        "--fail-on-change",
        action="store_true",
        help="exit 1 if anything changed, for cron and CI",
    )
    scan.add_argument("--json", action="store_true")
    scan.set_defaults(func=cmd_scan)

    aud = sub.add_parser(
        "audit",
        help="what this network exposes, and why it matters",
        description=(
            "Read-only exposure audit. Never sends credentials, never writes to a "
            "scanned host, and only ever reads the router's port-forwarding table."
        ),
    )
    aud.add_argument("subnet", nargs="?", help="CIDR to audit, e.g. 192.168.1.0/24")
    aud.add_argument("--ports", type=int, nargs="*", default=list(DEFAULT_PORTS))
    aud.add_argument("--no-resolve", action="store_true", help="skip reverse DNS")
    aud.add_argument(
        "--no-mdns", action="store_true", help="skip asking devices what they are"
    )
    aud.add_argument(
        "--no-upnp", action="store_true", help="skip the router port-forward check"
    )
    aud.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="expand every finding into its evidence, why, fix and verify",
    )
    aud.add_argument(
        "--explain", metavar="RULE", help="print the lesson for a rule and exit"
    )
    aud.add_argument(
        "--fail-on-finding",
        action="store_true",
        help="exit 1 on any critical or high finding, for cron and CI",
    )
    aud.add_argument("--json", action="store_true")
    aud.set_defaults(func=cmd_audit)

    inv = sub.add_parser("inventory", help="every device ever seen")
    inv.add_argument("--json", action="store_true")
    inv.set_defaults(func=cmd_inventory)

    hist = sub.add_parser("history", help="diff the two most recent scans")
    hist.add_argument("--limit", type=int, default=2)
    hist.set_defaults(func=cmd_history)

    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ValueError as exc:
        # A subnet is user input and it is parsed deep in `discover`, so a typo
        # or a /8 arrives here rather than at the argparse layer. Say what is
        # wrong instead of printing a traceback at someone.
        print(exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
