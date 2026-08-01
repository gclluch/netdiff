"""Turn observations into findings, and findings into lessons.

Every rule here is a pure function: evidence in, a Finding or None out. Nothing
in this module opens a socket. That is deliberate and it is the whole design -
security logic fused to network I/O cannot be tested without a live host, so it
never gets tested, so it quietly rots into checks that raise on their first line
and report an open port as a break-in.

Two consequences worth stating out loud:

`Finding.evidence` has no default. You cannot construct a finding without the
observation that proves it, so "I saw a thing and it felt bad" is not
expressible. If a rule cannot quote its receipt, it is not a rule.

Findings carry `why`, `fix` and `verify` because a scanner that only produces a
severity-coloured list teaches nothing. `verify` is a command you run yourself:
the point is that you should not have to take this tool's word for anything.

The thesis, which the severity ladder encodes rather than asserts:
an open port is not a vulnerability, a plaintext protocol is a confidentiality
gap, and internet-reachable is attack surface.
"""

from __future__ import annotations

from dataclasses import dataclass

from .scan import HTTP_PORTS

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}

# Protocols with no confidentiality by design. Naming one is a statement of
# fact about the protocol, not a guess about the device running it.
#
# The third element is whether the service greets you unprompted. Where it does,
# we refuse to name the protocol until we have heard it - a port number is a
# convention, not evidence, and "port 23 is open" does not prove telnet is
# behind it. Where it does not greet, the evidence says so in as many words.
PLAINTEXT_PROTOCOLS = {
    21: ("FTP", "usernames and passwords", True),
    23: ("Telnet", "usernames, passwords and every keystroke of the session", True),
    554: ("RTSP", "the camera stream and its credentials", False),
    1883: ("MQTT", "every message published, and any password used to connect", False),
    5900: ("VNC", "the screen contents, and often the password too", True),
}


@dataclass(frozen=True)
class Finding:
    """One thing that is true about the network, with its receipt.

    `evidence` is positional and has no default on purpose - see the module
    docstring.
    """

    rule: str
    severity: str
    device: str
    title: str
    evidence: str
    why: str
    fix: str
    verify: str


RULES = {
    "internet-exposed-service": {
        "severity": "critical",
        "title": "{label} is reachable from the internet on port {external_port}",
        "why": (
            "Your router forwards this port from the public internet straight to this "
            "device, so NAT is not protecting it. Anyone who scans your home IP address "
            "reaches this service directly - and the whole internet is scanned "
            "continuously. The service is exposed whether or not it was built to be."
        ),
        "fix": (
            "If you did not set this up deliberately, remove the forward in your "
            "router's admin page under Port Forwarding, then turn UPnP off so it "
            "cannot come back. If you do need remote access, put it behind a VPN or "
            "Tailscale instead of forwarding a port."
        ),
        "verify": (
            "curl -s https://api.ipify.org            # your public address\n"
            "nc -vz THAT_ADDRESS {external_port}      # from a phone on cellular, "
            "NOT on your wifi\n"
            "Testing from inside your own network proves nothing - most routers "
            "answer their own public address differently from the outside world."
        ),
    },
    "internet-exposed-port": {
        "severity": "high",
        "title": "port {external_port} is forwarded from the internet to {internal}",
        "why": (
            "Your router forwards this port in from the public internet. The target "
            "did not answer our scan, so we cannot say what is behind it - but the "
            "hole in the firewall is real and it is open right now."
        ),
        "fix": (
            "Find this entry in your router's Port Forwarding or UPnP table and "
            "delete it if you do not recognise it."
        ),
        "verify": (
            "curl -s https://api.ipify.org            # your public address\n"
            "nc -vz THAT_ADDRESS {external_port}      # from outside your network"
        ),
    },
    "upnp-mapping-dangling": {
        "severity": "high",
        "title": "port {external_port} is forwarded to {internal}, which is not on the network",
        "why": (
            "The router is holding a door open to an address where nothing currently "
            "lives. DHCP hands addresses out again, so the next device to receive this "
            "one inherits an internet-facing port forward that nobody chose for it - a "
            "guest's laptop, a new smart plug. This is how a forward set up for a games "
            "console in 2021 ends up pointed at a camera."
        ),
        "fix": (
            "Delete the entry in your router's Port Forwarding table. If you need it "
            "for a device that is usually online, give that device a DHCP reservation "
            "so its address stops moving."
        ),
        "verify": (
            "ping -c1 {client}\narp -an | grep {client}\n"
            "Nothing answers, and the ARP table has no entry for it."
        ),
    },
    "upnp-control-open": {
        "severity": "medium",
        "title": "the router lets any device on the LAN open its firewall",
        "why": (
            "We asked the router for its port-forwarding table and it answered - no "
            "password, no prompt. The same interface accepts AddPortMapping, so any "
            "device here can open a path from the internet to itself and you will not "
            "be told. That includes anything that gets compromised: a smart bulb, a TV, "
            "a page open in a browser. This is the mechanism behind most of the other "
            "findings in this report, and it is on by default on nearly every home "
            "router."
        ),
        "fix": (
            "Turn UPnP off in your router's admin page unless something genuinely "
            "needs it, and add the one or two forwards you actually want by hand. "
            "Games consoles are the usual reason to leave it on; weigh that against "
            "every other device on the network having the same privilege."
        ),
        "verify": (
            "The router answered this with no credentials. Paste it and watch:\n"
            "curl -s -H 'SOAPAction: \"{service_type}#GetGenericPortMappingEntry\"' "
            "-H 'Content-Type: text/xml' --data "
            '\'<?xml version="1.0"?><s:Envelope '
            'xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            '<u:GetGenericPortMappingEntry xmlns:u="{service_type}">'
            "<NewPortMappingIndex>0</NewPortMappingIndex>"
            "</u:GetGenericPortMappingEntry></s:Body></s:Envelope>' {control_url}\n"
            "Nothing in that request identifies you as the owner of the network."
        ),
    },
    "plaintext-protocol": {
        "severity": "high",
        "title": "{protocol} on port {port} sends {exposed} in cleartext",
        "why": (
            "{protocol} has no encryption. Anything it carries - {exposed} - travels "
            "the network readable by anyone who can see the traffic: another device on "
            "the same wifi, a guest, anything already compromised on the network. This "
            "is a property of the protocol, not a misconfiguration of this device, "
            "which is why the fix is to stop using it rather than to tune it."
        ),
        "fix": (
            "Prefer the encrypted equivalent - SSH instead of Telnet, SFTP or FTPS "
            "instead of FTP, MQTT over TLS on 8883 instead of 1883. If the device is "
            "too old to offer one, keep it on a separate VLAN or guest network and "
            "never reuse its password anywhere else."
        ),
        "verify": (
            "nc {device} {port}\n"
            "The service greets you before it authenticates you, and everything you "
            "type after that crosses the network readable."
        ),
    },
    "http-auth-plaintext": {
        "severity": "high",
        "title": "port {port} asks for a password over unencrypted HTTP",
        "why": (
            "This device answered with an authentication challenge on plain HTTP, so "
            "the password protecting it is sent unencrypted. Anyone able to observe "
            "the traffic captures it verbatim. A login prompt on HTTP protects against "
            "a curious housemate and nothing else."
        ),
        "fix": (
            "Use the device's HTTPS interface if it has one. If it does not, treat "
            "that password as public: never reuse it, and do not let this device's "
            "admin page be reachable from outside the LAN."
        ),
        "verify": "curl -sI http://{device}:{port}/ | grep -i www-authenticate",
    },
    "ssh-v1": {
        "severity": "high",
        "title": "SSH protocol 1 offered on port {port}",
        "why": (
            "SSH version 1 has structural cryptographic flaws and has been deprecated "
            "since 2006. Its integrity checking can be defeated, which means an "
            "attacker positioned on the network can inject commands into a session "
            "that looks encrypted and normal to both ends."
        ),
        "fix": (
            "Set 'Protocol 2' in the device's sshd_config, or update its firmware. A "
            "device still offering SSH-1 in the present day is usually unmaintained, "
            "which is its own finding."
        ),
        "verify": (
            "nc {device} {port}\nThe first line it prints is the version it speaks."
        ),
    },
    "open-ports-noted": {
        "severity": "info",
        "title": "{count} open port(s) observed, and not reported as problems",
        "why": (
            "An open port means a service accepted a TCP handshake. That is not a "
            "vulnerability - it is what a working device looks like. Tools that list "
            "every open port under a heading like 'vulnerabilities found' are counting "
            "furniture and calling it a fire. A port becomes interesting when the "
            "protocol behind it is unencrypted, when it is reachable from outside the "
            "network, or when the software behind it is known-broken. Those are the "
            "things reported above."
        ),
        "fix": (
            "Nothing to fix. Worth skimming the device list anyway: a port you cannot "
            "account for on a device you cannot identify is worth ten minutes."
        ),
        "verify": "netdiff inventory - every device and port this tool has ever seen here.",
    },
}


def finding(rule: str, device: str, evidence: str, **context) -> Finding:
    """Build a Finding from the rule's teaching text.

    One source for both the report and `--explain`, so the lesson cannot drift
    away from the thing that fired.
    """
    spec = RULES[rule]
    fields = dict(context, device=device)
    return Finding(
        rule=rule,
        severity=spec["severity"],
        device=device,
        title=spec["title"].format(**fields),
        evidence=evidence,
        why=spec["why"].format(**fields),
        fix=spec["fix"].format(**fields),
        verify=spec["verify"].format(**fields),
    )


def rule_upnp_control_open(gateway):
    """The router answered an unauthenticated control request."""
    if gateway is None:
        return None
    return finding(
        "upnp-control-open",
        "network",
        f"{gateway.control_url} answered GetGenericPortMappingEntry with no "
        f"credentials ({len(gateway.mappings)} mapping(s) returned)",
        control_url=gateway.control_url,
        service_type=gateway.service_type,
    )


def rule_mapping(mapping, devices):
    """Classify one port forward against what is actually on the network."""
    by_ip = {d.ip: d for d in devices}
    device = by_ip.get(mapping.internal_client)
    internal = f"{mapping.internal_client}:{mapping.internal_port}"

    if device is None:
        return finding(
            "upnp-mapping-dangling",
            mapping.internal_client,
            str(mapping),
            external_port=mapping.external_port,
            internal=internal,
            client=mapping.internal_client,
        )

    if mapping.internal_port in device.ports:
        label = device.hostname or device.vendor or device.ip
        return finding(
            "internet-exposed-service",
            device.ip,
            f"{mapping} - and {device.ip}:{mapping.internal_port} answered our scan",
            external_port=mapping.external_port,
            label=f"{label} ({device.ip}:{mapping.internal_port})",
        )

    return finding(
        "internet-exposed-port",
        device.ip,
        str(mapping),
        external_port=mapping.external_port,
        internal=internal,
    )


def rule_plaintext_protocol(ip: str, port: int, banner: str):
    """A protocol with no encryption, confirmed by what the service said.

    Silence from a service that should have greeted us is not evidence of that
    service, so we say nothing rather than name a protocol we did not hear.
    """
    if port not in PLAINTEXT_PROTOCOLS:
        return None
    protocol, exposed, greets = PLAINTEXT_PROTOCOLS[port]
    if greets and not banner.strip():
        return None
    evidence = banner.strip() or (
        f"port {port} accepted a connection; {protocol} is the service assigned "
        f"to that port and does not announce itself"
    )
    return finding(
        "plaintext-protocol",
        ip,
        evidence,
        port=port,
        protocol=protocol,
        exposed=exposed,
    )


def rule_http_auth_plaintext(ip: str, port: int, banner: str):
    """An HTTP auth challenge on a port that is not TLS."""
    if port not in HTTP_PORTS:
        return None
    for line in banner.splitlines():
        if line.lower().startswith("www-authenticate:"):
            return finding("http-auth-plaintext", ip, line.strip(), port=port)
    return None


def rule_ssh_v1(ip: str, port: int, banner: str):
    """SSH-1 announces itself in the first line it sends."""
    if not banner.startswith("SSH-1."):
        return None
    return finding("ssh-v1", ip, banner.splitlines()[0].strip(), port=port)


BANNER_RULES = (rule_plaintext_protocol, rule_http_auth_plaintext, rule_ssh_v1)


def audit(devices, gateway=None, banners=None) -> list[Finding]:
    """Apply every rule. `banners` maps (ip, port) -> whatever the service said."""
    banners = banners or {}
    findings = []

    control = rule_upnp_control_open(gateway)
    if control:
        findings.append(control)
    if gateway is not None:
        for mapping in gateway.mappings:
            if mapping.enabled:
                findings.append(rule_mapping(mapping, devices))

    open_ports = 0
    for device in devices:
        for port in device.ports:
            open_ports += 1
            banner = banners.get((device.ip, port), "")
            for rule in BANNER_RULES:
                hit = rule(device.ip, port, banner)
                if hit:
                    findings.append(hit)

    if open_ports:
        findings.append(
            finding(
                "open-ports-noted",
                "network",
                f"{open_ports} open port(s) across {len(devices)} device(s)",
                count=open_ports,
            )
        )

    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.device))


def summarise(findings) -> str:
    """'1 critical, 2 high' - info is counted but never leads."""
    counts = {}
    for item in findings:
        counts[item.severity] = counts.get(item.severity, 0) + 1
    parts = [f"{counts[name]} {name}" for name in SEVERITY_ORDER if counts.get(name)]
    return ", ".join(parts) if parts else "nothing to report"
