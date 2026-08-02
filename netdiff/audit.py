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

import re
from dataclasses import dataclass
from datetime import date

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

# SSH algorithms that are deprecated rather than merely old, with the reason -
# the reason is the finding, since "weak" on its own is a word not an argument.
# A server offering these still works; it also still accepts them, which is what
# a client downgrade attack needs.
WEAK_SSH_ALGORITHMS = {
    "diffie-hellman-group1-sha1": "1024-bit key exchange, breakable by Logjam",
    "diffie-hellman-group14-sha1": "SHA-1 key exchange",
    "diffie-hellman-group-exchange-sha1": "SHA-1 key exchange",
    "ssh-rsa": "SHA-1 signatures, disabled by OpenSSH 8.8 in 2021",
    "ssh-dss": "1024-bit DSA, removed from OpenSSH in 2015",
    "arcfour": "RC4, biased keystream",
    "arcfour128": "RC4, biased keystream",
    "arcfour256": "RC4, biased keystream",
    "3des-cbc": "56-bit effective key",
    "aes128-cbc": "CBC in SSH is encrypt-and-MAC, which leaks plaintext",
    "aes192-cbc": "CBC in SSH is encrypt-and-MAC, which leaks plaintext",
    "aes256-cbc": "CBC in SSH is encrypt-and-MAC, which leaks plaintext",
    "blowfish-cbc": "64-bit block cipher in CBC mode",
    "cast128-cbc": "64-bit block cipher in CBC mode",
    "hmac-md5": "MD5 integrity",
    "hmac-md5-96": "MD5 integrity, truncated",
    "hmac-sha1-96": "truncated SHA-1 integrity",
    "none": "no encryption at all, if a client asks for it",
}

# `lighttpd/1.4.35`, `OpenSSH_7.4`, `Boa/0.94`. Two characters of name, then a
# separator, then a dotted number - narrow on purpose, because a looser pattern
# reads version numbers out of dates, ETags and session cookies.
_VERSION = re.compile(r"\b([A-Za-z][A-Za-z0-9.+-]{1,30})[/_](\d+(?:\.\d+)+[\w.-]*)")


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


def headline(finding) -> str:
    """The title, prefixed with the device when the title does not name it.

    Both renderers show findings as a flat list with no device column, which was
    readable while a quiet network produced one or two of them. It stopped being
    readable the moment a report could say "port 80 identifies itself as
    lighttpd 1.4.59" three times about three different devices.
    """
    if finding.device in ("", "network") or finding.device in finding.title:
        return finding.title
    return f"{finding.device}  {finding.title}"


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
    "smb-v1": {
        "severity": "high",
        "title": "SMBv1 file sharing is enabled on port {port}",
        "why": (
            "This device agreed to speak the 1996 version of the Windows file "
            "sharing protocol. SMBv1 cannot verify who it is talking to, so a "
            "device on the same network can sit in the middle of a file transfer "
            "unnoticed. It is also the protocol EternalBlue and WannaCry travelled "
            "over, and worms built on it are still circulating years later because "
            "the devices still answering are the ones nobody updates. Microsoft "
            "stopped installing it by default in 2017."
        ),
        "fix": (
            "On Windows: Control Panel, Turn Windows features on or off, untick "
            "'SMB 1.0/CIFS File Sharing Support'. On a NAS, look for a minimum SMB "
            "protocol setting and set it to SMB2 or SMB3 - every client made in the "
            "last decade speaks those. If a device only offers SMBv1 and cannot be "
            "updated, it should not be on the same network as anything you care about."
        ),
        "verify": (
            "nmap --script smb-protocols -p445 {device}\n"
            "Anything listing a dialect of 'NT LM 0.12' is SMBv1."
        ),
    },
    "ssh-weak-algorithms": {
        "severity": "medium",
        "title": "SSH on port {port} still offers {count} deprecated algorithm(s)",
        "why": (
            "SSH negotiates its cryptography with each client, and this server is "
            "still willing to accept: {detail}. A current client will pick something "
            "stronger, so this is not a break - it is a downgrade waiting for an old "
            "client or someone able to interfere with the negotiation. It is also a "
            "reliable sign of firmware that has not been updated in years, which is "
            "usually the more useful thing to learn from it."
        ),
        "fix": (
            "Update the device's firmware first - modern OpenSSH drops these by "
            "default and this list disappears on its own. Where that is not "
            "possible, set KexAlgorithms, Ciphers and MACs explicitly in sshd_config "
            "to the current defaults."
        ),
        "verify": (
            "ssh -vv {device} 2>&1 | grep 'peer server KEXINIT'\n"
            "Or: nmap --script ssh2-enum-algos -p {port} {device}"
        ),
    },
    "tls-cert-expired": {
        "severity": "medium",
        "title": "the certificate on port {port} expired on {not_after}",
        "why": (
            "Encryption still works, so traffic is not readable - but every browser "
            "and app reaching this device now shows a warning, and the only way to "
            "keep using it is to click through that warning. Once clicking through "
            "is routine, a genuine interception looks exactly like the thing you "
            "already dismiss every day. That is the real cost, and it is a habit "
            "rather than a vulnerability."
        ),
        "fix": (
            "Reissue the certificate in the device's admin page. Many devices "
            "regenerate a self-signed one on request, or after a factory reset. If "
            "the device cannot, its firmware is old enough that the certificate is "
            "the smaller problem."
        ),
        "verify": (
            "openssl s_client -connect {device}:{port} </dev/null 2>/dev/null"
            " | openssl x509 -noout -dates"
        ),
    },
    "tls-cert-untrusted": {
        "severity": "info",
        "title": "port {port} uses a certificate that vouches for itself",
        "why": (
            "Explicitly not a problem on its own, and the normal case for home "
            "equipment - a router or NAS has no way to obtain a certificate a "
            "browser would trust for a private address. The traffic is genuinely "
            "encrypted. What is missing is identity: nothing here proves the device "
            "answering is the one you meant, so the padlock says the connection is "
            "private without saying who it is private with. Worth knowing because it "
            "is why this device shows a warning, and why that warning is not one to "
            "chase."
        ),
        "fix": (
            "Nothing, for most devices. If you want the warning gone properly, "
            "run a local certificate authority or use a tool that issues real "
            "certificates for internal names. Do not disable TLS to avoid the "
            "warning - encrypted-but-unverified beats plaintext every time."
        ),
        "verify": (
            "openssl s_client -connect {device}:{port} </dev/null 2>/dev/null"
            " | openssl x509 -noout -subject -issuer\n"
            "The same name on both lines means it signed its own certificate."
        ),
    },
    "dns-recursion-open": {
        "severity": "info",
        "title": "{device} resolves internet names for anything that asks it",
        "why": (
            "This device answered a query for a name it does not own, which makes it "
            "a recursive resolver. On a home network that is usually just the router "
            "doing its job, and it is not a problem while it is only reachable "
            "from inside. It becomes one if the same device is reachable from the "
            "internet: an open resolver is the classic amplifier for denial of "
            "service attacks, because a small forged query produces a large reply "
            "sent to whoever the attacker named. Check whether port 53 appears in "
            "any exposure finding above."
        ),
        "fix": (
            "Nothing, if this is your router and nothing forwards port 53 inward. "
            "If it is not your router, ask why that device is running a resolver at "
            "all. Where the option exists, restrict recursion to the local subnet."
        ),
        "verify": (
            "dig @{device} example.com +short\n"
            "An answer means it resolved a name it is not authoritative for."
        ),
    },
    "service-version": {
        "severity": "info",
        "title": "port {port} identifies itself as {product} {version}",
        "why": (
            "Not a finding, a fact: this is the software the service names when "
            "asked, quoted rather than guessed. netdiff does not match it against a "
            "vulnerability database - home equipment rarely announces a precise "
            "enough version for that to be honest, and a list of maybe-CVEs reads "
            "as alarming while meaning nothing. What this is good for is the "
            "question a database cannot answer: is this version still supported? A "
            "web server from 2014 on a device with no firmware updates left is worth "
            "more of your attention than any severity score."
        ),
        "fix": (
            "Search for '{product} {version} release date' and for the vendor's "
            "support page for this device. If the version predates the last "
            "firmware update you can install, install it. If the vendor has stopped "
            "shipping updates, that is the finding."
        ),
        "verify": "curl -sI http://{device}:{port}/ | grep -i server",
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
        label = device.hostname or device.vendor or device.services or device.ip
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


def _version_line(banner: str) -> str:
    """The line of a banner that names software, if one does.

    An HTTP `Server:` header and an SSH version string are both declarations of
    identity. Anything else falls back to the first line, which is where every
    protocol that greets you puts its name - except an HTTP status line, where
    `HTTP/1.0` is the version of the protocol and says nothing about the
    software. Reporting that as a product would be the exact failure this tool
    exists to avoid: a confident sentence about nothing.
    """
    for line in banner.splitlines():
        if line.lower().startswith("server:") or line.startswith("SSH-"):
            return line.strip()
    lines = [
        line for line in banner.strip().splitlines() if not line.startswith("HTTP/")
    ]
    return lines[0].strip() if lines else ""


def rule_service_version(ip: str, port: int, banner: str):
    """The software a service names, quoted rather than interpreted."""
    line = _version_line(banner)
    match = _VERSION.search(line)
    if not match:
        return None
    return finding(
        "service-version",
        ip,
        line,
        port=port,
        product=match.group(1),
        version=match.group(2),
    )


BANNER_RULES = (
    rule_plaintext_protocol,
    rule_http_auth_plaintext,
    rule_ssh_v1,
    rule_service_version,
)


def rule_smbv1(ip: str, port: int, dialect: str):
    """The server accepted an offer of the 1996 dialect and nothing else."""
    if not dialect:
        return None
    return finding(
        "smb-v1",
        ip,
        f"negotiated dialect {dialect!r} when offered no other option",
        port=port,
    )


def rule_ssh_weak_algorithms(ip: str, port: int, algorithms):
    """Deprecated algorithms in what the server offered to negotiate with."""
    weak = [name for name in algorithms if name in WEAK_SSH_ALGORITHMS]
    if not weak:
        return None
    return finding(
        "ssh-weak-algorithms",
        ip,
        "offered: " + ", ".join(weak),
        port=port,
        count=len(weak),
        detail="; ".join(f"{name} ({WEAK_SSH_ALGORITHMS[name]})" for name in weak),
    )


def rule_tls_cert_expired(ip: str, port: int, cert, today: str):
    """Past its notAfter, by its own dates."""
    if cert is None or not cert.not_after or cert.not_after >= today:
        return None
    return finding(
        "tls-cert-expired",
        ip,
        f"certificate valid {cert.not_before} to {cert.not_after}, today is {today}",
        port=port,
        not_after=cert.not_after,
    )


def rule_tls_cert_untrusted(ip: str, port: int, cert):
    """Issuer and subject are the same name, so nothing external vouches for it."""
    if cert is None or not cert.self_signed:
        return None
    return finding(
        "tls-cert-untrusted",
        ip,
        f"subject and issuer are both {cert.subject!r}; "
        f"valid {cert.not_before} to {cert.not_after}",
        port=port,
    )


def rule_dns_recursion(ip: str, evidence: str):
    """It resolved a name it has no authority over."""
    if not evidence:
        return None
    return finding("dns-recursion-open", ip, evidence)


def audit(
    devices, gateway=None, banners=None, probes=None, today=None
) -> list[Finding]:
    """Apply every rule.

    `banners` maps (ip, port) -> whatever the service said. `probes` is the dict
    `probe.collect()` returns: certificates, SMB dialects and SSH algorithms per
    (ip, port), and DNS recursion evidence per ip. Both are plain data gathered
    by the caller, which is what keeps this module free of sockets.
    """
    banners = banners or {}
    probes = probes or {}
    today = today or date.today().isoformat()
    findings = []

    control = rule_upnp_control_open(gateway)
    if control:
        findings.append(control)
    if gateway is not None:
        for mapping in gateway.mappings:
            if mapping.enabled:
                findings.append(rule_mapping(mapping, devices))

    certs = probes.get("certs", {})
    smb = probes.get("smb", {})
    ssh = probes.get("ssh", {})
    resolvers = probes.get("dns", {})

    open_ports = 0
    for device in devices:
        for port in device.ports:
            open_ports += 1
            pair = (device.ip, port)
            banner = banners.get(pair, "")
            hits = [rule(device.ip, port, banner) for rule in BANNER_RULES]
            hits.append(rule_smbv1(device.ip, port, smb.get(pair, "")))
            hits.append(rule_ssh_weak_algorithms(device.ip, port, ssh.get(pair, ())))
            hits.append(rule_tls_cert_expired(device.ip, port, certs.get(pair), today))
            hits.append(rule_tls_cert_untrusted(device.ip, port, certs.get(pair)))
            findings.extend(hit for hit in hits if hit)
        resolver = rule_dns_recursion(device.ip, resolvers.get(device.ip, ""))
        if resolver:
            findings.append(resolver)

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
