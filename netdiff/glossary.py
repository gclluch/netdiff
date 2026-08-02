"""The vocabulary the rest of the output is written in.

`audit --explain RULE` explains a finding. This explains the words a finding is
made of, which is the other half of the same job: "the router answered an
unauthenticated control request" only lands on someone who already knows what
UPnP is, and the people most helped by this tool are exactly the ones who do not.

One rule keeps this from turning into an encyclopaedia of networking: **a term
earns an entry only if netdiff itself says it.** Every slug below appears in a
finding, a change line, a column heading or a limitation in the README. Anything
netdiff never prints is somebody else's glossary.

`long` is written for someone who has just read the word for the first time and
wants the sentence they were reading to make sense - not for someone studying
for an exam. Where a term is commonly misunderstood in a direction that matters
here, saying so is the most useful thing the entry can do.
"""

from __future__ import annotations

TERMS = {
    "arp": {
        "name": "ARP - Address Resolution Protocol",
        "short": "how a device finds the hardware address behind an IP",
        "long": (
            "Before one device on your network can send anything to another, it has "
            "to know that device's MAC address - the IP address alone is not enough "
            "to put a packet on the wire. ARP is the shout that asks: 'who has "
            "192.168.1.42?', broadcast to everyone on the segment, answered by "
            "whoever holds it. Every operating system caches the answers, which is "
            "why netdiff can find your devices without root: it provokes the "
            "questions, then reads your own machine's cache of the answers. ARP has "
            "no authentication at all - any device can answer for any address, which "
            "is a design decision from 1982 that everything since has had to live "
            "with."
        ),
        "see": ("mac-address", "subnet"),
    },
    "mac-address": {
        "name": "MAC address",
        "short": "the hardware address of a network interface",
        "long": (
            "Six bytes, written as `a4:83:e7:1c:2d:9f`, belonging to a network "
            "interface rather than to a network. An IP address is where a device is; "
            "a MAC address is which device it is. That is why netdiff tracks devices "
            "by MAC and not by IP - a phone that gets a new DHCP lease is the same "
            "phone, and reporting it as one device leaving and another arriving "
            "would bury the events that matter. The first three bytes are assigned "
            "to a manufacturer, which is how a vendor name can be shown without "
            "asking anyone."
        ),
        "see": ("arp", "randomised-mac", "vendor"),
    },
    "randomised-mac": {
        "name": "randomised MAC",
        "short": "a per-network MAC address, invented by the device to avoid tracking",
        "long": (
            "Phones and laptops now make up a fresh MAC address for each wifi "
            "network they join, and change it periodically after that. It stops "
            "shops and networks from recognising the same device across visits, "
            "which is a good thing that happens to break device tracking on your own "
            "network too. netdiff labels these `randomised` rather than pretending "
            "to know whose they are: the second byte of the address has a bit set "
            "that says 'this address was made up locally'. If you want a device to "
            "keep a stable identity at home, turn private addressing off for that "
            "one network on that device."
        ),
        "see": ("mac-address",),
    },
    "vendor": {
        "name": "vendor (OUI lookup)",
        "short": "the manufacturer a MAC address was assigned to",
        "long": (
            "The first three bytes of a MAC address are an Organisationally Unique "
            "Identifier, bought from the IEEE by whoever made the interface. Looking "
            "it up gives you a company, offline, with no lookup sent anywhere. What "
            "it does not give you is a device type: 'Espressif' covers a smart plug, "
            "a doorbell and someone's weekend project equally, and the company that "
            "made the wifi chip is often not the company whose logo is on the box."
        ),
        "see": ("mac-address",),
    },
    "subnet": {
        "name": "subnet",
        "short": "the range of addresses that share one local network",
        "long": (
            "The group of IP addresses that can talk to each other directly, without "
            "going through a router. `192.168.1.0/24` is a subnet holding 254 usable "
            "addresses. It matters here because ARP does not cross routers: netdiff "
            "sees one subnet, completely, and nothing at all beyond it. That is a "
            "property of how it works rather than a limitation to be fixed."
        ),
        "see": ("cidr", "arp"),
    },
    "cidr": {
        "name": "CIDR notation",
        "short": "the `/24` that says how much of an address is the network part",
        "long": (
            "`192.168.1.0/24` means the first 24 bits identify the network and the "
            "remaining 8 identify a device on it - so 256 addresses, of which 254 "
            "are usable. A smaller number means a bigger network: `/16` is 65,536 "
            "addresses. Home networks are almost always /24. netdiff works this out "
            "for you from your own interface rather than assuming, because 'almost "
            "always' is exactly the kind of nearly-true it refuses elsewhere."
        ),
        "see": ("subnet",),
    },
    "port": {
        "name": "port",
        "short": "a numbered door on a device, one per service",
        "long": (
            "One IP address, 65,535 possible TCP ports. A device runs a web server "
            "on port 80 and a file server on port 445 and both are reachable at the "
            "same address, because the port number says which one you meant. Common "
            "numbers are conventions, not rules - a web server can listen on 8443 "
            "and something else entirely can listen on 80, which is why netdiff will "
            "not name a protocol from a port number alone."
        ),
        "see": ("open-port", "banner", "port-forward"),
    },
    "open-port": {
        "name": "open port",
        "short": "a port where something accepted a connection - not a vulnerability",
        "long": (
            "'Open' means a TCP handshake completed: something is listening and it "
            "said hello back. That is what a working device looks like. A printer "
            "with no open ports is a broken printer. Tools that list every open port "
            "under a heading like 'vulnerabilities found' are counting furniture and "
            "calling it a fire, and they train you to ignore the report. A port "
            "becomes interesting when the protocol behind it has no encryption, when "
            "it is reachable from outside your network, or when the software behind "
            "it is known-broken."
        ),
        "see": ("port", "port-forward", "plaintext"),
    },
    "banner": {
        "name": "banner",
        "short": "what a service volunteers about itself when you connect",
        "long": (
            "Most plaintext protocols greet you before they authenticate you - "
            "connect to an FTP server and it announces its name and version before "
            "asking who you are. Reading that greeting is banner grabbing, and it "
            "sends nothing, stores nothing and needs no credentials. HTTP is the "
            "exception: it says nothing until asked, so netdiff sends `HEAD /`, the "
            "smallest possible request. A banner is what the service tells everyone "
            "who connects, which is the whole reason it is fair to read."
        ),
        "see": ("port", "open-port"),
    },
    "plaintext": {
        "name": "plaintext protocol",
        "short": "a protocol with no encryption, by design rather than by mistake",
        "long": (
            "Telnet, FTP, VNC, MQTT and RTSP carry everything readable: passwords, "
            "keystrokes, camera streams. Anyone who can see the traffic sees the "
            "contents - another device on the same wifi, a guest, anything on the "
            "network that has been compromised. This is a property of the protocol "
            "and not a setting on the device, which is why the fix is always to stop "
            "using it rather than to tune it. Their encrypted equivalents exist: SSH "
            "for Telnet, SFTP for FTP, MQTT over TLS on 8883."
        ),
        "see": ("telnet", "ssh", "tls"),
    },
    "nat": {
        "name": "NAT - Network Address Translation",
        "short": "why every device at home shares one public address",
        "long": (
            "Your router has one address on the internet and hands out private ones "
            "inside. When a device here opens a connection outward, the router "
            "rewrites it to come from itself, and remembers enough to send the reply "
            "back. The side effect is a firewall you did not configure: an "
            "unsolicited connection arriving from outside has no entry in that table "
            "and nowhere to go, so it is dropped. NAT was never designed as security "
            "- it is a consequence of running out of addresses - and a port forward "
            "is the hole punched straight through it."
        ),
        "see": ("port-forward", "upnp"),
    },
    "port-forward": {
        "name": "port forward",
        "short": "a rule sending a port on your public address to one device inside",
        "long": (
            "'Anything arriving from the internet on port 8080, send it to "
            "192.168.1.42 port 80.' It is the deliberate exception to NAT, and it "
            "means the device behind it is reachable by anyone who scans your public "
            "address - which the whole internet does continuously, as a background "
            "hum. Forwards get created by hand in a router's admin page, and also by "
            "devices asking for them over UPnP without telling you. A forward "
            "pointing at an address nothing currently holds is worse than useless: "
            "DHCP will eventually give that address to something else, which "
            "inherits the hole."
        ),
        "see": ("nat", "upnp", "dhcp"),
    },
    "upnp": {
        "name": "UPnP - Universal Plug and Play",
        "short": "how a device asks the router to open a port for it, unauthenticated",
        "long": (
            "A protocol that lets devices on the LAN discover the router and ask it "
            "to forward a port to them. There is no password and no prompt: the "
            "router does it because it was asked. Games consoles are the usual "
            "reason it is left on, and it is on by default on nearly every home "
            "router. The cost is that every other device has the same privilege - a "
            "smart bulb, a TV, a compromised laptop, a page open in a browser - and "
            "you are not told. netdiff only ever asks the router to list the "
            "forwards it already has; there is deliberately no code path in it that "
            "creates one."
        ),
        "see": ("port-forward", "nat", "ssdp"),
    },
    "ssdp": {
        "name": "SSDP - Simple Service Discovery Protocol",
        "short": "the multicast shout UPnP devices answer to announce themselves",
        "long": (
            "How a device finds the UPnP router on a network: send a multicast "
            "question, listen for replies naming a URL to fetch next. The replies "
            "are unauthenticated UDP, so anything on the network can forge one and "
            "choose the URL you fetch. That is why netdiff only follows a location "
            "whose host is a literal private address inside the subnet being "
            "audited, re-checks it at every hop, and refuses redirects outright."
        ),
        "see": ("upnp", "mdns"),
    },
    "mdns": {
        "name": "mDNS / Bonjour / DNS-SD",
        "short": "how devices announce what they are to everyone on the network",
        "long": (
            "DNS without a server: ask a question over multicast and whichever "
            "device owns the answer replies to the whole segment. It is how your "
            "phone finds a printer or a Chromecast, and it means most devices "
            "announce their model and their services unprompted, continuously, to "
            "anyone listening. netdiff asks the same question every phone on your "
            "network already asks, and prints the device's own word for itself - "
            "`Mac15,7` is a claim the device made, not an inference. A device that "
            "announces nothing is left blank, because not knowing is the normal case."
        ),
        "see": ("dns", "ssdp"),
    },
    "dns": {
        "name": "DNS - Domain Name System",
        "short": "turning a name into an address, and a place your traffic can be steered",
        "long": (
            "Every connection to a name starts with a question to a resolver: what "
            "address is `example.com`? Whoever answers that question decides where "
            "you go. On a network you do not control, the resolver is chosen for you "
            "by DHCP, which makes it the easiest place to watch what you look up, or "
            "to send you somewhere else. A resolver that fabricates answers for names "
            "that do not exist is doing both."
        ),
        "see": ("resolver", "dns-recursion", "captive-portal"),
    },
    "resolver": {
        "name": "resolver",
        "short": "the server your machine asks to turn names into addresses",
        "long": (
            "Usually your router, which passes the question on to your ISP; often a "
            "public one like 1.1.1.1 or 9.9.9.9 if you have set one. Which resolver "
            "you use is handed to you by the network over DHCP unless you override "
            "it, so on someone else's wifi you are using theirs by default. It sees "
            "every name you look up, in order, with timestamps."
        ),
        "see": ("dns", "dns-recursion"),
    },
    "dns-recursion": {
        "name": "recursion (open resolver)",
        "short": "a server that will look up names it has no authority over",
        "long": (
            "Answering 'what is the address of example.com' when you are not "
            "example.com means going and asking on the caller's behalf - that is "
            "recursion, and it is what a resolver is for. On a home network it is "
            "usually just the router doing its job, and not a problem while it is "
            "only reachable from inside. It becomes one when the same device is "
            "reachable from the internet: a small forged query produces a large "
            "reply sent to whoever the attacker named, which is the classic "
            "amplifier for denial-of-service attacks."
        ),
        "see": ("dns", "resolver", "port-forward"),
    },
    "captive-portal": {
        "name": "captive portal",
        "short": "a network that intercepts your traffic until you agree to something",
        "long": (
            "The hotel or cafe page demanding a room number or a tick-box before "
            "anything works. Mechanically it is interception: the network answers "
            "DNS with its own address and redirects your web requests to itself. "
            "That is unremarkable while it is only the portal, and worth knowing "
            "about because the same machinery does not always switch off after you "
            "have agreed. A network that still rewrites your DNS after you are "
            "logged in is doing something else."
        ),
        "see": ("dns", "tls", "client-isolation"),
    },
    "tls": {
        "name": "TLS (the S in HTTPS)",
        "short": "encryption plus identity - and the identity half is the part that fails",
        "long": (
            "TLS does two separate jobs: it encrypts the connection so nobody in "
            "between can read it, and it proves the other end is who it claims to "
            "be, using a certificate. The first job almost always works. The second "
            "is the one that fails in interesting ways, and every browser warning "
            "you have ever clicked through is about the second job, not the first. "
            "Encrypted-but-unverified still beats plaintext every time - the point "
            "is knowing which of the two you have."
        ),
        "see": ("certificate", "self-signed", "certificate-authority"),
    },
    "certificate": {
        "name": "certificate",
        "short": "a document saying 'this key belongs to this name', signed by someone",
        "long": (
            "Presented by a server at the start of a TLS connection. It carries the "
            "name it claims to be, the dates it is valid between, and a signature "
            "from whoever vouches for it. Your browser trusts the connection if it "
            "trusts the signer, the name matches what you typed, and today falls "
            "between the dates. All three can fail independently, and the warning "
            "rarely says which."
        ),
        "see": ("tls", "self-signed", "certificate-authority"),
    },
    "certificate-authority": {
        "name": "certificate authority (CA)",
        "short": "an organisation your machine already trusts to vouch for others",
        "long": (
            "Your operating system ships with a list of a few hundred of them. A "
            "certificate signed by one on that list is accepted silently; anything "
            "else produces a warning. Anyone who can add a CA to your machine can "
            "sign certificates for any name in the world and your browser will show "
            "a padlock - which is exactly how corporate traffic inspection works, "
            "with consent, and how it works without consent when someone else "
            "installs one."
        ),
        "see": ("certificate", "self-signed", "tls"),
    },
    "self-signed": {
        "name": "self-signed certificate",
        "short": "a certificate that vouches for itself - normal on a home network",
        "long": (
            "Subject and issuer are the same name: nothing external attests to it. "
            "This is the ordinary case for a router or a NAS, which has no way to "
            "obtain a certificate a browser would trust for a private address. The "
            "traffic is genuinely encrypted; what is missing is identity, so the "
            "padlock says the connection is private without saying who it is private "
            "with. It is why the device shows a warning, and it is not a warning "
            "worth chasing. Do not turn TLS off to make it go away."
        ),
        "see": ("certificate", "certificate-authority", "tls"),
    },
    "smb": {
        "name": "SMB / CIFS",
        "short": "Windows file sharing, on port 445 - and its 1996 version is still around",
        "long": (
            "The protocol behind shared folders and network drives. SMBv1, from "
            "1996, cannot verify who it is talking to, so a device on the same "
            "network can sit in the middle of a file transfer unnoticed. It is the "
            "protocol EternalBlue and WannaCry travelled over, and worms built on it "
            "are still circulating, because the devices still answering it are the "
            "ones nobody updates. Microsoft stopped installing it by default in "
            "2017. Every client made in the last decade speaks SMB2 or SMB3."
        ),
        "see": ("port", "plaintext"),
    },
    "ssh": {
        "name": "SSH - Secure Shell",
        "short": "an encrypted remote login, on port 22",
        "long": (
            "The right way to get a command line on another machine, and the "
            "replacement for Telnet. It negotiates its cryptography with each client "
            "and announces the algorithms it is willing to use before authentication "
            "happens at all - which is why those can be read without ever attempting "
            "a login. A server still offering RC4, CBC ciphers or SHA-1 key exchange "
            "is not broken, but it is a reliable sign of firmware nobody has updated "
            "in years, which is usually the more useful thing to learn from it."
        ),
        "see": ("telnet", "plaintext", "banner"),
    },
    "telnet": {
        "name": "Telnet",
        "short": "a remote login with no encryption whatsoever, on port 23",
        "long": (
            "Everything typed and everything shown crosses the network readable, "
            "including the password at the start. It has been superseded by SSH "
            "since the 1990s. Finding it open on a device today says less about the "
            "risk of that one port than about the age of the firmware behind it."
        ),
        "see": ("plaintext", "ssh"),
    },
    "ttl": {
        "name": "TTL - Time To Live",
        "short": "a hop counter whose starting value hints at the operating system",
        "long": (
            "Every packet carries a number that each router decrements, so a packet "
            "cannot loop forever. On one local segment there are no routers in the "
            "way, so what arrives is what the sender started with - and different "
            "operating systems start with different values: 64 for Linux, macOS and "
            "BSD, 128 for Windows, 255 for a lot of network gear. That narrows a "
            "device to a family and nothing more, and only when the value is an "
            "exact match. Real fingerprinting needs crafted packets and root."
        ),
        "see": ("open-port",),
    },
    "dhcp": {
        "name": "DHCP",
        "short": "how a device is handed an address, a gateway and a resolver on joining",
        "long": (
            "Join a network and it gives you an IP address on a lease, tells you "
            "which address is the router, and tells you which resolver to use. All "
            "three are choices the network makes for you, which is why joining a "
            "network you do not control is a decision and not a formality. Leases "
            "expire and addresses are handed out again, which is what makes a port "
            "forward pointed at an absent device dangerous rather than merely stale."
        ),
        "see": ("resolver", "port-forward", "mac-address"),
    },
    "client-isolation": {
        "name": "client isolation (AP isolation)",
        "short": "a wifi setting stopping devices on the same network from reaching each other",
        "long": (
            "With it on, every device can reach the internet and nothing else - not "
            "even the machine at the next table. Guest networks and decent public "
            "wifi turn it on; plenty of public wifi does not. It cuts both ways, "
            "which is the point: when it is off, other people's devices are "
            "reachable from yours, and yours is reachable from theirs."
        ),
        "see": ("subnet", "captive-portal", "vpn"),
    },
    "vpn": {
        "name": "VPN",
        "short": "a tunnel that moves your trust from the local network to somewhere else",
        "long": (
            "Everything you send is encrypted to a server elsewhere before it "
            "touches the local network, so a hostile network sees encrypted traffic "
            "to one address and nothing about its contents. It is the general answer "
            "to 'this wifi cannot be trusted', and the right answer to 'I need to "
            "reach something at home from outside' - a VPN back to your own network "
            "replaces a port forward, and does not leave a hole open for everyone "
            "else. What it does not do is protect you from the device you are typing "
            "on."
        ),
        "see": ("client-isolation", "port-forward", "captive-portal"),
    },
}
