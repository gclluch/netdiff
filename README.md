# netdiff

Track what is on your network, what it exposes to the internet, and when that changed. **Pure standard library, no root.**

`nmap` and Fing answer "what is on my network *right now*". Neither remembers. netdiff records every scan, diffs it against the last one, and tells you what actually changed - a device that appeared at 3am, a printer that quietly opened port 8080, a laptop that moved to a new DHCP lease.

Then `netdiff audit` asks the question those tools do not: **which of these is reachable from outside your house, and why does that matter?**

```console
$ netdiff scan 192.168.1.0/24
scan 7: 12 device(s) on 192.168.1.0/24
  192.168.1.1     00:1d:c9:0a:1b:2c  router.local  ports 53,80,443
  192.168.1.23    b8:27:eb:aa:bb:cc  Raspberry Pi  (SSH, Web interface)  ports 22
  192.168.1.64    54:60:09:11:22:33  Google  (Chromecast)
  192.168.1.71    d8:3a:dd:aa:bb:cc  Mac15,7, AirPlay
  ...

changes since last scan: 1 appeared, 1 port-opened
  [appeared] randomised 192.168.1.102 b6:41:9f:00:11:22
  [port-opened] Raspberry Pi 192.168.1.23 b8:27:eb:aa:bb:cc (8080)
```

## The audit: what your network exposes

Most people assume NAT is a firewall - nothing outside can reach in unless they set it up. UPnP quietly breaks that. Any device on your LAN can ask the router to open a port from the internet straight to itself, with no prompt and no record anyone ever reads. The holes outlive the software that opened them.

`netdiff audit` asks the router to list them, cross-references each forward against the devices actually present, and explains what it found.

```console
$ netdiff audit 192.168.1.0/24
audit 12: 192.168.1.0/24 - 1 critical, 2 high, 1 medium, 1 info

    critical  nas.local (192.168.1.23:8080) is reachable from the internet on port 8080   [NEW]
    high      Telnet on port 23 sends usernames, passwords and every keystroke of the
              session in cleartext
    high      port 8080 asks for a password over unencrypted HTTP
    medium    the router lets any device on the LAN open its firewall
    info      7 open port(s) observed, and not reported as problems

-v adds the evidence each line rests on, why it matters, how to fix it,
and a command you can run yourself to confirm it.
```

A report nobody finishes reading teaches nothing, so depth is something you ask for. `-v` expands every line above into the finding it stands for:

```console
$ netdiff audit 192.168.1.0/24 -v
audit 12: 192.168.1.0/24 - 1 critical, 2 high, 1 medium, 1 info

CRITICAL
  nas.local (192.168.1.23:8080) is reachable from the internet on port 8080   [NEW]
    evidence  *:8080/tcp -> 192.168.1.23:8080 (transmission) - and 192.168.1.23:8080 answered our scan
    why       Your router forwards this port from the public internet straight to this
              device, so NAT is not protecting it. Anyone who scans your home IP address
              reaches this service directly - and the whole internet is scanned
              continuously. The service is exposed whether or not it was built to be.
    fix       If you did not set this up deliberately, remove the forward in your
              router's admin page under Port Forwarding, then turn UPnP off so it
              cannot come back. If you do need remote access, put it behind a VPN or
              Tailscale instead of forwarding a port.
    verify    curl -s https://api.ipify.org            # your public address
              nc -vz THAT_ADDRESS 8080                 # from a phone on cellular, NOT on your wifi
              Testing from inside your own network proves nothing - most routers
              answer their own public address differently from the outside world.
```

Every finding carries the observation that produced it, what an attacker gains, how to fix it, and **a command you run yourself to confirm it**. You should not have to take a scanner's word for anything.

```bash
netdiff audit 192.168.1.0/24                  # a headline per finding
netdiff audit 192.168.1.0/24 -v               # each one expanded into its lesson
netdiff audit 192.168.1.0/24 --json           # every field, machine-readable
netdiff audit 192.168.1.0/24 --no-upnp        # skip the router check
netdiff audit --explain upnp-control-open     # read a lesson without scanning
netdiff audit 192.168.1.0/24 --fail-on-finding   # exit 1 on critical/high, for cron
```

Findings are recorded alongside scans, so a repeat audit marks what is `[NEW]` since the last one. A port forward that appeared on Tuesday is the thing worth knowing.

### What it reports, and what it refuses to

| Rule | Severity | Fires when |
| --- | --- | --- |
| `internet-exposed-service` | critical | A port forward points at a device, and that device answered on that port |
| `internet-exposed-port` | high | A port forward points inward, but we could not confirm what is behind it |
| `upnp-mapping-dangling` | high | A forward points at an address nothing currently holds - DHCP will hand it to something else |
| `plaintext-protocol` | high | Telnet, FTP, RTSP, MQTT or VNC - protocols with no encryption by design, confirmed by what the service said |
| `http-auth-plaintext` | high | A device sent an auth challenge over cleartext HTTP |
| `ssh-v1` | high | SSH protocol 1, deprecated since 2006 |
| `upnp-control-open` | medium | The router answered an unauthenticated control request - so would it for anything else on the LAN |
| `open-ports-noted` | info | Explicitly **not** a problem. See below. |

**And a vendor is not a device type.** "Espressif" covers a smart plug, a doorbell and someone's weekend project equally, so a MAC lookup alone leaves the most useful column nearly empty. Rather than guess a device type from its open ports - which is how the tool netdiff replaced arrived at "Managed Web Server" for a printer - netdiff asks the network the question every phone on it asks continuously, and reads the answer. Chromecasts, printers, Sonos, HomeKit gear and Apple devices all announce their services over multicast DNS, unprompted, to anyone on the segment. `Mac15,7` in the output is the device's own word for itself, not an inference. A device that announces nothing is left blank, because not knowing is the normal case.

**A port number is not evidence of a protocol either.** Port 23 being open does not prove telnet is behind it. So for services that greet you unprompted - FTP, Telnet, VNC - netdiff will not name the protocol until it has heard the greeting. RTSP and MQTT say nothing until spoken to, so there the evidence line states plainly that the identification is by port assignment, and the `verify` command lets you settle it.

**An open port is not a vulnerability.** It is what a working device looks like. Tools that list every open port under a heading like "vulnerabilities found" are counting furniture and calling it a fire, and they train you to ignore the report. netdiff counts open ports and says out loud that they are not findings. A port becomes interesting when the protocol behind it is unencrypted, when it is reachable from outside the network, or when the software behind it is known-broken - and those are the rules above.

There is no CVE matching here. Home-LAN banners rarely carry a precise enough version to map to a CVE honestly, and guessing produces a scary list that means nothing.

### Read-only, and it means it

The audit **never sends credentials, never writes to a scanned host, and never changes router configuration.** It reads banners that services volunteer to anyone who connects, and it calls exactly one UPnP method - `GetGenericPortMappingEntry`. There is deliberately no `AddPortMapping` code path in the source.

This rules out checks that would otherwise be easy. Anonymous-FTP detection needs a login attempt, so it is not here. A failed SSH auth against every host on every scan - a common trick for grabbing SSH banners - lands you in the target's auth log and in fail2ban, so that is not here either.

One trust boundary is worth naming: SSDP replies are unauthenticated UDP, so anything on your network can forge one and choose the URL netdiff fetches next. netdiff only follows a `LOCATION` whose host is a literal private address inside the subnet being audited, and caps every response it reads.

That check holds for every hop, not just the first. A device description can name an absolute `controlURL` that discards the URL we vetted, and any response can redirect, so the control URL is re-checked against the same subnet and redirects are refused outright. The same reasoning covers what gets *printed*: a `verify` line is a command you are told to run, so every value from the network that reaches one - the control URL, a forward's internal client - is validated where it enters, not escaped where it is rendered.

## Why no dependencies, and why no root

Most LAN scanners either shell out to `nmap` or send raw ARP frames with `scapy`, and raw frames need root. netdiff does neither.

Your OS already maintains an ARP table. Sending *any* packet to an address on the local segment forces the kernel to resolve its MAC first. So netdiff sends a throwaway UDP datagram to every address in the subnet, waits a moment, and reads the ARP cache back with `arp -an` (or `ip neigh`).

The upside beyond dependencies: this finds devices that **drop ICMP entirely** and would be invisible to a ping sweep. Plenty of IoT gear does exactly that.

## Install

```bash
git clone https://github.com/gclluch/netdiff && cd netdiff
pip install -e .          # or just run: python -m netdiff
```

Python 3.9+. Nothing else - `pip show netdiff` lists no dependencies, and CI asserts it.

## Use

```bash
netdiff scan 192.168.1.0/24              # scan, record, report changes
netdiff scan 192.168.1.0/24 --no-ports   # discovery only, no TCP connections
netdiff scan 192.168.1.0/24 --no-mdns    # skip asking devices what they are
netdiff audit 192.168.1.0/24             # what this network exposes, and why it matters
netdiff inventory                        # every device ever seen, first and last sighting
netdiff history                          # diff the two most recent scans

# alerting: POST a JSON payload anywhere when something changed
netdiff scan 192.168.1.0/24 --webhook https://ntfy.sh/my-topic

# cron-friendly: exit 1 when anything changed
netdiff scan 192.168.1.0/24 --fail-on-change
```

Hourly, via cron:

```cron
0 * * * * /usr/local/bin/netdiff scan 192.168.1.0/24 --webhook https://ntfy.sh/my-topic
```

History lives in `~/.netdiff/history.db` (override with `--db`). It is a plain SQLite file - query it directly if you want something the CLI does not print.

## What counts as a change

| Kind | Meaning |
| --- | --- |
| `appeared` | A MAC not seen in the previous scan |
| `vanished` | A previously present MAC is gone |
| `ip-changed` | Same device, new address - usually a DHCP lease |
| `port-opened` | A TCP port that was closed last scan now accepts connections |
| `port-closed` | The reverse |
| `hostname-changed` | Reverse DNS returns something different |

**Devices are identified by MAC, never by IP.** A DHCP lease change is reported as one `ip-changed`, not as a departure plus an arrival - otherwise a router rebooting would bury real events under a wall of noise.

## Honest limitations

- **Randomised MACs.** Phones and laptops rotate their MAC per network by default. Those devices appear as new hardware whenever they rotate; netdiff labels them `randomised` rather than pretending to know better. If you want stable identity for a device, disable private addressing for your network on that device.
- **Same broadcast segment only.** ARP does not cross routers, so this sees your subnet and nothing beyond it. That is a property of the approach, not a bug to fix.
- **A device asleep during a scan is indistinguishable from one that left.** Expect `vanished`/`appeared` churn from phones. Longer intervals produce less noise.
- **`port-opened` means a TCP handshake completed**, nothing about what is listening. `netdiff audit` adds banner reading, but there is still no OS fingerprinting and no CVE matching, on purpose - shallow version-guessing cannot compete with real scanners and only produces false confidence.
- **No UPnP gateway means no UPnP findings, not a clean bill of health.** A router with UPnP disabled is a good result, and it is also the common case now. Port forwards you configured by hand do not appear in the UPnP table at all - check your router's admin page for those.
- **The audit sees the LAN's exposure, not the internet's view of it.** It reads the forwarding table the router admits to. The only way to know what is actually reachable is to test from outside, which is why every exposure finding hands you that command.
- **The bundled vendor table is small.** It covers common home-network hardware. For full coverage, download the IEEE registry and point `NETDIFF_OUI` at the CSV:
  ```bash
  curl -o oui.csv https://standards-oui.ieee.org/oui/oui.csv
  export NETDIFF_OUI=$PWD/oui.csv
  ```

## Scope

Only scan networks you are responsible for. netdiff is deliberately read-only - it sends empty UDP datagrams, completes TCP handshakes, reads banners services volunteer, asks the standard DNS-SD question over multicast and reads the replies, and asks the router to list its own port forwards. It never writes to a host, never authenticates, and never changes router configuration. Even so, scanning equipment you do not own is your problem, not the tool's.

## Development

```bash
pip install pytest && pytest -q
```

The tests never touch the network. ARP parsing runs against captured `arp -an` and `ip neigh` output, UPnP parsing against captured router XML, mDNS parsing against hand-built packets, and the one end-to-end test stands up a throwaway HTTP server on loopback. The database is a temp file.

`test_mdns.py` builds its packets with its own helpers rather than with the encoder in `mdns.py`, because a decoder tested only against its own encoder agrees with itself however wrong both are. Half of that file is malformed input - a name pointing at itself, a record claiming to be longer than the packet carrying it - because anything able to send a UDP datagram can send those.

`test_diff.py` covers change detection. `test_audit.py` covers the rules, and roughly half of it asserts that something is *not* reported - an open port, an HTTP 200, a missing security header, a connection error. Those are the important half: the failure mode for a tool like this is not missing a finding, it is inventing one.

Every audit rule is a pure function - evidence in, a `Finding` or `None` out - and nothing in `audit.py` opens a socket. That is what makes the security logic testable at all. `Finding.evidence` has no default value, so a finding cannot be constructed without the observation that proves it.

## License

MIT
