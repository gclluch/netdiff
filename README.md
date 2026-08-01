# netdiff

Track what is on your network and tell you when it changes. **Pure standard library, no root.**

`nmap` and Fing answer "what is on my network *right now*". Neither remembers. netdiff records every scan, diffs it against the last one, and tells you what actually changed - a device that appeared at 3am, a printer that quietly opened port 8080, a laptop that moved to a new DHCP lease.

```console
$ netdiff scan 192.168.1.0/24
scan 7: 12 device(s) on 192.168.1.0/24
  192.168.1.1     00:1d:c9:0a:1b:2c  router.local     ports 53,80,443
  192.168.1.23    b8:27:eb:aa:bb:cc  Raspberry Pi     ports 22
  ...

changes since last scan: 1 appeared, 1 port-opened
  [appeared] randomised 192.168.1.102 b6:41:9f:00:11:22
  [port-opened] Raspberry Pi 192.168.1.23 b8:27:eb:aa:bb:cc (8080)
```

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
- **`port-opened` means a TCP handshake completed**, nothing about what is listening. There is no service fingerprinting and no vulnerability scanning here on purpose - shallow banner-matching cannot compete with real scanners and only produces false confidence.
- **The bundled vendor table is small.** It covers common home-network hardware. For full coverage, download the IEEE registry and point `NETDIFF_OUI` at the CSV:
  ```bash
  curl -o oui.csv https://standards-oui.ieee.org/oui/oui.csv
  export NETDIFF_OUI=$PWD/oui.csv
  ```

## Scope

Only scan networks you are responsible for. netdiff is deliberately read-only - it sends empty UDP datagrams and completes TCP handshakes, and never writes, authenticates, or probes a service. Even so, port scanning equipment you do not own is your problem, not the tool's.

## Development

```bash
pip install pytest && pytest -q
```

The tests never touch the network: ARP parsing runs against captured `arp -an` and `ip neigh` output, and the database is a temp file. `test_diff.py` covers the change detection, which is the part worth getting right.

## License

MIT
