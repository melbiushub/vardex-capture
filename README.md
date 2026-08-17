# vardex-capture

**Packet capture subprocess for [Vardex](https://melbius.com)**

This repository contains the open-source packet capture component of Vardex,
published under the GNU General Public License v2 to comply with Scapy's
license terms.

---

## What this is

`vardex_capture.py` is a standalone Python subprocess that:

- Captures live network packets and ARP traffic using **[Scapy](https://scapy.net)** (GPL v2)
- Auto-detects the best network interface, or accepts one as a CLI argument
- Resolves Windows friendly interface names (e.g. `Wi-Fi`) to their NPF GUIDs
- Emits each captured packet or ARP sighting as a single JSON line to **stdout**
- Runs completely independently — no shared memory or imports with Vardex's backend

### Why it's a separate program

Scapy is licensed under GPL v2. To allow Vardex's proprietary backend to
remain closed-source, this capture component runs as a **separate OS
process** and communicates exclusively via a stdout pipe — no code, object
files, or data structures are linked into, imported by, or shared in-process
with the proprietary application. The FSF recognises inter-process
communication over a pipe as legally separate programs, satisfying GPL v2
without requiring the rest of Vardex to be open-sourced. This program itself,
because it directly uses Scapy, is licensed under GPL v2 in its own right —
see [LICENSE](LICENSE).

---

## JSON output format

Each line written to stdout is one JSON object. There are two kinds of
capture events, distinguished by the `"kind"` field:

**Packet capture** (`"kind": "pkt"`) — one line per IP/IPv6 packet seen:

```json
{
  "kind":     "pkt",
  "src_ip":   "192.168.1.50",
  "dst_ip":   "8.8.8.8",
  "src_port": 54321,
  "dst_port": 53,
  "protocol": "UDP",
  "length":   74,
  "flags":    {}
}
```

TCP packets additionally include a `"flags"` object (`SYN`/`ACK`/`FIN`/`RST`/
`PSH`/`URG` booleans), and a `"payload"` field (up to 4096 bytes, latin-1
decoded) when a PSH packet is seen on a common plaintext HTTP port — used
upstream for SQL-injection pattern inspection. HTTPS traffic is encrypted and
is never inspected at this layer.

**ARP sighting** (`"kind": "arp"`) — one line per ARP is-at reply (op=2),
used upstream for MAC-based device identity (who-has requests are noise and
are not emitted):

```json
{"kind": "arp", "ip": "192.168.1.50", "mac": "aa:bb:cc:dd:ee:ff"}
```

Status and error messages use `"status"`, `"info"`, and `"error"` keys instead
of `"kind"`, e.g. `{"status": "ready", "interface": "Wi-Fi"}`.

---

## Usage

```bash
# Auto-detect best interface
python vardex_capture.py auto

# Specific interface (Windows friendly name)
python vardex_capture.py Wi-Fi

# Specific interface (Linux)
python vardex_capture.py eth0
```

**Requirements:**
- Python 3.10+
- [Scapy](https://scapy.net): `pip install scapy`
- Windows: [Npcap](https://npcap.com) must be installed
- Linux/macOS: libpcap (`sudo apt install libpcap-dev`)

---

## Integration

Vardex's backend launches this script as a subprocess and reads its stdout
line by line:

```python
proc = subprocess.Popen(
    ["python", "vardex_capture.py", "auto"],
    stdout=subprocess.PIPE,
    text=True,
    bufsize=1,
)
for line in proc.stdout:
    event = json.loads(line)
    if event.get("kind") == "arp":
        ...  # device identity tracking
    elif event.get("kind") == "pkt":
        ...  # threat detection
```

---

## License

GNU General Public License v2.0 — see [LICENSE](LICENSE)

This component uses [Scapy](https://scapy.net) © Philippe Biondi et al., GPL v2.

---

## Contributing

Issues and pull requests welcome. This component is intentionally minimal —
its only job is reliable packet capture and clean JSON output.

---

*Part of [Vardex](https://melbius.com) by The Trustee for THE THREE
WANDERERS TRUST.*
