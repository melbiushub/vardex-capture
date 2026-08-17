"""
vardex_capture.py — packet capture subprocess for Vardex

Copyright (C) 2026  The Trustee for THE THREE WANDERERS TRUST

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; version 2 of the License. See LICENSE in this
repository for the full text.

This is a standalone, independent program, licensed separately from
Vardex itself: it uses Scapy (GPL v2) directly, so it is distributed
here under GPL v2 in its own right. Vardex (the proprietary application
that uses it) invokes this program as a wholly separate OS process and
communicates with it only via a line-delimited JSON pipe over stdout —
no code, objects, or memory are shared between the two. See README.md
for the interface this program exposes.
"""

import json
import sys
import platform


def resolve_interface(name):
    if platform.system() != "Windows":
        return name
    if "\\" in name:
        return name
    try:
        from scapy.arch.windows import get_windows_if_list
        ifaces = get_windows_if_list()
    except Exception:
        return name
    for iface in ifaces:
        if iface.get("name", "").lower() == name.lower():
            guid = iface.get("guid", "")
            if guid:
                resolved = "\\Device\\NPF_" + guid
                sys.stdout.write(json.dumps({"info": "Resolved " + name + " to " + resolved}) + "\n")
                sys.stdout.flush()
                return resolved
    sys.stdout.write(json.dumps({"info": "Could not resolve " + name + ", trying as-is"}) + "\n")
    sys.stdout.flush()
    return name



def auto_detect_interface():
    """
    Find the best network interface for packet capture automatically.

    Strategy:
    1. UDP socket trick: connect to 8.8.8.8 (no data sent) to discover
       the IP of the default outbound interface.
    2. Match that IP against Scapy's interface list, skipping virtual,
       filter-driver, VPN, tunnel, and Bluetooth adapters.
    3. Fall back to the first non-virtual interface with a real IP.
    4. Last resort: Scapy's own configured default.
    """
    import socket as _socket

    SKIP = {
        "loopback","pseudo","virtual","wfp","qos","filter driver","miniport",
        "teredo","tunnel","6to4","pptp","l2tp","ikev2","sstp","pppoe",
        "tap-windows","openvpn","dco adapter","bluetooth","debug",
        "npcap packet driver","native mac layer","wifi filter driver",
        "light weight filter","lightweight filter","packet scheduler",
        "wan miniport","ip-https","isatap","kernel debug",
    }

    def _is_virtual(desc):
        d = desc.lower()
        return any(k in d for k in SKIP)

    # Step 1: outbound IP via UDP socket (no packets sent)
    active_ip = None
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        active_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    try:
        from scapy.arch.windows import get_windows_if_list
        ifaces = get_windows_if_list()

        # Step 2: match by outbound IP
        if active_ip:
            for iface in ifaces:
                if _is_virtual(iface.get("description", "")):
                    continue
                if iface.get("ip") == active_ip:
                    return iface["name"]

        # Step 3: first physical interface with a routable IP
        for iface in ifaces:
            if _is_virtual(iface.get("description", "")):
                continue
            ip = iface.get("ip", "")
            if ip and not ip.startswith("169.254") and ip != "0.0.0.0":
                return iface["name"]

    except Exception:
        pass

    # Step 4: Scapy default
    try:
        from scapy.all import conf
        return str(conf.iface)
    except Exception:
        pass

    return "Wi-Fi"


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No interface specified"}), flush=True)
        sys.exit(1)

    friendly_name = sys.argv[1]
    if friendly_name.lower() == "auto":
        friendly_name = auto_detect_interface()
        sys.stdout.write(json.dumps({"info": f"Auto-detected interface: {friendly_name}"}) + "\n")
        sys.stdout.flush()

    try:
        from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, conf
        conf.verb = 0
    except ImportError:
        print(json.dumps({"error": "Scapy not installed. Run: pip install scapy"}), flush=True)
        sys.exit(1)

    interface = resolve_interface(friendly_name)

    def packet_to_dict(pkt):
        # ARP is-at replies (op=2) are authoritative IP<->MAC bindings on the
        # local broadcast domain — the signal device-identity tracking needs.
        # who-has requests (op=1) are just noise (every host asks constantly).
        if ARP in pkt and pkt[ARP].op == 2:
            return {"kind": "arp", "ip": pkt[ARP].psrc, "mac": pkt[ARP].hwsrc}

        result = {
            "kind": "pkt",
            "src_ip": None,
            "dst_ip": None,
            "src_port": 0,
            "dst_port": 0,
            "protocol": "OTHER",
            "length": len(pkt),
            "flags": {},
        }
        if IP in pkt:
            result["src_ip"] = pkt[IP].src
            result["dst_ip"] = pkt[IP].dst
        elif IPv6 in pkt:
            result["src_ip"] = pkt[IPv6].src
            result["dst_ip"] = pkt[IPv6].dst
        else:
            return None
        # Ports on which we attempt HTTP payload extraction (plaintext only).
        # HTTPS traffic is encrypted — not inspectable at this layer without
        # an SSL inspection proxy and explicit network-owner consent.
        HTTP_PORTS = {80, 8080, 8000, 8008, 8888, 3000, 5000}

        if TCP in pkt:
            result["protocol"] = "TCP"
            result["src_port"] = pkt[TCP].sport
            result["dst_port"] = pkt[TCP].dport
            flags = pkt[TCP].flags
            result["flags"] = {
                "SYN": bool(flags & 0x02),
                "ACK": bool(flags & 0x10),
                "FIN": bool(flags & 0x01),
                "RST": bool(flags & 0x04),
                "PSH": bool(flags & 0x08),
                "URG": bool(flags & 0x20),
            }
            # Extract HTTP payload for SQLi inspection.
            # Only on PSH packets (data push) to HTTP ports — avoids wasting
            # CPU on SYN/ACK handshake packets which carry no application data.
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            if (sport in HTTP_PORTS or dport in HTTP_PORTS) and bool(flags & 0x08):
                try:
                    raw = bytes(pkt[TCP].payload)
                    if raw:
                        # latin-1 handles all 256 byte values without error.
                        # Cap at 4096 bytes — enough for any HTTP header + body start.
                        result["payload"] = raw[:4096].decode("latin-1")
                except Exception:
                    pass
        elif UDP in pkt:
            result["protocol"] = "UDP"
            result["src_port"] = pkt[UDP].sport
            result["dst_port"] = pkt[UDP].dport
        elif ICMP in pkt:
            result["protocol"] = "ICMP"
        return result

    def on_packet(pkt):
        data = packet_to_dict(pkt)
        if data:
            sys.stdout.write(json.dumps(data) + "\n")
            sys.stdout.flush()

    sys.stdout.write(json.dumps({"status": "ready", "interface": interface}) + "\n")
    sys.stdout.flush()

    try:
        sniff(iface=interface, prn=on_packet, store=False)
    except Exception as e:
        sys.stdout.write(json.dumps({"error": str(e)}) + "\n")
        sys.stdout.flush()
        sys.exit(1)


if __name__ == "__main__":
    main()
