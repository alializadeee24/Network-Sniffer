#!/usr/bin/env python3
"""CodeAlpha Task 1 - Basic Network Sniffer (scapy).
Use ONLY on networks you own or are authorised to monitor.
  sudo python3 sniffer.py -i eth0 -c 50 -f "tcp port 80" -w out.pcap
"""
import argparse, datetime, signal, sys
from collections import Counter
from scapy.all import (sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, Raw, ARP)

stats, talkers, captured = Counter(), Counter(), []
PORTS = {80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 21: "FTP", 25: "SMTP",
         23: "Telnet", 110: "POP3", 143: "IMAP", 3389: "RDP", 445: "SMB"}
C = {"TCP": "\033[96m", "UDP": "\033[93m", "ICMP": "\033[95m", "ARP": "\033[92m", "END": "\033[0m"}

def flags(p):
    names = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH", "A": "ACK", "U": "URG"}
    return ",".join(names.get(f, f) for f in str(p[TCP].flags))

def payload_preview(pkt, n=60):
    if Raw not in pkt:
        return ""
    data = bytes(pkt[Raw].load)[:n]
    txt = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return f"  payload({len(pkt[Raw].load)}B): {txt}"

def handle(pkt):
    captured.append(pkt)
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    if ARP in pkt:
        stats["ARP"] += 1
        a = pkt[ARP]
        print(f"{C['ARP']}[{ts}] ARP  {a.psrc} -> {a.pdst} ({'request' if a.op == 1 else 'reply'}){C['END']}")
        return
    ip = pkt[IP] if IP in pkt else pkt[IPv6] if IPv6 in pkt else None
    if ip is None:
        stats["OTHER"] += 1
        return
    src, dst = ip.src, ip.dst
    talkers[src] += 1
    if TCP in pkt:
        proto, sp, dp = "TCP", pkt[TCP].sport, pkt[TCP].dport
        extra = f"[{flags(pkt)}] {PORTS.get(dp) or PORTS.get(sp) or ''}"
    elif UDP in pkt:
        proto, sp, dp = "UDP", pkt[UDP].sport, pkt[UDP].dport
        extra = PORTS.get(dp) or PORTS.get(sp) or ""
        if DNS in pkt and pkt.haslayer(DNSQR):
            extra += f" query={pkt[DNSQR].qname.decode(errors='ignore')}"
    elif ICMP in pkt:
        proto, sp, dp, extra = "ICMP", "-", "-", f"type={pkt[ICMP].type} code={pkt[ICMP].code}"
    else:
        proto, sp, dp, extra = "OTHER", "-", "-", ""
    stats[proto] += 1
    print(f"{C.get(proto,'')}[{ts}] {proto:<4} {src}:{sp} -> {dst}:{dp} len={len(pkt)} {extra}{C['END']}")
    line = payload_preview(pkt)
    if line:
        print(line)
    if Raw in pkt and TCP in pkt and dp == 80 and pkt[Raw].load.startswith((b"GET", b"POST", b"HEAD")):
        print("  [!] Plain HTTP request (unencrypted):", pkt[Raw].load.split(b"\r\n")[0].decode(errors="ignore"))

def summary(*_):
    print("\n=== SUMMARY ===")
    for k, v in stats.most_common():
        print(f"{k:<6}{v}")
    print("Top talkers:", talkers.most_common(5))
    if ARGS.write and captured:
        wrpcap(ARGS.write, captured)
        print("Saved ->", ARGS.write)
    sys.exit(0)

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Basic network sniffer")
    ap.add_argument("-i", "--iface"); ap.add_argument("-c", "--count", type=int, default=0)
    ap.add_argument("-f", "--filter", default="", help="BPF filter, e.g. 'tcp port 80'")
    ap.add_argument("-w", "--write", help="save pcap (open in Wireshark)")
    ARGS = ap.parse_args()
    signal.signal(signal.SIGINT, summary)
    print("Sniffing... Ctrl+C to stop")
    sniff(iface=ARGS.iface, filter=ARGS.filter, prn=handle, count=ARGS.count, store=False)
    summary()
