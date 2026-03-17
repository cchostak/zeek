#!/usr/bin/env python3
"""Generate synthetic traffic and save as PCAP for Zeek analysis."""
from scapy.all import IP, TCP, UDP, ICMP, Ether, wrpcap

OUTPUT = "/data/sample.pcap"

packets = []

# Simulate TCP handshake + HTTP GET request
for i in range(1, 3):
    src_port = 40000 + i
    packets.append(Ether() / IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=src_port, dport=80, flags="S", seq=1000))
    packets.append(Ether() / IP(src="10.0.0.20", dst="10.0.0.10") / TCP(sport=80, dport=src_port, flags="SA", seq=2000, ack=1001))
    packets.append(Ether() / IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=src_port, dport=80, flags="A", seq=1001, ack=2001))
    packets.append(Ether() / IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=src_port, dport=80, flags="PA", seq=1001, ack=2001) / (
        b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Zeek-Learn/1.0\r\n\r\n"
    ))
    packets.append(Ether() / IP(src="10.0.0.20", dst="10.0.0.10") / TCP(sport=80, dport=src_port, flags="PA", seq=2001, ack=1041) / b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, Zeek!"
    )
    packets.append(Ether() / IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=src_port, dport=80, flags="FA", seq=1041, ack=2014))
    packets.append(Ether() / IP(src="10.0.0.20", dst="10.0.0.10") / TCP(sport=80, dport=src_port, flags="FA", seq=2014, ack=1042))

# ICMP request/reply
packets.append(Ether() / IP(src="10.0.0.30", dst="10.0.0.40") / ICMP(type=8, id=1, seq=1))
packets.append(Ether() / IP(src="10.0.0.40", dst="10.0.0.30") / ICMP(type=0, id=1, seq=1))

# DNS-like UDP query/response
packets.append(Ether() / IP(src="10.0.0.50", dst="10.0.0.60") / UDP(sport=53535, dport=53) / b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x05example\x03com\x00\x00\x01\x00\x01"
)
packets.append(Ether() / IP(src="10.0.0.60", dst="10.0.0.50") / UDP(sport=53, dport=53535) / b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03www\x05example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\xa8\x00\x01")

print(f"Writing {len(packets)} packets to {OUTPUT}")
wrpcap(OUTPUT, packets)
print("PCAP generation complete.")
