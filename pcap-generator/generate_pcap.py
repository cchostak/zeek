#!/usr/bin/env python3
"""Generate richer synthetic traffic and save as PCAP for Zeek analysis."""
import random

from scapy.all import DNS, DNSQR, DNSRR, Ether, ICMP, IP, TCP, UDP, Raw, wrpcap

OUTPUT = "/data/sample.pcap"

random.seed(1337)
packets = []

PUBLIC_CLIENTS = [
    "73.162.21.44",
    "189.18.222.9",
    "82.66.14.201",
    "201.44.88.30",
    "45.112.92.14",
]

WEB_SERVERS = [
    ("93.184.216.34", "example.com"),
    ("151.101.1.69", "api.example.net"),
    ("172.217.14.206", "www.search.example"),
    ("81.2.69.142", "uk.edge.example"),
    ("210.140.92.183", "jp.edge.example"),
]

DNS_RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "77.88.8.8"]


def add_tcp_session(src_ip, dst_ip, src_port, dst_port, request_bytes, response_bytes, base_seq):
    """Build a minimal complete TCP session with payload exchange."""
    client_seq = base_seq
    server_seq = base_seq + 10000

    packets.append(Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S", seq=client_seq))
    packets.append(Ether() / IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="SA", seq=server_seq, ack=client_seq + 1))

    client_seq += 1
    server_seq += 1
    packets.append(Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="A", seq=client_seq, ack=server_seq))

    packets.append(
        Ether()
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=src_port, dport=dst_port, flags="PA", seq=client_seq, ack=server_seq)
        / Raw(load=request_bytes)
    )
    client_seq += len(request_bytes)

    packets.append(
        Ether()
        / IP(src=dst_ip, dst=src_ip)
        / TCP(sport=dst_port, dport=src_port, flags="PA", seq=server_seq, ack=client_seq)
        / Raw(load=response_bytes)
    )
    server_seq += len(response_bytes)

    packets.append(Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="FA", seq=client_seq, ack=server_seq))
    client_seq += 1
    packets.append(Ether() / IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="FA", seq=server_seq, ack=client_seq))
    server_seq += 1
    packets.append(Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="A", seq=client_seq, ack=server_seq))


# Rich HTTP traffic: mix methods, hosts, paths, and response codes.
http_paths = ["/", "/index.html", "/api/v1/users", "/products/42", "/status"]
http_methods = ["GET", "GET", "GET", "POST"]
http_statuses = [200, 200, 201, 302, 404, 500]

for i in range(24):
    client_ip = random.choice(PUBLIC_CLIENTS)
    server_ip, host = random.choice(WEB_SERVERS)
    method = random.choice(http_methods)
    path = random.choice(http_paths)
    status = random.choice(http_statuses)

    if method == "POST":
        body = b'{"action":"purchase","item":42}'
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: Zeek-Learn/2.0\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode() + body
    else:
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: Zeek-Learn/2.0\r\n"
            "Accept: */*\r\n\r\n"
        ).encode()

    status_msg = {
        200: b"OK",
        201: b"Created",
        302: b"Found",
        404: b"Not Found",
        500: b"Internal Server Error",
    }[status]
    payload = f"response-status-{status}".encode()
    response = (
        b"HTTP/1.1 "
        + str(status).encode()
        + b" "
        + status_msg
        + b"\r\nContent-Type: text/plain\r\nContent-Length: "
        + str(len(payload)).encode()
        + b"\r\n\r\n"
        + payload
    )

    add_tcp_session(
        src_ip=client_ip,
        dst_ip=server_ip,
        src_port=41000 + i,
        dst_port=80,
        request_bytes=request,
        response_bytes=response,
        base_seq=100000 + i * 250,
    )


# DNS traffic: A/AAAA lookups, mix of successful and NXDOMAIN answers.
domains = [
    "example.com",
    "openai.com",
    "wikipedia.org",
    "cdn.example.net",
    "missing.invalid",
    "images.example.com",
]
answer_ips = ["93.184.216.34", "151.101.1.69", "172.217.14.206", "104.16.132.229"]

for i in range(18):
    client_ip = random.choice(PUBLIC_CLIENTS)
    resolver_ip = random.choice(DNS_RESOLVERS)
    domain = random.choice(domains)
    qtype = random.choice(["A", "AAAA"])
    txid = 5000 + i
    src_port = 53000 + i

    query_pkt = DNS(id=txid, rd=1, qd=DNSQR(qname=domain, qtype=qtype))

    if domain.endswith(".invalid"):
        response_pkt = DNS(
            id=txid,
            qr=1,
            aa=1,
            rd=1,
            ra=1,
            rcode=3,
            qd=DNSQR(qname=domain, qtype=qtype),
            ancount=0,
        )
    else:
        if qtype == "A":
            answer = DNSRR(rrname=domain, type="A", ttl=300, rdata=random.choice(answer_ips))
        else:
            answer = DNSRR(rrname=domain, type="AAAA", ttl=300, rdata="2606:2800:220:1:248:1893:25c8:1946")

        response_pkt = DNS(
            id=txid,
            qr=1,
            aa=1,
            rd=1,
            ra=1,
            rcode=0,
            qd=DNSQR(qname=domain, qtype=qtype),
            an=answer,
            ancount=1,
        )

    packets.append(Ether() / IP(src=client_ip, dst=resolver_ip) / UDP(sport=src_port, dport=53) / query_pkt)
    packets.append(Ether() / IP(src=resolver_ip, dst=client_ip) / UDP(sport=53, dport=src_port) / response_pkt)


# Non-HTTP TCP sessions (SSH and SMTP style payloads) for service diversity.
for i in range(6):
    client_ip = random.choice(PUBLIC_CLIENTS)
    server_ip = random.choice(["185.199.108.153", "31.13.71.36", "52.95.110.1", "81.2.69.142", "210.140.92.183"])

    add_tcp_session(
        src_ip=client_ip,
        dst_ip=server_ip,
        src_port=44000 + i,
        dst_port=22,
        request_bytes=b"SSH-2.0-OpenSSH_9.3\r\n",
        response_bytes=b"SSH-2.0-OpenSSH_8.9\r\n",
        base_seq=220000 + i * 310,
    )

for i in range(4):
    client_ip = random.choice(PUBLIC_CLIENTS)
    server_ip = random.choice(["142.250.72.14", "151.101.1.69", "81.2.69.142", "210.140.92.183"])
    smtp_req = b"EHLO client.example\r\nMAIL FROM:<user@example.com>\r\nRCPT TO:<alerts@example.net>\r\n"
    smtp_resp = b"250-mail.example.net\r\n250 AUTH PLAIN LOGIN\r\n"

    add_tcp_session(
        src_ip=client_ip,
        dst_ip=server_ip,
        src_port=45000 + i,
        dst_port=25,
        request_bytes=smtp_req,
        response_bytes=smtp_resp,
        base_seq=280000 + i * 350,
    )


# ICMP pings between global hosts.
for i in range(10):
    src_ip = random.choice(PUBLIC_CLIENTS)
    dst_ip = random.choice(["8.8.8.8", "1.1.1.1", "9.9.9.9"])
    packets.append(Ether() / IP(src=src_ip, dst=dst_ip) / ICMP(type=8, id=10 + i, seq=1))
    packets.append(Ether() / IP(src=dst_ip, dst=src_ip) / ICMP(type=0, id=10 + i, seq=1))


# UDP service chatter (NTP + syslog-like payloads).
for i in range(8):
    src_ip = random.choice(PUBLIC_CLIENTS)
    ntp_server = random.choice(["129.6.15.28", "162.159.200.1", "77.88.8.8", "81.2.69.142"])
    packets.append(Ether() / IP(src=src_ip, dst=ntp_server) / UDP(sport=46000 + i, dport=123) / Raw(load=b"\x1b" + b"\x00" * 47))
    packets.append(Ether() / IP(src=ntp_server, dst=src_ip) / UDP(sport=123, dport=46000 + i) / Raw(load=b"\x1c" + b"\x11" * 47))

for i in range(6):
    src_ip = random.choice(PUBLIC_CLIENTS)
    dst_ip = random.choice(["52.95.110.1", "31.13.71.36", "81.2.69.142", "210.140.92.183"])
    msg = f"<134>Mar 17 14:00:{10+i:02d} app{i} synthetic syslog event".encode()
    packets.append(Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=47000 + i, dport=514) / Raw(load=msg))


print(f"Writing {len(packets)} packets to {OUTPUT}")
wrpcap(OUTPUT, packets)
print("PCAP generation complete.")
