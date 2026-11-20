#!/usr/bin/env python3
"""Generates a synthetic capture that triggers every pcapan detector (stdlib only).

Usage: python3 scripts/gen_fixtures.py [output.pcap]   (default: samples/sample.pcap)
"""
import os
import socket
import struct
import sys

T0 = 1_700_000_000.0
FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
ETH_SRC, ETH_DST = b"\x02\x00\x00\x00\x00\x01", b"\x02\x00\x00\x00\x00\x02"

frames = []  # (timestamp, bytes)


def eth(payload, ethertype=0x0800):
    return ETH_DST + ETH_SRC + struct.pack("!H", ethertype) + payload


def ipv4(src, dst, proto, l4):
    total = 20 + len(l4)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + l4


def tcp(sport, dport, seq, ack, flags, window=65535, payload=b""):
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                      5 << 4, flags, window, 0, 0)
    return hdr + payload


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def add_tcp(ts, src, sport, dst, dport, seq, ack, flags, window=65535, payload=b""):
    frames.append((ts, eth(ipv4(src, dst, 6, tcp(sport, dport, seq, ack, flags, window, payload)))))


def add_udp(ts, src, sport, dst, dport, payload):
    frames.append((ts, eth(ipv4(src, dst, 17, udp(sport, dport, payload)))))


def scenario_session():
    c, s = "10.0.0.2", "10.0.0.1"
    t, cseq, sseq = T0, 1000, 5000
    add_tcp(t, c, 50000, s, 80, cseq, 0, SYN)
    add_tcp(t + 0.020, s, 80, c, 50000, sseq, cseq + 1, SYN | ACK)
    add_tcp(t + 0.040, c, 50000, s, 80, cseq + 1, sseq + 1, ACK)
    cseq += 1
    sseq += 1
    t += 0.1
    for i in range(60):
        add_tcp(t, c, 50000, s, 80, cseq, sseq, ACK | PSH, payload=b"x" * 1000)
        if i % 8 == 7:  # retransmission of the same segment
            add_tcp(t + 0.004, c, 50000, s, 80, cseq, sseq, ACK | PSH, payload=b"x" * 1000)
        cseq += 1000
        add_tcp(t + 0.002, s, 80, c, 50000, sseq, cseq, ACK)
        t += 0.05
    for i in range(4):  # zero-window advertisements
        add_tcp(t, s, 80, c, 50000, sseq, cseq, ACK, window=0)
        t += 0.1
    add_tcp(t, c, 50000, s, 80, cseq, sseq, FIN | ACK)
    add_tcp(t + 0.01, s, 80, c, 50000, sseq, cseq + 1, FIN | ACK)
    add_tcp(t + 0.02, c, 50000, s, 80, cseq + 1, sseq + 1, ACK)


def scenario_dns():
    for i in range(20):
        t = T0 + 0.5 + i * 0.3
        add_udp(t, "10.0.0.2", 53000 + i, "10.0.0.53", 53, b"q" * 32)
        add_udp(t + 0.01, "10.0.0.53", 53, "10.0.0.2", 53000 + i, b"r" * 96)


def scenario_port_scan():
    for port in range(1, 151):
        add_tcp(T0 + 2 + port * 0.01, "10.0.0.66", 40000, "10.0.0.1", port, 1, 0, SYN)


def scenario_syn_flood():
    for i in range(300):
        src = "172.16.%d.%d" % (i // 250, i % 250 + 1)
        add_tcp(T0 + 5 + i * 0.003, src, 1024 + i, "10.0.0.1", 80, 1, 0, SYN)


def scenario_rst_storm():
    for i in range(150):
        add_tcp(T0 + 8 + i * 0.005, "10.0.0.1", 80, "10.0.0.99", 40000 + i, 1, 1, RST | ACK)


def scenario_flags():
    add_tcp(T0 + 9, "10.0.0.66", 41000, "10.0.0.1", 22, 1, 0, FIN | PSH | URG)
    add_tcp(T0 + 9.1, "10.0.0.66", 41001, "10.0.0.1", 22, 1, 0, 0)
    add_tcp(T0 + 9.2, "10.0.0.66", 41002, "10.0.0.1", 22, 1, 0, SYN | FIN)


def scenario_udp_flood():
    for i in range(4800):
        add_udp(T0 + 10 + i * (4.0 / 4800), "10.0.0.77", 20000 + i % 50, "10.0.0.5", 9999,
                b"f" * 64)


def scenario_misc():
    frames.append((T0 + 11, eth(b"\x45\x00\x00\x28\x00\x00")))  # truncated IPv4 header
    src = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    dst = socket.inet_pton(socket.AF_INET6, "2001:db8::2")
    payload = udp(5000, 5001, b"v6" * 20)
    hdr = struct.pack("!IHBB16s16s", 0x60000000, len(payload), 17, 64, src, dst)
    frames.append((T0 + 11.5, eth(hdr + payload, 0x86DD)))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join("samples", "sample.pcap")
    for fn in (scenario_session, scenario_dns, scenario_port_scan, scenario_syn_flood,
               scenario_rst_storm, scenario_flags, scenario_udp_flood, scenario_misc):
        fn()
    frames.sort(key=lambda f: f[0])
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, data in frames:
            sec = int(ts)
            fh.write(struct.pack("<IIII", sec, int((ts - sec) * 1_000_000), len(data), len(data)))
            fh.write(data)
    print("wrote %d packets to %s" % (len(frames), out))


if __name__ == "__main__":
    main()
