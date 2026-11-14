"""生成测试用 sample_traffic.pcap（经典 PCAP 格式，Ethernet+IPv4+TCP/UDP）。

流量剧本（配合 M1 的 Glyph 流摘要检测）：
1. 正常业务流：内网 10.25.73.34 与 10.60.33.18 之间的少量 HTTP/DNS 会话
2. 端口扫描：境外 45.61.10.9 对 10.60.33.18 做 40 个端口的 TCP SYN 扫描 → 触发 PORT_SWEEP
3. C2 心跳样例：45.61.10.9 每 30 秒一次到 10.60.33.18:8443 的短连接（IOC 场景素材）

用法: .venv/Scripts/python.exe scripts/make_sample_pcap.py [输出路径]
"""
from __future__ import annotations

import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

PCAP_GLOBAL_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
ETH_IPV4 = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00"


def ipv4_checksum(header: bytes) -> int:
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) + header[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def packet(src: tuple[int, int, int, int], dst: tuple[int, int, int, int],
           src_port: int, dst_port: int, proto: int, when: datetime, flags: int = 0x02) -> bytes:
    tcp = struct.pack(">HHIIBBHHH", src_port, dst_port, 1000, 0, 5 << 4, flags, 8192, 0, 0)
    ip_header = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0x1234, 0, 64, proto, 0,
                            bytes(src), bytes(dst))
    checksum = ipv4_checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack(">H", checksum) + ip_header[12:]
    frame = ETH_IPV4 + ip_header + tcp
    stamp = when.timestamp()
    return struct.pack("<IIII", int(stamp), int(stamp % 1 * 1_000_000), len(frame), len(frame)) + frame


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else
               Path(__file__).resolve().parents[1] / "tests_integration" / "fixtures" / "sample_traffic.pcap")
    base = datetime(2025, 11, 15, 9, 0, 0, tzinfo=timezone.utc)
    inside = (10, 60, 33, 18)
    workstation = (10, 25, 73, 34)
    attacker = (45, 61, 10, 9)
    packets: list[bytes] = []

    # 1) 正常业务：工作站访问业务端口
    for i, port in enumerate([80, 443, 80, 443, 8080]):
        packets.append(packet(workstation, inside, 40000 + i, port, 6,
                              datetime.fromtimestamp(base.timestamp() + i * 7, timezone.utc), 0x18))
    # DNS 查询（UDP 53）
    for i in range(3):
        packets.append(packet(workstation, (10, 60, 1, 53), 51000 + i, 53, 17,
                              datetime.fromtimestamp(base.timestamp() + 60 + i * 5, timezone.utc), 0x18))

    # 2) 端口扫描：45.61.10.9 → 10.60.33.18，40 个端口 SYN（含 22/80/443/3389/8443 等）
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521,
                  2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9000, 9200, 11211,
                  27017, 50000, 50001, 50002, 50003, 50004, 50005, 50006, 50007, 50008, 50009, 50010]
    for i, port in enumerate(scan_ports):
        packets.append(packet(attacker, inside, 60000 + i, port, 6,
                              datetime.fromtimestamp(base.timestamp() + 300 + i * 0.2, timezone.utc), 0x02))

    # 3) C2 心跳：每 30 秒一次到 8443 的 SYN+ACK 短连接
    for i in range(6):
        packets.append(packet(attacker, inside, 4444, 8443, 6,
                              datetime.fromtimestamp(base.timestamp() + 600 + i * 30, timezone.utc), 0x12))

    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("wb") as stream:
        stream.write(PCAP_GLOBAL_HEADER)
        for one in packets:
            stream.write(one)
    print(f"written {out} with {len(packets)} packets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
