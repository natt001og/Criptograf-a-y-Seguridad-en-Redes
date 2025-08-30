#!/usr/bin/env python3
"""
icmp_sender_like_ping.py

Imita el formato de ping de Linux:
- 8 bytes de timestamp (sec + usec) al inicio del campo data,
- seguido de 40 bytes de padding (0x10..0x37),
- primer byte del padding reemplazado por el carácter enviado.
"""

import sys
import os
import time
from scapy.all import IP, ICMP, send

# Padding de Linux ping (0x10..0x37 = 40 bytes)
PING_PADDING = bytearray([
    0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b,
    0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b,
    0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33,
    0x34, 0x35, 0x36, 0x37
])

def send_string_icmp_like_ping(text: str, dest_ip: str):
    pid = os.getpid() & 0xFFFF  # ID coherente con ping
    seq = 1

    for i, ch in enumerate(text):
        char_byte = ch.encode("utf-8")
        if len(char_byte) != 1:
            raise ValueError("Solo se permite un carácter ASCII por paquete")

        # Construir timestamp de 8 bytes (sec + usec, big endian)
        now = time.time()
        sec = int(now)
        usec = int((now - sec) * 1_000_000) & 0xFFFFFFFF
        ts_bytes = sec.to_bytes(4, "big") + usec.to_bytes(4, "big")

        # Copia del padding
        payload = bytearray(PING_PADDING)

        # Reemplazar primer byte del padding con tu carácter
        payload[0] = char_byte[0]

        # Payload final: timestamp (8B) + padding (40B) = 48 bytes
        final_data = ts_bytes + bytes(payload)

        # Armar paquete ICMP
        packet = IP(dst=dest_ip) / ICMP(id=pid, seq=seq) / final_data
        send(packet, verbose=False)

        print(f"[{i+1}/{len(text)}] Enviado: '{ch}' | ID={pid}, Seq={seq}, payload_len={len(final_data)}")

        seq += 1


def main(argv):
    if len(argv) != 2:
        print("Uso: sudo python3 icmp_sender_like_ping.py 'Texto' DEST_IP")
        sys.exit(1)

    text = argv[0]
    dest_ip = argv[1]
    send_string_icmp_like_ping(text, dest_ip)


if __name__ == "__main__":
    main(sys.argv[1:])
