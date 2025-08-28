#!/usr/bin/env python3
"""
icmp_sender_padded.py -- Enviar caracteres de un string como paquetes ICMP
con padding exacto de 40 bytes según captura de Wireshark.
"""

import sys
from scapy.all import ICMP, IP, send

# Padding exacto de la captura (desde 0x10 hasta 0x37)
WIRESHARK_PADDING = bytes([
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

def send_string_icmp_padded(text: str, dest_ip: str):
    total_size = 40  # bytes del campo data

    for i, ch in enumerate(text):
        char_byte = ch.encode('utf-8')
        # Reemplazamos los primeros bytes del padding con el carácter
        # y completamos hasta 40 bytes con el padding de Wireshark
        if len(char_byte) > 1:
            raise ValueError("Solo se puede enviar un carácter por paquete")
        data = char_byte + WIRESHARK_PADDING[1:]  # Primer byte es tu carácter
        packet = IP(dst=dest_ip)/ICMP()/data
        send(packet, verbose=False)
        print(f"[{i+1}/{len(text)}] Enviado: '{ch}' -> {len(data)} bytes a {dest_ip}")

def main(argv):
    if len(argv) != 2:
        print("Uso: sudo python3 icmp_sender_padded.py 'Texto' DEST_IP")
        sys.exit(1)
    
    text = argv[0]
    dest_ip = argv[1]
    send_string_icmp_padded(text, dest_ip)

if __name__ == "__main__":
    main(sys.argv[1:])
