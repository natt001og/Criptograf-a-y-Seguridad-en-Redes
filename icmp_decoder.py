#!/usr/bin/env python3
"""
Descifra un mensaje codificado tipo César obtenido de ICMP Echo Request.
El descifrado más probable se marca en verde usando diccionario en español.
"""

import sys
from scapy.all import rdpcap, ICMP
from colorama import Fore, Style, init
import string

init(autoreset=True)

# Cargamos un diccionario simple de palabras en español
# Puedes reemplazarlo por un archivo de palabras más completo si quieres
SPANISH_WORDS = {
    'hola', 'mundo', 'esto', 'es', 'una', 'prueba', 'mensaje', 'secreto',
    'de', 'la', 'el', 'un', 'una', 'y', 'con', 'por', 'para', 'frase',
    'en', 'espacio', 'texto', 'seguro'
}

def extract_first_bytes(pcap_file):
    packets = rdpcap(pcap_file)
    data_bytes = []
    for pkt in packets:
        if ICMP in pkt and pkt[ICMP].type == 8:  # Solo Echo Request
            payload = bytes(pkt[ICMP].payload)
            if len(payload) > 0:
                data_bytes.append(chr(payload[0]))  # Convertimos a carácter
    return ''.join(data_bytes)

def caesar_decode(word):
    """
    Genera todos los descifrados posibles con César (shift 1-25)
    y calcula un score según la cantidad de palabras existentes en español.
    """
    results = []
    for shift in range(1, 26):
        decoded = []
        for ch in word:
            if ch.isupper():
                idx = (ord(ch) - ord('A') - shift) % 26
                decoded.append(chr(ord('A') + idx))
            elif ch.islower():
                idx = (ord(ch) - ord('a') - shift) % 26
                decoded.append(chr(ord('a') + idx))
            else:
                decoded.append(ch)  # No alfabético
        decoded_str = ''.join(decoded)
        # Score: proporción de palabras válidas en español
        words = decoded_str.lower().split()
        if words:
            score = sum(1 for w in words if w in SPANISH_WORDS) / len(words)
        else:
            score = 0
        results.append((shift, decoded_str, score))
    return results

def main(argv):
    if len(argv) != 1:
        print("Uso: python3 script.py CAPTURA.pcapng")
        sys.exit(1)

    word = extract_first_bytes(argv[0])
    print(f"[+] Mensaje codificado extraído: {word}\n")

    decoded_words = caesar_decode(word)
    # Encontrar el descifrado más probable
    best_shift, best_decoded, _ = max(decoded_words, key=lambda x: x[2])

    print("[+] Posibles descifrados:")
    for shift, decoded, _ in decoded_words:
        if shift == best_shift:
            print(Fore.GREEN + f"Shift {shift:2}: {decoded}" + Style.RESET_ALL)
        else:
            print(f"Shift {shift:2}: {decoded}")

if __name__ == "__main__":
    main(sys.argv[1:])


