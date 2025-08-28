#!/usr/bin/env python3
"""
cesar.py -- cifrado César

Uso:
    python3 cesar.py "Texto a cifrar" 3        # cifra con shift = 3
    python3 cesar.py "Texto a cifrar" -3       # cifra con shift = -3
    python3 cesar.py -m decrypt "Texto" 3      # descifra (equivalente a shift negativo)
Opciones:
    -m, --mode     : "encrypt" (por defecto) o "decrypt"
"""

import argparse
import sys

def caesar_shift_char(ch: str, shift: int) -> str:
    """Aplica shift a un solo caracter ASCII alfabético (A-Z, a-z)."""
    if 'a' <= ch <= 'z':
        start = ord('a')
        return chr((ord(ch) - start + shift) % 26 + start)
    if 'A' <= ch <= 'Z':
        start = ord('A')
        return chr((ord(ch) - start + shift) % 26 + start)
    # No alfabético ASCII -> lo devolvemos sin cambios (incluye espacios, números, signos, acentos, ñ, etc.)
    return ch

def caesar(text: str, shift: int) -> str:
    """Aplica cifrado César sobre el texto completo (preserva no-letras)."""
    return ''.join(caesar_shift_char(ch, shift) for ch in text)

def parse_args(argv):
    p = argparse.ArgumentParser(description="Cifrado César simple")
    p.add_argument("text", help="Texto a cifrar/descifrar (proteger con comillas si tiene espacios)")
    p.add_argument("shift", type=int, help="Corrimiento (integer). Usar negativo para corrimiento inverso")
    p.add_argument("-m", "--mode", choices=["encrypt", "decrypt"], default="encrypt",
                   help="Modo: encrypt (por defecto) o decrypt. decrypt aplica el shift negativo.")
    return p.parse_args(argv)

def main(argv):
    args = parse_args(argv)
    shift = args.shift % 26  # reduce shift al rango 0..25
    if args.mode == "decrypt":
        shift = (-shift) % 26
    result = caesar(args.text, shift)
    print(result)

if __name__ == "__main__":
    main(sys.argv[1:])
