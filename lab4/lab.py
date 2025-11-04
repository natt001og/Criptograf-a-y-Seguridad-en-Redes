#!/usr/bin/env python3
"""
Programa: cifrado_cbc_menu.py
Requisitos: pip install pycryptodome

Descripción:
- Implementa cifrado/descifrado DES, 3DES (24 bytes) y AES-256 en modo CBC.
- Permite elegir algoritmo y acción (cifrar o descifrar) desde un menú.
- Ajusta la key (completa con bytes aleatorios o trunca) y muestra la key/IV finales.
- Usa PKCS#7 padding.
"""

import base64
from Crypto.Cipher import DES, DES3, AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding

# --- Padding PKCS7 ---
def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    return Padding.pad(data, block_size)

def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    return Padding.unpad(data, block_size)

# --- Ajuste de key e IV ---
def adjust_key(key_bytes: bytes, required_len: int) -> bytes:
    if len(key_bytes) < required_len:
        key_bytes += get_random_bytes(required_len - len(key_bytes))
    elif len(key_bytes) > required_len:
        key_bytes = key_bytes[:required_len]
    return key_bytes

def adjust_iv(iv_bytes: bytes, required_len: int) -> bytes:
    if len(iv_bytes) < required_len:
        iv_bytes += get_random_bytes(required_len - len(iv_bytes))
    elif len(iv_bytes) > required_len:
        iv_bytes = iv_bytes[:required_len]
    return iv_bytes

# --- DES ---
def des_encrypt(key: bytes, iv: bytes, plaintext: str) -> bytes:
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return cipher.encrypt(pkcs7_pad(plaintext.encode('utf-8'), DES.block_size))

def des_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> str:
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return pkcs7_unpad(cipher.decrypt(ciphertext), DES.block_size).decode('utf-8', errors='replace')

# --- 3DES (24 bytes, 3 claves distintas) ---
def adjust_3des_key(key_bytes: bytes) -> bytes:
    """Asegura que la key tenga 24 bytes y paridad correcta para 3DES"""
    if len(key_bytes) < 24:
        key_bytes += get_random_bytes(24 - len(key_bytes))
    elif len(key_bytes) > 24:
        key_bytes = key_bytes[:24]
    key_bytes = DES3.adjust_key_parity(key_bytes)
    return key_bytes

def des3_encrypt(key: bytes, iv: bytes, plaintext: str) -> bytes:
    key = adjust_3des_key(key)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return cipher.encrypt(pkcs7_pad(plaintext.encode('utf-8'), DES3.block_size))

def des3_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> str:
    key = adjust_3des_key(key)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return pkcs7_unpad(cipher.decrypt(ciphertext), DES3.block_size).decode('utf-8', errors='replace')

# --- AES-256 ---
def aes256_encrypt(key: bytes, iv: bytes, plaintext: str) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pkcs7_pad(plaintext.encode('utf-8'), AES.block_size))

def aes256_decrypt(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    # Si el texto termina con bytes de padding, intenta removerlos
    try:
        return Padding.unpad(decrypted, AES.block_size).decode('utf-8', errors='replace')
    except ValueError:
        # Si no tiene padding, lo devolvemos tal cual
        return decrypted.decode('utf-8', errors='replace')

# --- Utilidades ---
def ask_bytes(prompt: str) -> bytes:
    s = input(prompt).strip()
    if s.startswith("0x") or s.startswith("0X"):
        return bytes.fromhex(s[2:])
    if s.lower().startswith("hex:"):
        return bytes.fromhex(s[4:])
    return s.encode('utf-8')

def safe_print_hex(label: str, b: bytes):
    print(f"{label}: (len={len(b)}) {b.hex()}")

# --- Menú ---
def menu():
    print("\n==== MENÚ DE CIFRADO ====")
    print("1. DES")
    print("2. 3DES (24 bytes, 3 claves distintas)")
    print("3. AES-256")
    print("4. Salir")
    return input("Seleccione el algoritmo (1-4): ").strip()

def submenu():
    print("\n--- Acción ---")
    print("1. Cifrar")
    print("2. Descifrar")
    return input("Seleccione acción (1-2): ").strip()

def run_algorithm(name, key_len, iv_len, encrypt_fn, decrypt_fn):
    action = submenu()
    key_in = ask_bytes(f"Ingrese la key para {name} (texto | hex:abcdef | 0xabcdef): ")
    iv_in = ask_bytes(f"Ingrese el IV para {name} (texto | hex:...): ")

    # Ajuste de key y IV
    if "3DES" in name:
        key_final = adjust_3des_key(key_in)
    else:
        key_final = adjust_key(key_in, key_len)
    iv_final = adjust_iv(iv_in, iv_len)

    safe_print_hex("Key final (hex)", key_final)
    safe_print_hex("IV final (hex)", iv_final)

    if action == '1':  # Cifrar
        plaintext = input("Ingrese el texto a cifrar: ")
        ciphertext = encrypt_fn(key_final, iv_final, plaintext)
        print("\nTexto cifrado (Base64):")
        print(base64.b64encode(ciphertext).decode('utf-8'))
    elif action == '2':  # Descifrar
        ct_b64 = input("Ingrese el texto cifrado en Base64: ")
        try:
            ciphertext = base64.b64decode(ct_b64)
        except Exception:
            print("Base64 inválido")
            return
        decrypted = decrypt_fn(key_final, iv_final, ciphertext)
        print("\nTexto descifrado:")
        print(decrypted)
    else:
        print("Opción inválida")

def main_menu():
    while True:
        choice = menu()
        if choice == '1':
            run_algorithm("DES", 8, 8, des_encrypt, des_decrypt)
        elif choice == '2':
            run_algorithm("3DES (Triple DES, 3-key)", 24, 8, des3_encrypt, des3_decrypt)
        elif choice == '3':
            run_algorithm("AES-256", 32, 16, aes256_encrypt, aes256_decrypt)
        elif choice == '4':
            print("Saliendo...")
            break
        else:
            print("Opción inválida, intente de nuevo.")

if __name__ == "__main__":
    print("Programa de cifrado CBC con PyCryptodome")
    print("Nota: para ingresar bytes en hex use prefijo 'hex:' o '0x'.")
    main_menu()
