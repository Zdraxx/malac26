import socket
import time
import re
import sys
import os

NMAP_FILE = "f2_detalle.nmap"
TARGET_IP = "10.66.0.1"
OUTPUT_FILE = "banners2.txt"

def extract_ports(filename):
    """Extrae los puertos TCP abiertos de un fichero de salida de Nmap (.nmap)."""
    if not os.path.exists(filename):
        print(f"[!] Error: No se encuentra el archivo '{filename}'")
        sys.exit(1)
        
    ports = []
    # Regex equivalente a: '^\d+(?=/tcp\s+open)'
    pattern = re.compile(r'^(\d+)/tcp\s+open')
    
    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            match = pattern.search(line.strip())
            if match:
                ports.append(int(match.group(1)))
                
    return sorted(list(set(ports)))

# 1. Cargar puertos dinámicamente
ports = extract_ports(NMAP_FILE)
print(f"[+] Se han detectado {len(ports)} puertos abiertos en '{NMAP_FILE}':")
print(f"    {ports}\n")

# 2. Grabber y medición de latencia RTT
print(f"[*] Iniciando prueba de puertos en {TARGET_IP}...\n")

with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
    for port in ports:
        start = time.time()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.5)
            s.connect((TARGET_IP, port))
            
            # Sonda de prueba para solicitar banner/respuesta
            s.sendall(b"HEAD / HTTP/1.1\r\nHost: 10.66.0.1\r\n\r\n")
            
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            elapsed = time.time() - start
            s.close()
            
            # Limpiar saltos de línea para el log
            clean_banner = " ".join(banner.splitlines()) if banner else "[Sin Banner]"
            
            res_str = f"== Puerto {port} (RTT: {elapsed:.3f}s) ==\n{banner}\n\n"
            print(f"[+] Puerto {port:<5} | RTT: {elapsed:.3f}s | Banner: {clean_banner[:70]}")
            out.write(res_str)
            
        except Exception as e:
            elapsed = time.time() - start
            res_str = f"== Puerto {port} (Timeout/Error) ==\nError: {e}\n\n"
            print(f"[-] Puerto {port:<5} | RTT: {elapsed:.3f}s | Sin respuesta ({e})")
            out.write(res_str)

print(f"\n[+] Captura de banners completada y guardada en {OUTPUT_FILE}.")