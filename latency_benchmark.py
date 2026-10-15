import socket
import ssl
import time
import statistics
import re
import os
import sys
import urllib.request
import urllib.error

NMAP_FILE = "f2_detalle.nmap"
TARGET_IP = "10.66.0.1"
SAMPLES = 5          # Número de peticiones por puerto para sacar la media
TIMEOUT = 4.0        # Timeout máximo en segundos por petición

# Contexto SSL para ignorar certificados autofirmados
ssl_context = ssl._create_unverified_context()

def extract_all_open_ports(filename):
    """Extrae todos los puertos TCP abiertos del fichero de Nmap."""
    if not os.path.exists(filename):
        print(f"[!] Error: No existe el archivo '{filename}'")
        sys.exit(1)
        
    ports = []
    pattern = re.compile(r'^(\d+)/tcp\s+open', re.IGNORECASE)
    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            match = pattern.search(line.strip())
            if match:
                ports.append(int(match.group(1)))
    return sorted(list(set(ports)))

def measure_tcp_latency(ip, port, samples=SAMPLES):
    """Mide la latencia a nivel de socket TCP (Handshake SYN/ACK)."""
    latencies = []
    for _ in range(samples):
        start = time.perf_counter()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT)
            s.connect((ip, port))
            end = time.perf_counter()
            latencies.append((end - start) * 1000) # Convertir a milisegundos (ms)
            s.close()
        except Exception:
            pass
        time.sleep(0.05) # Pequeña pausa entre muestras
    return latencies

def measure_http_latency(ip, port, use_ssl=False, samples=SAMPLES):
    """Mide la latencia de respuesta HTTP/HTTPS a nivel de aplicación."""
    protocol = "https" if use_ssl else "http"
    url = f"{protocol}://{ip}:{port}/"
    headers = {"User-Agent": "Latencer-Benchmark/1.0"}
    latencies = []
    response_body = ""
    
    for _ in range(samples):
        req = urllib.request.Request(url, headers=headers)
        start = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=ssl_context) as resp:
                end = time.perf_counter()
                latencies.append((end - start) * 1000)
                if not response_body:
                    response_body = resp.read().decode('utf-8', errors='ignore')
        except urllib.error.HTTPError as e:
            end = time.perf_counter()
            latencies.append((end - start) * 1000)
            if not response_body and e.fp:
                response_body = e.fp.read().decode('utf-8', errors='ignore')
        except Exception:
            pass
        time.sleep(0.05)
        
    return latencies, response_body

def calc_stats(latencies):
    """Calcula Min, Max, Media y Desviación Estándar de una lista de latencias."""
    if not latencies:
        return None
    
    min_l = min(latencies)
    max_l = max(latencies)
    mean_l = statistics.mean(latencies)
    std_l = statistics.stdev(latencies) if len(latencies) > 1 else 0.0
    return {"min": min_l, "max": max_l, "avg": mean_l, "std": std_l, "count": len(latencies)}

# --- EJECUCIÓN PRINCIPAL ---
ports = extract_all_open_ports(NMAP_FILE)
print(f"================================================================")
print(f" BENCHMARK DE LATENCIA Y FIABILIDAD - MALACKATHON 2026")
print(f" Target: {TARGET_IP} | Muestras por puerto: {SAMPLES}")
print(f" Puertos detectados: {len(ports)}")
print(f"================================================================\n")

results_summary = []

for port in ports:
    print(f"[*] Analizando Puerto {port}...")
    
    # 1. Medir Latencia TCP pura
    tcp_lats = measure_tcp_latency(TARGET_IP, port)
    tcp_stats = calc_stats(tcp_lats)
    
    # 2. Medir Latencia HTTP/HTTPS
    http_lats, http_body = measure_http_latency(TARGET_IP, port, use_ssl=False)
    http_stats = calc_stats(http_lats)
    
    protocol_used = "HTTP"
    
    # Si HTTP falla o da tiempos nulos, probar HTTPS
    if not http_stats:
        https_lats, https_body = measure_http_latency(TARGET_IP, port, use_ssl=True)
        https_stats = calc_stats(https_lats)
        if https_stats:
            http_stats = https_stats
            http_body = https_body
            protocol_used = "HTTPS"
            
    # Mostrar resultados en pantalla
    tcp_str = f"Avg: {tcp_stats['avg']:.2f}ms | Min: {tcp_stats['min']:.2f}ms | Max: {tcp_stats['max']:.2f}ms | StdDev: {tcp_stats['std']:.2f}ms" if tcp_stats else "N/A (Timeout)"
    app_str = f"[{protocol_used}] Avg: {http_stats['avg']:.2f}ms | Min: {http_stats['min']:.2f}ms | Max: {http_stats['max']:.2f}ms | StdDev: {http_stats['std']:.2f}ms" if http_stats else "N/A (No Web)"
    
    print(f"    TCP Connect -> {tcp_str}")
    print(f"    App Response -> {app_str}")
    
    # Detección temprana de IA por anomalía de latencia (Inferencia > 600ms o Alta Desviación)
    ia_flag = False
    if http_stats and (http_stats['avg'] > 600 or http_stats['std'] > 200):
        ia_flag = True
        print(f"    ⚠️ [ALERTA LATENCIA] Latencia de aplicación inusualmente alta o inestable. ¡Posible IA (Clase 3)!")
        
    results_summary.append({
        "port": port,
        "tcp_avg": tcp_stats['avg'] if tcp_stats else 0,
        "app_avg": http_stats['avg'] if http_stats else 0,
        "app_std": http_stats['std'] if http_stats else 0,
        "proto": protocol_used if http_stats else "RAW/TCP",
        "ia_flag": ia_flag
    })
    print("-" * 64)

# Guardar resumen en CSV para análisis y gráficos
with open("latencias_resumen.csv", "w", encoding="utf-8") as f:
    f.write("Puerto,Protocolo,TCP_Avg_ms,App_Avg_ms,App_StdDev_ms,Sospecha_IA\n")
    for r in results_summary:
        f.write(f"{r['port']},{r['proto']},{r['tcp_avg']:.2f},{r['app_avg']:.2f},{r['app_std']:.2f},{r['ia_flag']}\n")

print("\n[+] Benchmark finalizado. Resumen estadístico guardado en 'latencias_resumen.csv'")