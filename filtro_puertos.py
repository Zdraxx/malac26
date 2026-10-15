#!/usr/bin/env python3
"""
Filtro de puertos vivos/muertos por handshake de protocolo.

VIVO   = el puerto habla de verdad el protocolo esperado.
MUERTO = rechaza, cierra sin hablar, o contesta algo que no es el protocolo.
?      = TCP abierto pero en silencio (ambiguo; con --strict-silence cuenta como MUERTO).

Uso:  python3 filtro_puertos.py [-t 10.66.0.1] [-w 8] [-r 2] [--strict-silence] [-o filtro.csv]
"""
import argparse
import csv
import random
import re
import shutil
import socket
import ssl
import string
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

PORTS = {
    "http":  [43989, 55099, 57144, 59646],
    "https": [20749, 30259, 31893, 36681, 37076, 38250, 39051, 41766, 42107, 44965,
              49301, 51315, 51535, 51598, 53968, 54181, 55582, 55794],
    "ssh":   [29095, 41199, 45293, 46658, 50846, 59413],
    "ftp":   [20828],
    "vnc":   [22938, 43238],
    "telnet": [24368, 34199],
    "imap":  [25068, 25139, 25904, 51544, 54693],
    "smtp":  [45342, 52498],
}

TARGET = "10.66.0.1"
CONNECT_TO = 8.0   # timeout de connect()
IO_TO = 5.0        # timeout de inactividad por recv()


# --------------------------------------------------------------------------- #
# Infraestructura de sockets
# --------------------------------------------------------------------------- #
def _make_tls_ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    try:
        c.minimum_version = ssl.TLSVersion.TLSv1      # servidores viejos
    except (ValueError, AttributeError):
        pass
    try:
        c.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return c


TLS_CTX = _make_tls_ctx()


def conn(p, tls=False):
    s = socket.create_connection((TARGET, p), timeout=CONNECT_TO)
    s.settimeout(IO_TO)
    if tls:
        s = TLS_CTX.wrap_socket(s)
    return s


def rx_until(s, done=None, total=6.0, idle=None, maxb=65536):
    """Lee hasta que done(data) sea True, el peer cierre, haya inactividad o venza 'total'.
    Devuelve (datos, cerrado). Maneja respuestas repartidas en varios segmentos TCP."""
    idle = idle or IO_TO
    end = time.monotonic() + total
    data, closed = b"", False
    while len(data) < maxb:
        left = end - time.monotonic()
        if left <= 0:
            break
        s.settimeout(min(left, idle))
        try:
            x = s.recv(4096)
        except socket.timeout:
            break
        except OSError:
            closed = True
            break
        if not x:
            closed = True
            break
        data += x
        if done and done(data):
            break
    return data, closed


def ends_line(d):
    return d.endswith(b"\n")


def code_final(d):
    """True si la última línea es una respuesta final estilo SMTP/FTP ('250 ...', no '250-...')."""
    if not d.endswith(b"\n"):
        return False
    last = d.rstrip(b"\r\n").split(b"\n")[-1]
    return bool(re.match(rb"\d{3}( |$)", last))


def plain_or_tls(p, dialog):
    """Ejecuta dialog(sock) en claro; si el puerto no dijo nada, reintenta con TLS implícito
    (IMAPS/SMTPS/FTPS pueden estar en esos puertos). dialog -> (ok, info, el_peer_hablo)."""
    notes = []
    for tls in (False, True):
        tag = "tls" if tls else "plain"
        try:
            with conn(p, tls) as s:
                ok, info, spoke = dialog(s)
        except ConnectionRefusedError:
            return False, "conexión rechazada (RST)"
        except Exception as e:
            ok, info, spoke = False, f"{type(e).__name__}: {e}", False
        if ok is not False:
            return ok, f"[{tag}] {info}"
        notes.append(f"[{tag}] {info}")
        if spoke:           # habló pero no era el protocolo: TLS no va a cambiar nada
            break
    return False, " | ".join(notes)


# --------------------------------------------------------------------------- #
# HTTP / HTTPS
# --------------------------------------------------------------------------- #
def http_get(p, tls, path):
    with conn(p, tls) as s:
        req = (f"GET {path} HTTP/1.1\r\nHost: {TARGET}\r\nUser-Agent: Mozilla/5.0\r\n"
               f"Accept: */*\r\nConnection: close\r\n\r\n")
        s.sendall(req.encode())
        d, _ = rx_until(s, None, total=8, maxb=40000)
    if not d:
        return False, "sin respuesta"
    if not d.startswith(b"HTTP/"):
        return False, f"no es HTTP: {d[:30]!r}"
    head, _, body = d.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n")[0].decode(errors="replace")
    m = re.match(r"HTTP/\S+\s+(\d{3})", status_line)
    status = int(m.group(1)) if m else 0
    t = re.sub(rb"<(script|style)\b.*?</\1>|<title>.*?</title>|<!--.*?-->", b"", body,
               flags=re.S | re.I)
    t = re.sub(rb"<[^>]+>", b"", t)
    if b"transfer-encoding: chunked" in head.lower():
        t = re.sub(rb"(?m)^[0-9a-fA-F]+\r?$", b"", t)   # quita tamaños de chunk ("0" != texto)
    t = t.strip()
    redir = 300 <= status < 400 and b"\nlocation:" in head.lower()
    return bool(t) or redir, f"{status_line[:40]} body={len(body)}B texto={len(t)}B"


def web(p, tls):
    ok1, i1 = http_get(p, tls, "/")
    rand = "/" + "".join(random.choices(string.ascii_lowercase, k=12))
    try:
        ok2, i2 = http_get(p, tls, rand)
    except Exception as e:
        ok2, i2 = False, f"{type(e).__name__}: {e}"
    return (ok1 or ok2), f"/ [{i1}] | {rand} [{i2}]"


# --------------------------------------------------------------------------- #
# SSH
# --------------------------------------------------------------------------- #
def ssh(p):
    with conn(p) as s:
        b, _ = rx_until(s, ends_line, total=5)
    if not b.startswith(b"SSH-"):
        return False, f"sin banner SSH: {b[:30]!r}"
    banner = b.split(b"\n")[0][:50]
    if not shutil.which("ssh-keyscan"):
        return True, f"banner={banner!r} (sin ssh-keyscan)"
    try:
        o = subprocess.run(["ssh-keyscan", "-T", "8", "-p", str(p), TARGET],
                           capture_output=True, text=True, timeout=15).stdout
    except subprocess.TimeoutExpired:
        return None, f"banner={banner!r} pero ssh-keyscan timeout"
    keys = [l for l in o.splitlines() if l and not l.startswith("#")]
    if keys:
        return True, f"banner={banner!r} {len(keys)} claves"
    return None, f"banner={banner!r} pero 0 claves"


# --------------------------------------------------------------------------- #
# FTP / SMTP / IMAP
# --------------------------------------------------------------------------- #
def ftp_dialog(s):
    b, _ = rx_until(s, code_final, total=5)
    if not b:
        return False, "sin banner", False
    if not b.startswith(b"220"):
        return False, f"banner no FTP: {b[:40]!r}", True
    s.sendall(b"FEAT\r\n")
    r, _ = rx_until(s, code_final, total=5)
    if re.match(rb"\d{3}", r):
        return True, f"banner={b[:30]!r} FEAT={r[:30]!r}", True
    return None, f"banner ok pero sin respuesta a FEAT: {r[:30]!r}", True


def smtp_dialog(s):
    b, _ = rx_until(s, code_final, total=5)
    if not b:
        return False, "sin banner", False
    if not b.startswith(b"220"):
        return False, f"banner no SMTP: {b[:40]!r}", True
    s.sendall(b"EHLO test.local\r\n")
    r, _ = rx_until(s, code_final, total=5)
    if re.search(rb"(?m)^250[ -]", r):
        return True, f"banner={b[:30]!r} EHLO ok", True
    s.sendall(b"HELO test.local\r\n")
    r2, _ = rx_until(s, code_final, total=5)
    if re.search(rb"(?m)^250[ -]", r2):
        return True, f"banner={b[:30]!r} HELO ok (EHLO={r[:20]!r})", True
    return False, f"EHLO={r[:30]!r} HELO={r2[:30]!r}", True


def imap_dialog(s):
    b, _ = rx_until(s, ends_line, total=5)
    if not b:
        return False, "sin banner", False
    if not re.match(rb"\* (OK|PREAUTH)", b):
        return False, f"banner no IMAP: {b[:40]!r}", True
    if b"CAPABILITY" in b.upper():
        return True, f"greeting con capability: {b[:50]!r}", True
    s.sendall(b"a1 CAPABILITY\r\n")
    r, _ = rx_until(s, lambda d: re.search(rb"(?m)^a1 (OK|NO|BAD)", d) is not None, total=5)
    if b"* CAPABILITY" in r or re.search(rb"(?m)^a1 (OK|NO|BAD)", r):
        return True, f"greet={b[:30]!r} resp={r[:40]!r}", True
    return False, f"greet={b[:30]!r} resp={r[:40]!r}", True


# --------------------------------------------------------------------------- #
# VNC
# --------------------------------------------------------------------------- #
def vnc(p):
    with conn(p) as s:
        v, _ = rx_until(s, lambda d: len(d) >= 12, total=5)
        m = re.match(rb"RFB (\d{3})\.(\d{3})\n", v)
        if not m:
            return False, f"sin versión RFB: {v[:20]!r}"
        major, minor = int(m.group(1)), int(m.group(2))
        if major > 3 or minor >= 8:
            reply, legacy = b"RFB 003.008\n", False
        elif minor >= 7:
            reply, legacy = b"RFB 003.007\n", False
        else:
            reply, legacy = b"RFB 003.003\n", True
        s.sendall(reply)
        if legacy:   # 3.3: el servidor manda 4 bytes con el tipo de seguridad
            r, _ = rx_until(s, lambda d: len(d) >= 4, total=4)
            if len(r) < 4:
                return False, f"ver={v[:12]!r} sin tipo de seguridad (raw={r.hex()})"
            return True, f"ver={v[:11]!r} sec33={int.from_bytes(r[:4], 'big')}"
        r, _ = rx_until(s, lambda d: len(d) >= 1 and (d[0] == 0 or len(d) >= 1 + d[0]), total=4)
    if not r:
        return False, f"ver={v[:11]!r} sin tipos de seguridad tras handshake"
    n = r[0]
    if n == 0:   # el servidor rechaza, pero habla VNC de verdad
        return True, f"ver={v[:11]!r} tipos=0 (rechaza: {r[1:40]!r})"
    return True, f"ver={v[:11]!r} tipos={list(r[1:1 + n])}"


# --------------------------------------------------------------------------- #
# Telnet
# --------------------------------------------------------------------------- #
IAC, DONT, DO, WONT, WILL = 255, 254, 253, 252, 251


def telnet_reply(d):
    out, i = b"", 0
    while i < len(d) - 2:
        if d[i] == IAC and d[i + 1] in (DO, WILL):
            out += bytes([IAC, WONT if d[i + 1] == DO else DONT, d[i + 2]])
            i += 3
        else:
            i += 1
    return out


def strip_iac(d):
    return re.sub(rb"\xff[\xfb-\xfe].|\xff\xfa.*?\xff\xf0|\xff.", b"", d, flags=re.S)


def telnet(p):
    with conn(p) as s:
        d, closed = rx_until(s, None, total=3, idle=1.5)
        if not d:
            if closed:
                return False, "cierra sin negociar"
            s.sendall(b"\r\n")
            d2, closed2 = rx_until(s, None, total=3, idle=1.5)
            if d2:
                return True, f"habla tras CRLF: {d2[:40]!r}"
            return (False if closed2 else None), "TCP abierto y silencio absoluto"
        s.sendall(telnet_reply(d) + b"\r\n")
        d2, closed2 = rx_until(s, None, total=3, idle=1.5)
    if strip_iac(d) or strip_iac(d2):
        return True, f"texto/prompt: {(strip_iac(d) + strip_iac(d2))[:40]!r}"
    if closed2:
        return False, "cierra tras negociación"
    return True, f"negocia IAC ({len(d)}B) y mantiene la conexión abierta"


# --------------------------------------------------------------------------- #
# Orquestación
# --------------------------------------------------------------------------- #
CHK = {
    "http":   lambda p: web(p, False),
    "https":  lambda p: web(p, True),
    "ssh":    ssh,
    "ftp":    lambda p: plain_or_tls(p, ftp_dialog),
    "imap":   lambda p: plain_or_tls(p, imap_dialog),
    "smtp":   lambda p: plain_or_tls(p, smtp_dialog),
    "vnc":    vnc,
    "telnet": telnet,
}
LABEL = {True: "VIVO", False: "MUERTO", None: "?"}


def run(item, retries, strict):
    proto, p = item
    ok, info, lat = False, "", 0
    for i in range(retries + 1):
        t0 = time.monotonic()
        try:
            ok, info = CHK[proto](p)
        except ConnectionRefusedError:
            ok, info = False, "conexión rechazada (RST)"
        except Exception as e:
            ok, info = False, f"{type(e).__name__}: {e}"
        lat = int((time.monotonic() - t0) * 1000)
        if ok is not False:
            break
        if i < retries:
            time.sleep(1)
    attempts = i + 1
    if ok is None and strict:
        ok, info = False, info + " (silencio estricto)"
    return [p, proto, LABEL[ok], attempts, lat, info]


def main():
    global TARGET
    ap = argparse.ArgumentParser()
    ap.add_argument("-t", "--target", default=TARGET)
    ap.add_argument("-w", "--workers", type=int, default=8)
    ap.add_argument("-r", "--retries", type=int, default=2, help="reintentos para los MUERTO")
    ap.add_argument("--strict-silence", action="store_true",
                    help="TCP abierto y en silencio cuenta como MUERTO")
    ap.add_argument("-o", "--out", default="filtro.csv")
    a = ap.parse_args()
    TARGET = a.target

    jobs = [(pr, p) for pr, ps in PORTS.items() for p in ps]
    with ThreadPoolExecutor(a.workers) as ex:
        res = sorted(ex.map(lambda j: run(j, a.retries, a.strict_silence), jobs))

    with open(a.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["puerto", "protocolo", "veredicto", "intentos", "latency_ms", "evidencia"])
        w.writerows(res)
    for r in res:
        print(*r, sep=" | ")
    print(f"\nVIVOS: {sum(r[2] == 'VIVO' for r in res)}  "
          f"MUERTOS: {sum(r[2] == 'MUERTO' for r in res)}  "
          f"?: {sum(r[2] == '?' for r in res)}   -> {a.out}")


if __name__ == "__main__":
    main()
