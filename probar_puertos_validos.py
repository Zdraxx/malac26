import socket, ssl, re, subprocess, csv
from concurrent.futures import ThreadPoolExecutor
T = "10.66.0.1"
P = {
 "http":  [43989,55099,57144,59646],
 "https": [20749,30259,31893,36681,37076,38250,39051,41766,42107,44965,
           49301,51315,51535,51598,53968,54181,55582,55794],
 "ssh":   [29095,41199,45293,46658,50846,59413],
 "ftp":   [20828], "vnc": [22938,43238], "telnet": [24368,34199],
 "imap":  [25068,25139,25904,51544,54693], "smtp": [45342,52498],
}
def conn(p):
    s = socket.create_connection((T, p), timeout=8); s.settimeout(5); return s
def rx(s, n=4096):
    try: return s.recv(n)
    except socket.timeout: return None      # abierto pero en silencio
    except OSError: return b""              # cierre/reset
def web(p, tls):
    s = conn(p)
    if tls:
        c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
        s = c.wrap_socket(s)
    s.sendall(f"GET / HTTP/1.1\r\nHost: {T}\r\nConnection: close\r\n\r\n".encode())
    d = b""
    while len(d) < 20000:
        x = rx(s)
        if not x: break
        d += x
    if not d: return False, "sin respuesta"
    head, _, body = d.partition(b"\r\n\r\n")
    t = re.sub(rb"<(script|style).*?</\1>|<title>.*?</title>", b"", body, flags=re.S|re.I)
    t = re.sub(rb"<[^>]+>", b"", t).strip()
    redir = b"\nlocation:" in head.lower()
    return bool(t) or redir, f"{head.split(b'\r\n')[0].decode(errors='replace')} body={len(body)}B texto={len(t)}B"
def ssh(p):
    o = subprocess.run(["ssh-keyscan","-T","8","-p",str(p),T], capture_output=True, text=True).stdout
    k = [l for l in o.splitlines() if not l.startswith("#")]
    return bool(k), f"{len(k)} claves"
def line(p, cmd, ok):
    s = conn(p); b = rx(s)
    if not b: return False, "sin banner"
    s.sendall(cmd); r = rx(s)
    return bool(r) and r.startswith(ok), f"banner={b[:30]!r} resp={(r or b'')[:30]!r}"
def vnc(p):
    s = conn(p); rx(s); s.sendall(b"RFB 003.008\n"); r = rx(s)
    return bool(r) and r[0] > 0, f"resp={(r or b'').hex()}"
def telnet(p):
    s = conn(p)
    if not rx(s): return False, "sin negociación"
    s.sendall(bytes([255,252,24,255,253,1,255,253,3])); r = rx(s)
    return (None if r is None else bool(r)), f"resp={(r or b'')[:40]!r}"
CHK = {"http": lambda p: web(p,False), "https": lambda p: web(p,True), "ssh": ssh,
 "ftp": lambda p: line(p,b"FEAT\r\n",b"211"), "imap": lambda p: line(p,b"a1 CAPABILITY\r\n",b"* CAPABILITY"),
 "smtp": lambda p: line(p,b"EHLO test.local\r\n",b"250"), "vnc": vnc, "telnet": telnet}
def run(item):
    proto, p = item
    try: ok, info = CHK[proto](p)
    except Exception as e: ok, info = False, f"error: {e}"
    return p, proto, {True:"VIVO", False:"MUERTO", None:"?"}[ok], info
jobs = [(pr, p) for pr, ps in P.items() for p in ps]
with ThreadPoolExecutor(8) as ex: res = sorted(ex.map(run, jobs))
with open("filtro.csv","w",newline="") as f: csv.writer(f).writerows(res)
for r in res: print(*r, sep=" | ")
print("\nVIVOS:", sum(r[2]=="VIVO" for r in res), " MUERTOS:", sum(r[2]=="MUERTO" for r in res))