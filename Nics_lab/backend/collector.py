import asyncio
import hashlib
import json
import re
import statistics
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx
from loguru import logger
from sqlalchemy.orm import Session

from .config import settings
from .events import event_hub
from .families import Probe, probes_for
from .models import Clue, Observation, Port, RequestRecord

FAMILIES = ("elastic", "synology", "wordpress", "grafana", "nextcloud", "generic")
HEADER_NAMES = ("server", "x-powered-by", "link", "content-type", "set-cookie", "x-elastic-product", "content-security-policy", "x-frame-options", "last-modified", "etag", "date")
active_collections: set[int] = set()


def detect_family(body: str, headers: dict[str, str], extra_bodies: list[str] | None = None) -> str:
    text = "\n".join([body, *(extra_bodies or [])]).lower()
    link = headers.get("link", "").lower()
    compact = re.sub(r"\s+", "", text)
    if headers.get("x-elastic-product") or '"tagline":"youknow,forsearch' in compact:
        return "elastic"
    if "synology.com" in text or "/webman/" in text or "/webapi/" in text:
        return "synology"
    if "/wp-json/" in link or "wp-content" in text:
        return "wordpress"
    if "grafana" in text:
        return "grafana"
    if re.search(r'"productname"\s*:\s*"nextcloud"', text.replace("'", '"')):
        return "nextcloud"
    return "generic"


def _headers(response: httpx.Response) -> dict[str, str]:
    return {name: response.headers.get(name, "") for name in HEADER_NAMES if response.headers.get(name) is not None}


async def _request(client: httpx.AsyncClient, probe: Probe, base: str) -> dict:
    started = time.perf_counter()
    url = urljoin(base, probe.path)
    try:
        response = await client.request(probe.method, url, content=probe.body, headers=probe.headers)
        body = response.content[: settings.max_body_bytes]
        return {"method": probe.method, "url": str(response.url), "status": response.status_code, "latency_ms": (time.perf_counter() - started) * 1000, "size": len(response.content), "headers": _headers(response), "request_body": probe.body, "body": body.decode("utf-8", errors="replace"), "hash": hashlib.sha256(body).hexdigest(), "error": None}
    except Exception as exc:
        return {"method": probe.method, "url": url, "status": None, "latency_ms": (time.perf_counter() - started) * 1000, "size": 0, "headers": {}, "request_body": probe.body, "body": "", "hash": None, "error": f"{type(exc).__name__}: {exc}"}


def _save_request(db: Session, port: Port, result: dict) -> RequestRecord:
    record = RequestRecord(port_id=port.id, method=result["method"], url=result["url"], status=result["status"], latency_ms=result["latency_ms"], size=result["size"], headers_json=json.dumps(result["headers"]), request_body=result["request_body"], response_body=result["body"], body_preview=result["body"][:1000], response_hash=result["hash"], error=result["error"], timestamp=datetime.utcnow())
    db.add(record)
    db.commit()
    return record


def _observation(db: Session, port: Port, tipo: str, descripcion: str, evidencia: str, sugerencia: str) -> None:
    db.add(Observation(port_id=port.id, tipo=tipo, descripcion=descripcion, evidencia=evidencia, sugerencia=sugerencia))
    db.commit()


async def _crawl(client: httpx.AsyncClient, port: Port, base: str, db: Session, scan_id: int) -> None:
    seen = {base}
    queue = deque([(base, 0)])
    while queue:
        url, depth = queue.popleft()
        if depth > settings.crawl_depth:
            continue
        result = await _request(client, Probe("GET", url), "")
        if url != base:
            _save_request(db, port, result)
        for candidate in re.findall(r"""(?:href|src)=["']([^"']+)""", result["body"], re.I):
            absolute = urljoin(url, candidate)
            parsed = urlparse(absolute)
            if parsed.netloc == urlparse(base).netloc and absolute not in seen and depth < settings.crawl_depth:
                seen.add(absolute)
                queue.append((absolute, depth + 1))
                if re.search(r"\.(?:doc|pdf|xlsx|zip|json|sql|bak|env|git)(?:$|\?)", absolute, re.I):
                    try:
                        loot = settings.loot_dir / str(port.port)
                        loot.mkdir(parents=True, exist_ok=True)
                        filename = Path(urlparse(absolute).path).name or "download"
                        response = await client.get(absolute)
                        (loot / filename).write_bytes(response.content[: settings.max_body_bytes])
                    except Exception as exc:
                        _observation(db, port, "loot_error", f"No se pudo descargar {absolute}", str(exc), "Revisar el recurso manualmente.")
        await _extract_clues(db, port, result["body"], url)
        await event_hub.publish(scan_id, {"type": "request", "payload": {"port": port.port, "url": url, "status": result["status"]}})


async def _extract_clues(db: Session, port: Port, body: str, source_url: str) -> None:
    patterns = {
        "subdomain": r"\b(?:[a-z0-9-]+\.)+local\b",
        "domain": r"\b(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}\b",
        "host_port": r"\b(?:10\.66\.0\.1|localhost):\d{1,5}\b",
        "email": r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        "file": r"\b[\w./-]+\.(?:doc|pdf|xlsx|zip|json|sql|bak|env|git)\b",
        "keyword": r"\b(?:password|token|api[_-]?key|secret|admin|debug)\b",
        "comment": r"<!--(.*?)-->",
    }
    for clue_type, pattern in patterns.items():
        for value in dict.fromkeys(re.findall(pattern, body, re.I | re.S)):
            value = value.strip()
            db.add(Clue(port_id=port.id, tipo=clue_type, valor=value, source_url=source_url, contexto=body[max(0, body.find(value)-100):body.find(value)+len(value)+100]))
    db.commit()


async def collect_port(port_id: int, scan_id: int, target: str, session_factory) -> None:
    if port_id in active_collections:
        return
    active_collections.add(port_id)
    db: Session = session_factory()
    port = db.get(Port, port_id)
    if not port:
        db.close()
        return
    try:
        timeout = httpx.Timeout(settings.request_timeout_seconds)
        async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
            results: list[dict] = []
            for scheme in ("http", "https"):
                base = f"{scheme}://{target}:{port.port}"
                for probe in (Probe("GET", "/"), Probe("HEAD", "/")):
                    result = await _request(client, probe, base)
                    _save_request(db, port, result)
                    results.append(result)
                    await event_hub.publish(scan_id, {"type": "request", "payload": {"port": port.port, "url": result["url"], "status": result["status"]}})
            first = next((item for item in results if item["status"] is not None and item["method"] == "GET"), results[0])
            active_base = f"{urlparse(first['url']).scheme}://{target}:{port.port}"
            family = detect_family(first["body"], first["headers"])
            port.family = family
            db.commit()
            not_found = await _request(client, Probe("GET", f"/pepito-{hashlib.sha1(str(time.time()).encode()).hexdigest()[:10]}"), active_base)
            _save_request(db, port, not_found)
            if first["status"] is not None and not_found["status"] is not None:
                _observation(
                    db,
                    port,
                    "root_vs_404",
                    "Se comparó la respuesta raíz con una ruta aleatoria inexistente.",
                    json.dumps(
                        {
                            "root_status": first["status"],
                            "root_size": first["size"],
                            "root_hash": first["hash"],
                            "not_found_status": not_found["status"],
                            "not_found_size": not_found["size"],
                            "not_found_hash": not_found["hash"],
                            "same_body": first["hash"] == not_found["hash"],
                        }
                    ),
                    "Revisar si el enrutador devuelve una plantilla genérica para cualquier ruta.",
                )
            for probe in probes_for(family):
                for _ in range(settings.behavior_samples):
                    result = await _request(client, probe, active_base)
                    _save_request(db, port, result)
                    if result["error"]:
                        _observation(db, port, "probe_error", f"Falló {probe.method} {probe.path}", result["error"], "Revisar conectividad, TLS o el comportamiento del servicio.")
                    await event_hub.publish(scan_id, {"type": "request", "payload": {"port": port.port, "url": result["url"], "status": result["status"]}})
            await _crawl(client, port, f"{active_base}/", db, scan_id)
            request_rows = db.query(RequestRecord).filter_by(port_id=port.id).all()
            for url in {row.url for row in request_rows}:
                samples = [row.latency_ms for row in request_rows if row.url == url and row.latency_ms is not None]
                if len(samples) > 1:
                    avg = statistics.mean(samples)
                    std = statistics.stdev(samples) if len(samples) > 1 else 0
                    _observation(db, port, "latencia", f"{len(samples)} muestras para {url}", json.dumps({"min": min(samples), "max": max(samples), "avg": avg, "std": std}), "Revisar si la latencia es estable o artificialmente clavada.")
            by_endpoint: dict[tuple[str, str, str | None], list[RequestRecord]] = {}
            for row in request_rows:
                if row.response_hash:
                    by_endpoint.setdefault((row.method, row.url, row.request_body), []).append(row)
            identical = [rows for rows in by_endpoint.values() if len(rows) >= 2 and len({row.response_hash for row in rows}) == 1]
            if identical:
                _observation(db, port, "respuestas_identicas", "Un mismo endpoint produjo el mismo cuerpo en llamadas repetidas.", identical[0][0].response_hash or "", "Revisar manualmente si el backend es determinista.")
            varying = [rows for rows in by_endpoint.values() if len(rows) >= 2 and len({row.response_hash for row in rows}) > 1]
            if varying:
                _observation(db, port, "respuestas_varian", "Un mismo endpoint produjo cuerpos distintos en llamadas repetidas.", json.dumps({"endpoints": [rows[0].url for rows in varying], "hashes": [list({row.response_hash for row in rows}) for rows in varying]}), "Revisar si la variación es dinámica, aleatoria o generada por un modelo.")
            port.suggested_label = "revisar_observaciones"
            db.commit()
    except Exception as exc:
        logger.exception("collection failed for port {}", port.port)
        _observation(db, port, "collector_error", "La recolección terminó con error.", f"{type(exc).__name__}: {exc}", "Revisar el error y repetir la recolección.")
    finally:
        db.close()
        active_collections.discard(port_id)
