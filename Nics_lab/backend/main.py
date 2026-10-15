import asyncio
import ipaddress
import json
import socket
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, PlainTextResponse
from loguru import logger
from sqlalchemy import desc
from sqlalchemy.orm import Session, selectinload

from .collector import active_collections, collect_port
from .db import SessionLocal, get_db, init_db
from .events import event_hub
from .models import Port, Scan
from .parser import parse_ports
from .report import export_port, port_markdown
from .scanner import run_scan
from .schemas import CollectResponse, ScanRequest


def validate_target(target: str) -> str:
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        if len(target) > 255 or any(not label or len(label) > 63 for label in target.split(".")):
            raise ValueError("target must be a host or IP")
        try:
            socket.getaddrinfo(target, None)
        except socket.gaierror as exc:
            raise ValueError("target could not be resolved") from exc
        return target


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="Recon CTF", version="0.1.0", lifespan=lifespan)
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


@app.get("/", include_in_schema=False)
def frontend_index():
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/ui/{asset}", include_in_schema=False)
def frontend_asset(asset: str):
    path = (FRONTEND_DIR / asset).resolve()
    if path.parent != FRONTEND_DIR or not path.is_file():
        raise HTTPException(404, "asset not found")
    return FileResponse(path)


@app.post("/api/scan", status_code=202)
async def start_scan(payload: ScanRequest, db: Session = Depends(get_db)):
    try:
        target = validate_target(payload.target)
        ports = parse_ports(payload.ports)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    scan = Scan(target=target, status="queued")
    scan.ports = [Port(port=port, status="queued", family="unknown") for port in ports]
    db.add(scan)
    db.commit()
    db.refresh(scan)
    asyncio.create_task(run_scan(scan.id, target, ports, payload.concurrency, SessionLocal))
    return {"id": scan.id, "target": target, "ports": ports, "status": scan.status}


@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).options(selectinload(Scan.ports)).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(404, "scan not found")
    return {"id": scan.id, "target": scan.target, "status": scan.status, "started_at": scan.started_at, "finished_at": scan.finished_at, "ports": [{"port": p.port, "status": p.status, "latency_ms": p.latency_ms, "family": p.family} for p in scan.ports]}


@app.get("/api/ports")
def list_ports(db: Session = Depends(get_db)):
    ports = db.query(Port).order_by(desc(Port.id)).all()
    return [{"port": p.port, "status": p.status, "family": p.family, "suggested_label": p.suggested_label, "latency_ms": p.latency_ms} for p in ports]


def latest_port(db: Session, port_number: int) -> Port:
    port = db.query(Port).options(selectinload(Port.requests), selectinload(Port.clues), selectinload(Port.observations)).filter_by(port=port_number).order_by(desc(Port.id)).first()
    if not port:
        raise HTTPException(404, "port not found")
    return port


@app.post("/api/collect/{port_number}", response_model=CollectResponse, status_code=202)
async def collect(port_number: int, db: Session = Depends(get_db)):
    port = latest_port(db, port_number)
    if port.status != "open":
        raise HTTPException(409, "only open ports can be collected")
    if port.id in active_collections:
        raise HTTPException(409, "collection already running for this port")
    scan = db.get(Scan, port.scan_id)
    asyncio.create_task(collect_port(port.id, scan.id, scan.target, SessionLocal))
    return CollectResponse(port=port.port, status="queued", family=port.family)


@app.get("/api/port/{port_number}")
def port_detail(port_number: int, db: Session = Depends(get_db)):
    return export_port(db, latest_port(db, port_number))


@app.get("/api/port/{port_number}/requests")
def port_requests(port_number: int, db: Session = Depends(get_db)):
    return latest_port(db, port_number).requests


@app.get("/api/port/{port_number}/clues")
def port_clues(port_number: int, db: Session = Depends(get_db)):
    return latest_port(db, port_number).clues


@app.get("/api/port/{port_number}/observations")
def port_observations(port_number: int, db: Session = Depends(get_db)):
    return latest_port(db, port_number).observations


@app.get("/api/port/{port_number}/report", response_class=PlainTextResponse)
def port_report(port_number: int, db: Session = Depends(get_db)):
    return port_markdown(latest_port(db, port_number))


@app.get("/api/export")
def export_all(db: Session = Depends(get_db)):
    ports = db.query(Port).options(selectinload(Port.requests), selectinload(Port.clues), selectinload(Port.observations)).all()
    return {"ports": [export_port(db, p) for p in ports]}


@app.websocket("/ws/scan/{scan_id}")
async def scan_events(websocket: WebSocket, scan_id: int):
    await websocket.accept()
    queue = event_hub.subscribe(scan_id)
    try:
        while True:
            await websocket.send_text(json.dumps(await queue.get()))
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    finally:
        event_hub.unsubscribe(scan_id, queue)
