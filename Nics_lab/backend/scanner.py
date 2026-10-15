import asyncio
import time
from datetime import datetime

from loguru import logger
from sqlalchemy.orm import Session

from .events import event_hub
from .models import Port, Scan


async def probe_tcp(target: str, port: int) -> tuple[str, float]:
    started = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout=3)
        writer.close()
        await writer.wait_closed()
        return "open", (time.perf_counter() - started) * 1000
    except asyncio.TimeoutError:
        return "filtered", (time.perf_counter() - started) * 1000
    except (ConnectionRefusedError, OSError):
        return "closed", (time.perf_counter() - started) * 1000


async def run_scan(scan_id: int, target: str, ports: list[int], concurrency: int, session_factory) -> None:
    db: Session = session_factory()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return
        scan.status = "running"
        db.commit()
        semaphore = asyncio.Semaphore(concurrency)

        async def run(port_record: Port) -> None:
            async with semaphore:
                status, latency = await probe_tcp(target, port_record.port)
                port_record.status = status
                port_record.latency_ms = latency
                db.commit()
                await event_hub.publish(scan_id, {"type": "port", "payload": {"port": port_record.port, "status": status, "latency_ms": latency}})

        await asyncio.gather(*(run(port_record) for port_record in scan.ports))
        scan.status = "finished"
        scan.finished_at = datetime.utcnow()
        db.commit()
    except Exception:
        logger.exception("scan {} failed", scan_id)
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = "failed"
            scan.finished_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()

