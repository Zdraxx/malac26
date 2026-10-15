from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    target: Mapped[str] = mapped_column(String(255))
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)
    status: Mapped[str] = mapped_column(String(32), default="queued")
    ports: Mapped[list["Port"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Port(Base):
    __tablename__ = "ports"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    port: Mapped[int] = mapped_column(Integer, index=True)
    status: Mapped[str] = mapped_column(String(16))
    family: Mapped[str] = mapped_column(String(32), default="unknown")
    suggested_label: Mapped[str | None] = mapped_column(String(64))
    latency_ms: Mapped[float | None]
    scan: Mapped[Scan] = relationship(back_populates="ports")
    requests: Mapped[list["RequestRecord"]] = relationship(back_populates="port_record", cascade="all, delete-orphan")
    clues: Mapped[list["Clue"]] = relationship(back_populates="port_record", cascade="all, delete-orphan")
    observations: Mapped[list["Observation"]] = relationship(back_populates="port_record", cascade="all, delete-orphan")


class RequestRecord(Base):
    __tablename__ = "requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    port_id: Mapped[int] = mapped_column(ForeignKey("ports.id"), index=True)
    method: Mapped[str] = mapped_column(String(12))
    url: Mapped[str] = mapped_column(Text)
    status: Mapped[int | None] = mapped_column(Integer)
    latency_ms: Mapped[float | None]
    size: Mapped[int] = mapped_column(Integer, default=0)
    headers_json: Mapped[str] = mapped_column(Text, default="{}")
    request_body: Mapped[str | None] = mapped_column(Text)
    response_body: Mapped[str | None] = mapped_column(Text)
    body_preview: Mapped[str | None] = mapped_column(Text)
    response_hash: Mapped[str | None] = mapped_column(String(64))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    error: Mapped[str | None] = mapped_column(Text)
    port_record: Mapped[Port] = relationship(back_populates="requests")


class Clue(Base):
    __tablename__ = "clues"
    id: Mapped[int] = mapped_column(primary_key=True)
    port_id: Mapped[int] = mapped_column(ForeignKey("ports.id"), index=True)
    tipo: Mapped[str] = mapped_column(String(64))
    valor: Mapped[str] = mapped_column(Text)
    source_url: Mapped[str | None] = mapped_column(Text)
    contexto: Mapped[str | None] = mapped_column(Text)
    port_record: Mapped[Port] = relationship(back_populates="clues")


class Observation(Base):
    __tablename__ = "observations"
    id: Mapped[int] = mapped_column(primary_key=True)
    port_id: Mapped[int] = mapped_column(ForeignKey("ports.id"), index=True)
    tipo: Mapped[str] = mapped_column(String(64))
    descripcion: Mapped[str] = mapped_column(Text)
    evidencia: Mapped[str] = mapped_column(Text)
    sugerencia: Mapped[str] = mapped_column(Text)
    port_record: Mapped[Port] = relationship(back_populates="observations")
