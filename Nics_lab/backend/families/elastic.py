"""Prueba APIs de Elasticsearch: salud, índices, mapping, búsqueda y settings."""

from . import Probe, probes_for

PROBES: list[Probe] = probes_for("elastic")
