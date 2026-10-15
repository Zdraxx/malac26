"""Prueba APIs DSM/Synology, incluyendo parámetros inválidos y login falso."""

from . import Probe, probes_for

PROBES: list[Probe] = probes_for("synology")
