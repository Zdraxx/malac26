"""Prueba rutas conversacionales genéricas sin inferir que exista una IA."""

from . import Probe, probes_for

PROBES: list[Probe] = probes_for("generic")
