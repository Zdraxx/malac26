"""Prueba health, configuración, login y recuperación de contraseña de Grafana."""

from . import Probe, probes_for

PROBES: list[Probe] = probes_for("grafana")
