"""Prueba status, capacidades OCS, login y webfinger de Nextcloud."""

from . import Probe, probes_for

PROBES: list[Probe] = probes_for("nextcloud")
