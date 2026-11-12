"""Quadlet + PostgreSQL + named volumes + Podman secrets + config files. Owner: E2."""
from .base import Adapter


class QuadletPostgresAdapter(Adapter):
    name = 'quadlet-postgres'
    version = 1
