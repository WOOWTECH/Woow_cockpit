"""Trusted application catalog (CONTRACT section 4). Owner: E2 engine-ops."""
from dataclasses import dataclass, field


@dataclass(frozen=True)
class App:
    id: str
    name: str
    description: str
    owner: str
    adapter: str
    quadlet_files: tuple
    template_dir: str | None
    units: tuple
    writer_units: tuple
    postgres: tuple
    volumes: tuple
    secrets: tuple
    config_files: tuple
    health: tuple
    verify: tuple
    sha256: str
    raw: dict = field(compare=False, repr=False, default_factory=dict)


def validate_entry(data, *, paths):
    """Strictly validate one catalog dict; return App or raise BackupError('invalid-request')."""
    raise NotImplementedError


def load_catalog(paths):
    """Load all root-owned, non-writable, non-symlink entries; returns {id: App}. Invalid files are reported, not loaded."""
    raise NotImplementedError
