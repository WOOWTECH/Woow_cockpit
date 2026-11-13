"""WOOWTECH Cockpit backup engine for rootless Podman Quadlet applications."""
from pathlib import Path

__all__ = ['version']


def version(lib_root=None):
    """Return the installed release string, or 'dev' in a source checkout."""
    root = Path(lib_root) if lib_root else Path(__file__).resolve().parent.parent
    for candidate in (root / 'VERSION', root.parent / 'VERSION'):
        try:
            return candidate.read_text().strip() or 'dev'
        except OSError:
            continue
    return 'dev'
