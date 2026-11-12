"""`.woowbackup` v1 format (CONTRACT section 5). Owner: E1 engine-core.

Outer header + age(X25519) ciphertext of zstd(PAX tar). `manifest.json` is the first member.
All readers treat the input as hostile until age and zstd exit 0 and every entry is verified.
"""
from dataclasses import dataclass
from pathlib import Path

MAGIC = b'WOOWTECH-BACKUP/1\n'
FORMAT = 1
MAX_HEADER = 4096
MAX_MANIFEST = 1024 * 1024
MAX_MEMBERS = 4000


@dataclass(frozen=True)
class Entry:
    """A file to add. `path` is the archive member name, `source` a local regular file."""
    path: str
    source: Path
    size: int
    sha256: str


def read_header(path):
    """Return the validated outer header dict; raise BackupError(not-a-backup|unsupported-format|corrupt-archive)."""
    raise NotImplementedError


def write_archive(dest, header, manifest, entries, recipient, *, tmp_dir, progress=None):
    """Write atomically (temp in `tmp_dir` on the same filesystem, fsync, rename to `dest`).

    `manifest['entries']` is (re)built from `entries` in order. Returns {'size', 'sha256'} of the file.
    `progress(done_bytes, total_bytes)` is optional.
    """
    raise NotImplementedError


def read_manifest(path, identity_files, *, limits=None):
    """Decrypt only as far as needed to return the validated manifest dict (no extraction)."""
    raise NotImplementedError


def verify_archive(path, identity_files, *, progress=None, limits=None):
    """Full streaming pass. Returns {'manifest', 'entries', 'bytes'}; raises BackupError on any defect."""
    raise NotImplementedError


def extract_archive(path, identity_files, dest_dir, *, progress=None, limits=None):
    """Safely extract into empty root-only `dest_dir`; returns the manifest. Partial output is the caller's to delete."""
    raise NotImplementedError


def validate_manifest(manifest):
    """Strict schema validation; returns the manifest or raises BackupError('invalid-manifest')."""
    raise NotImplementedError
