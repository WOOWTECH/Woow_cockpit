"""Filesystem layout (CONTRACT section 3). Tests pass `base` to relocate everything."""
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Paths:
    base: Path | None = None

    def _p(self, real):
        return Path(real) if self.base is None else Path(self.base) / str(real).lstrip('/')

    @property
    def data(self):
        return self._p('/var/lib/woowtech-backup')

    @property
    def archives(self):
        return self.data / 'archives'

    @property
    def uploads(self):
        return self.data / 'uploads'

    @property
    def staging(self):
        return self.data / 'staging'

    @property
    def jobs(self):
        return self.data / 'jobs'

    @property
    def requests(self):
        return self.data / 'requests.json'

    @property
    def run(self):
        return self._p('/run/woowtech-backup')

    @property
    def lock(self):
        return self.run / 'engine.lock'

    @property
    def config(self):
        return self._p('/etc/woowtech-cockpit/backup')

    @property
    def catalog(self):
        return self.config / 'apps'

    @property
    def keys(self):
        return self.config / 'keys'

    @property
    def templates(self):
        return self._p('/usr/local/share/woowtech-cockpit-backup/catalog')

    @property
    def lib(self):
        return self._p('/usr/local/lib/woowtech-cockpit-backup')

    @property
    def helper(self):
        return self._p('/usr/local/libexec/woowtech-cockpit-backup')

    # Reserve kept free on the data filesystem by every space check.
    reserve_bytes: int = 512 * 1024 * 1024
