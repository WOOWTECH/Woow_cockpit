"""Bounded host-side Podman bridge to the dedicated dev-d lab."""
from pathlib import Path
from types import SimpleNamespace

from woowbackup.podman import CommandError, default_runner

OWNER = Path(__file__).resolve().parent / 'owner.sh'


class Runner:
    uid = None
    home = '/home/appowner'

    def podman(self, *args, input=None, stdout=None, timeout=120, max_output=None, check=True, abort=None):
        if stdout is not None and max_output is None:
            max_output = 512 * 1024 * 1024
        result = default_runner([str(OWNER), 'd', 'podman', *args], input=input, stdout=stdout,
                                timeout=timeout, max_output=max_output, abort=abort)
        if check and result.returncode:
            raise CommandError('synthetic podman failure', returncode=result.returncode)
        return SimpleNamespace(stdout=result.stdout, returncode=result.returncode)

    def relay(self, args, **kwargs):
        return self.podman(*args, **kwargs)


def require_names_absent(runner, resources):
    """Refuse before any creation or cleanup unless every reserved name is absent."""
    for kind, names in resources:
        for name in names:
            if runner.podman(kind, 'exists', name, check=False).returncode != 1:
                raise RuntimeError('synthetic_name_not_proven_absent')
