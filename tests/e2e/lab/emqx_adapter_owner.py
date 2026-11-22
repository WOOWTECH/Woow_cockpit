"""Current-owner bridge for this synthetic adapter harness, not product code."""
import os
import pwd
import secrets
import socket

from emqx_adapter_fixture import Fixture
from emqx_adapter_provision import Provision
from woowbackup.podman import OwnerRunner


class LabOwnerRunner(OwnerRunner):
    def __init__(self):
        super().__init__('appowner')
        if (socket.gethostname() != 'woowbk-dev-d' or self.uid == 0
                or os.getuid() != self.uid or os.geteuid() != self.uid
                or os.getgid() != self.gid or os.getegid() != self.gid
                or pwd.getpwuid(os.geteuid()).pw_name != self.owner):
            raise RuntimeError('wrong-lab-owner')

    def prefix(self):
        # Already entered through owner.sh; retain the product's env-i contract.
        return super().prefix()[4:]


class OwnerProvision(Provision):
    def __init__(self, image_id):
        self.runner = LabOwnerRunner()
        self.fixture = Fixture('woowbk-emqxlab-' + secrets.token_hex(4), 'appowner', image_id)
        self.created = []
        # Unchanged Provision.create/cleanup own all synthetic resources.


def adapter_factory(fixture, runner):
    """Use the actual product adapter with only the scoped current-owner runner."""
    from woowbackup.adapters import get_adapter

    def create(app, *, log, **kwargs):
        if app.raw != fixture.catalog() or app.owner != runner.owner:
            raise RuntimeError('unexpected-synthetic-adapter')
        cls = get_adapter(app.adapter)
        if cls is None:
            raise RuntimeError('unexpected-synthetic-adapter')
        return cls(app, runner, log, **kwargs)
    return create
