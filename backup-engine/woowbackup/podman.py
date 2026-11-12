"""Run commands as an application owner (rootless Podman + user systemd). Owner: E2.

Root never opens paths inside the owner's home: file I/O there is executed as the owner.
"""


class OwnerRunner:
    def __init__(self, owner, *, runner=None):
        """`runner` injects a fake subprocess executor in tests."""
        self.owner = owner

    def run(self, argv, *, input=None, stdout=None, timeout=300, check=True):
        raise NotImplementedError

    def podman(self, *args, **kwargs):
        raise NotImplementedError

    def systemctl(self, *args, **kwargs):
        raise NotImplementedError

    def read_file(self, rel_path, max_bytes=16 * 1024 * 1024):
        raise NotImplementedError

    def write_file(self, rel_path, data, mode):
        raise NotImplementedError

    def remove_file(self, rel_path):
        raise NotImplementedError
