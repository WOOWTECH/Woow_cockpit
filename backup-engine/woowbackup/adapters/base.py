"""Adapter interface (CONTRACT section 9). Owner: E2."""


class Adapter:
    name = 'base'
    version = 1

    def __init__(self, app, runner, log):
        self.app, self.runner, self.log = app, runner, log

    def probe(self):
        """{'deployed': bool, 'state': str, 'units': [{'name','active'}], 'problems': [str]}"""
        raise NotImplementedError

    def estimate_bytes(self):
        raise NotImplementedError

    def backup(self, staging_dir, *, include_images):
        """Return (manifest_app_dict, [archive.Entry]). Writers are always restarted."""
        raise NotImplementedError

    def preflight(self, app_manifest, *, mode):
        """List of Check dicts for restoring this app_manifest here."""
        raise NotImplementedError

    def restore(self, app_manifest, extracted_dir, *, mode):
        """Perform the restore; raise BackupError on failure (caller handles rollback)."""
        raise NotImplementedError

    def remove_fresh(self):
        """Undo a failed fresh deployment (units, quadlet files, volumes, secrets, config)."""
        raise NotImplementedError

    def health(self):
        raise NotImplementedError

    def verify_snapshot(self):
        raise NotImplementedError
