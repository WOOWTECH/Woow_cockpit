"""Adapter interface (CONTRACT section 9). Owner: E2.

Adapters are trusted code shipped with the engine and selected by the local catalog entry;
archives can never supply adapter code. `phase(id)` and `checkpoint()` are optional hooks the
flows use to report job phases and honour cancellation.
"""


class Adapter:
    name = 'base'
    version = 1

    def __init__(self, app, runner, log, *, phase=None, checkpoint=None, writers_hook=None):
        self.app, self.runner, self.log = app, runner, log
        self.phase = phase or (lambda phase_id: None)
        self.checkpoint = checkpoint or (lambda: None)
        # Called with the writer units a backup is about to stop, and with [] once they run again,
        # so an interrupted job can be recovered (see jobs.recover_interrupted).
        self.writers_hook = writers_hook or (lambda units: None)
        # Set once restore() has changed anything on the system; the caller then rolls back.
        self.destructive_started = False
        # Seconds writers were stopped during the last backup().
        self.last_downtime = 0.0

    def probe(self):
        """{'deployed': bool, 'state': str, 'units': [{'name','active'}], 'problems': [str]}"""
        raise NotImplementedError

    def detect_mode(self):
        """'inplace' when deployed, 'fresh' when nothing is deployed; raise BackupError otherwise."""
        raise NotImplementedError

    def ensure_databases_running(self):
        """Start stopped database units so a safety backup can be dumped; returns the units started."""
        return []

    def estimate_bytes(self, *, include_images=False):
        raise NotImplementedError

    def backup(self, staging_dir, *, include_images):
        """Return (manifest_app_dict, [archive.Entry]). Writers are always restarted."""
        raise NotImplementedError

    def preflight(self, app_manifest, *, mode, entry_sizes=None):
        """List of Check dicts for restoring this app_manifest here."""
        raise NotImplementedError

    def restore(self, app_manifest, extracted_dir, *, mode):
        """Perform the restore; raise BackupError on failure (caller handles rollback)."""
        raise NotImplementedError

    def start_units(self, units):
        """Start the given units of this app in catalog order; returns the units that failed."""
        return list(units)

    def remove_fresh(self):
        """Undo a failed fresh deployment (units, quadlet files, volumes, secrets, config)."""
        raise NotImplementedError

    def health(self):
        raise NotImplementedError

    def verify_snapshot(self):
        raise NotImplementedError
