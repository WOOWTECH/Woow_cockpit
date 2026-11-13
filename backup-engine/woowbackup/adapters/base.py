"""Adapter interface (CONTRACT section 9). Owner: E2.

Adapters are trusted code shipped with the engine and selected by the local catalog entry;
archives can never supply adapter code. `phase(id)` and `checkpoint()` are optional hooks the
flows use to report job phases and honour cancellation.
"""


class Adapter:
    name = 'base'
    version = 1

    def __init__(self, app, runner, log, *, phase=None, checkpoint=None, writers_hook=None, imported_hook=None):
        self.app, self.runner, self.log = app, runner, log
        self.phase = phase or (lambda phase_id: None)
        self.checkpoint = checkpoint or (lambda: None)
        # Called with the writer units a backup is about to stop, and with [] once they run again,
        # so an interrupted job can be recovered (see jobs.recover_interrupted).
        self.writers_hook = writers_hook or (lambda units: None)
        # Called by restore() once the app's data import finished, right before its units may start: from then on
        # a fresh deployment is no longer "unfinished" for the recovery of a dead job (review finding HD-04).
        self.imported_hook = imported_hook or (lambda: None)
        # Set once restore() has changed anything on the system; the caller then rolls back.
        self.destructive_started = False
        # Seconds writers were stopped during the last backup().
        self.last_downtime = 0.0
        # zh-TW notes about what a restore could not keep (e.g. setuid bits); flows puts them in the result.
        self.warnings = []
        # The job this adapter works for (set by flows); names the restore's host-directory siblings.
        self.job_id = None

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

    def preflight(self, app_manifest, *, mode, entry_sizes=None, extracted_dir=None):
        """List of Check dicts for restoring this app_manifest here (`extracted_dir`: also check nested data)."""
        raise NotImplementedError

    def restore(self, app_manifest, extracted_dir, *, mode, rollback=False, unchecked_databases_ok=False,
                replaced_dirs=()):
        """Perform the restore; raise BackupError on failure (caller handles rollback).

        `rollback=True` restores the pre-restore safety backup after a failure: nothing may be downloaded.
        `unchecked_databases_ok=True`: the restore runs without a safety backup (explicitly accepted), so data
        that cannot be inspected may be replaced.
        """
        raise NotImplementedError

    def start_units(self, units):
        """Start the given units of this app in catalog order; returns the units that failed."""
        return list(units)

    def remove_fresh(self):
        """Undo a failed fresh deployment (units, quadlet files, volumes, secrets, config)."""
        raise NotImplementedError

    def fresh_in_use(self):
        """Units showing that a fresh deployment may already hold new data ([] = unfinished, may be removed)."""
        return []

    # Host directories (catalog `data_dirs`); adapters without them keep these defaults.
    def finish_dirs(self):
        """Delete the directory copies a restore moved aside once the job succeeded (for a rollback adapter: once the
        rollback was verified), never the only copy of the previous content; returns zh-TW notes."""
        return []

    def discard_dirs(self):
        """After a failure: undo an unfinished directory step (new copy being written); returns zh-TW problems."""
        return []

    def dir_leftovers(self):
        """zh-TW notes naming the directory copies this job left (after a failed rollback)."""
        return []

    def recover_dirs(self):
        """Recovery of the dead job `self.job_id`: settle the directory copies it left; returns zh-TW notes."""
        return []

    def health(self):
        raise NotImplementedError

    def health_hint(self):
        """Quick health problem text for the status page, or None (default: not checked)."""
        return None

    def verify_snapshot(self):
        raise NotImplementedError
