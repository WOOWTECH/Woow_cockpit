"""Local backup storage, index sidecars, uploads and staging (CONTRACT section 3). Owner: E1."""


class Storage:
    def __init__(self, paths):
        self.paths = paths

    def ensure_layout(self):
        """Create data/run dirs with mode 0700 (root-owned in production)."""
        raise NotImplementedError

    def new_backup_id(self, now=None):
        raise NotImplementedError

    def archive_path(self, backup_id):
        raise NotImplementedError

    def list_backups(self):
        """Index dicts (BackupMeta without key_available), newest first; ignores invalid sidecars."""
        raise NotImplementedError

    def get(self, backup_id):
        raise NotImplementedError

    def register(self, backup_id, meta):
        """Atomically write the index sidecar for an archive already in place."""
        raise NotImplementedError

    def update(self, backup_id, **fields):
        raise NotImplementedError

    def delete(self, backup_id):
        raise NotImplementedError

    def free_bytes(self):
        raise NotImplementedError

    def staging_dir(self, job_id):
        """Create and return an empty 0700 staging directory for a job."""
        raise NotImplementedError

    def remove_staging(self, job_id):
        raise NotImplementedError

    def begin_upload(self, filename, size):
        """Space check and placeholder; returns {'upload_id', 'path', 'max_size'}."""
        raise NotImplementedError

    def finish_upload(self, upload_id):
        """Validate the written file and register it as type 'uploaded'; returns BackupMeta."""
        raise NotImplementedError

    def abort_upload(self, upload_id):
        raise NotImplementedError

    def cleanup_uploads(self, max_age_seconds=86400):
        raise NotImplementedError

    def download_info(self, backup_id):
        raise NotImplementedError
