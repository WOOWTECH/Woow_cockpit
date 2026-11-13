"""Shared error type. Frozen by the coordinator; see docs/backup/CONTRACT.md section 7."""

CODES = frozenset({
    'invalid-request', 'not-found', 'busy', 'key-required', 'wrong-key', 'no-device-key',
    'not-a-backup', 'unsupported-format', 'corrupt-archive', 'invalid-manifest', 'limit-exceeded',
    'insufficient-space', 'incompatible', 'app-not-in-catalog', 'owner-missing', 'not-deployed',
    'permission-denied', 'not-cancellable', 'job-failed', 'internal-error',
})


class BackupError(Exception):
    """Expected failure with a stable code and a Traditional Chinese message for the UI.

    Never put secret or key material into `message` or `details`.
    """

    def __init__(self, code, message, **details):
        if code not in CODES:
            raise ValueError(f'unknown error code: {code}')
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details

    def as_dict(self):
        return {'code': self.code, 'message': self.message, 'details': self.details}
