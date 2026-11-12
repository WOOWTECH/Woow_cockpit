"""Job records, systemd-run launcher, lock and recovery (CONTRACT section 8). Owner: E2."""


class JobStore:
    def __init__(self, paths):
        self.paths = paths


def start_job(paths, job_type, params, request_id, *, key_text=None, launcher=None):
    raise NotImplementedError


def run_job(paths, job_id):
    raise NotImplementedError


def recover_interrupted(paths, *, unit_active=None):
    raise NotImplementedError
