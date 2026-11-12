"""age X25519 key management and the emergency kit (CONTRACT sections 1, 5, 7). Owner: E1."""
from dataclasses import dataclass


@dataclass(frozen=True)
class KeyInfo:
    key_id: str
    recipient: str
    path: object  # pathlib.Path of the identity file (0600)
    kind: str  # 'device' | 'imported'
    created: str
    kit_confirmed: bool = False


def key_id_for(recipient):
    """sha256(recipient)[:16] upper-case grouped XXXX-XXXX-XXXX-XXXX."""
    raise NotImplementedError


class KeyStore:
    def __init__(self, paths):
        self.paths = paths

    def device_key(self):
        """Current encryption KeyInfo or None."""
        raise NotImplementedError

    def ensure_device_key(self):
        """Return (KeyInfo, created_bool); generates with age-keygen when missing."""
        raise NotImplementedError

    def identities(self):
        """All KeyInfo usable for decryption (device first)."""
        raise NotImplementedError

    def find(self, key_id):
        raise NotImplementedError

    def import_key(self, secret_text):
        """Validate an AGE-SECRET-KEY-1… string, store as imported identity, return KeyInfo."""
        raise NotImplementedError

    def kit_text(self):
        """zh-TW emergency kit text containing key id, secret key and restore instructions."""
        raise NotImplementedError

    def confirm_kit(self, key_id):
        raise NotImplementedError

    def temp_identity(self, secret_text, name):
        """Context manager: write a validated secret key to run/<name> (0600), yield its Path, always delete."""
        raise NotImplementedError
