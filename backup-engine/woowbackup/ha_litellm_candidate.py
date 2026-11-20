"""Internal LiteLLM HA member preflight; NOT an importable app.

The caller supplies independently established target versions. This module reads no live
service or target secret, does not open PostgreSQL, and never returns the HA salt. A valid
source salt file is not evidence that the database contains the same key. Conversion is
unconditionally disabled until a trusted schema, secret transfer and real tests exist.
"""
import re
from dataclasses import dataclass

from . import habackup, hacommon
from .errors import BackupError

SLUG = 'woow-litellm'
PG_VERSION = 'data/postgres/PG_VERSION'
PG_CONTROL = 'data/postgres/global/pg_control'
STATE = 'data/woow/state.json'
SALT = 'data/secrets/salt_key'
# Only this release was verified from the checked-in HA build-info.json.
ADDON_VERSIONS = {'0.1.15': ('1.104.0', 18)}
_VERSION = re.compile(r'[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}\Z')
_SALT = re.compile(rb'[A-Za-z0-9_-]{16,256}\Z')
GUARD = 'LiteLLM HA 轉換尚未支援：資料庫結構與加密金鑰相容性尚未驗證。'


@dataclass(frozen=True)
class Source:
    addon_version: str | None
    product_version: str | None
    pg_major: int | None
    control_present: bool
    salt_valid: bool


def scan_member(stream, *, checkpoint=None):
    """Read only fixed source paths. Full tar is validated; secrets are not returned or logged."""
    report = habackup.Report()
    select = habackup.Select(include=(PG_VERSION, PG_CONTROL, STATE, SALT), max_bytes=1024 * 1024)
    pg_major = product = None
    control = salt_valid = False
    for entry in habackup.iter_entries(stream, select, report, addon=True, checkpoint=checkpoint):
        if entry.kind != 'file':
            continue
        if entry.name == PG_VERSION:
            if entry.size <= 16:
                raw = entry.read_all(16).strip()
                if re.fullmatch(rb'[1-9][0-9]?', raw):
                    pg_major = int(raw)
        elif entry.name == PG_CONTROL:
            control = entry.size > 0
        elif entry.name == STATE:
            if entry.size <= 65536:
                state = hacommon.strict_json(entry.read_all(65536), 65536)
                value = state.get('litellm_version') if isinstance(state, dict) else None
                if isinstance(value, str) and _VERSION.fullmatch(value):
                    product = value
        elif entry.name == SALT:
            if entry.size <= 1024:
                # HA read_secret strips surrounding whitespace before validating SECRET_VALUE_RE.
                salt_valid = bool(_SALT.fullmatch(entry.read_all(1024).strip()))
    info = report.addon
    if info is None or info.slug != SLUG:
        raise BackupError('incompatible', '備份不是可辨識的 LiteLLM 附加元件。')
    return Source(info.version, product, pg_major, control, salt_valid)


def assess(source, *, target_version, target_pg_major):
    """Restricted preflight. Inputs must come from a verified target, not an image tag guess.

    Even with matching versions the result is blocked: no database or key correspondence
    has been checked. Only static, non-secret messages and numeric facts are returned.
    """
    blockers = []
    expected = ADDON_VERSIONS.get(source.addon_version)
    if expected is None:
        blockers.append('無法確認 HA LiteLLM 附加元件版本。')
    if source.product_version is None:
        blockers.append('HA LiteLLM 的資料庫版本記錄缺失或格式不正確。')
    elif expected and source.product_version != expected[0]:
        blockers.append('HA LiteLLM 版本記錄與附加元件版本不一致。')
    if not isinstance(target_version, str) or not _VERSION.fullmatch(target_version):
        blockers.append('無法可靠確認目標 LiteLLM 版本。')
    elif source.product_version and source.product_version != target_version:
        blockers.append('HA 與目標 LiteLLM 版本不同。')
    if source.pg_major is None or not source.control_present:
        blockers.append('HA PostgreSQL 版本或資料庫控制檔缺失。')
    elif expected and source.pg_major != expected[1]:
        blockers.append('HA PostgreSQL 主版本與附加元件版本不一致。')
    if type(target_pg_major) is not int or not 1 <= target_pg_major <= 99:
        blockers.append('無法可靠確認目標 PostgreSQL 主版本。')
    elif source.pg_major and source.pg_major > target_pg_major:
        blockers.append('HA PostgreSQL 主版本較新，不支援跨版本降版匯入。')
    if not source.salt_valid:
        blockers.append('HA 資料庫加密金鑰來源缺失或格式不正確。')
    blockers.append(GUARD)
    return {'blockers': blockers, 'warnings': ['尚未驗證來源金鑰與資料庫內金鑰一致，也未驗證憑證可解密。'],
            'litellm': {'source_version': source.product_version or '', 'source_pg_major': source.pg_major,
                        'target_pg_major': target_pg_major if type(target_pg_major) is int and 1 <= target_pg_major <= 99 else None,
                        'salt_file_valid': source.salt_valid}}


_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PG_ENV = re.compile(r"PG_MAJOR=([1-9][0-9]?)\Z")


def target_evidence(*, running_db_image_id, inspected_db_image):
    """Build non-secret target facts from caller-supplied image inspection.

    The caller must obtain the ID of the running DB container and inspect the exact
    same image. A tag or an image's environment without this binding is insufficient.
    This helper performs no container operation and cannot authenticate its caller.
    LiteLLM's version remains unknown: the available package has no verified runtime
    version probe in this candidate. Neither secret material nor env is returned.
    """
    product = None
    pg_major = None
    if isinstance(inspected_db_image, dict):
        image_id = inspected_db_image.get('id')
        env = inspected_db_image.get('env')
        if (isinstance(running_db_image_id, str) and _IMAGE_ID.fullmatch(running_db_image_id)
                and image_id == running_db_image_id and isinstance(env, list)):
            # Conflicting or malformed PG_MAJOR entries cannot establish a version.
            versions = [item for item in env if isinstance(item, str) and item.startswith('PG_MAJOR=')]
            if len(versions) == 1:
                match = _PG_ENV.fullmatch(versions[0])
                if match:
                    pg_major = int(match.group(1))
    return {'target_version': product, 'target_pg_major': pg_major}


def assess_target(source, evidence):
    """Use only the non-secret target facts produced by target_evidence."""
    if not isinstance(evidence, dict):
        evidence = {}
    return assess(source, target_version=evidence.get('target_version'),
                  target_pg_major=evidence.get('target_pg_major'))


def preservation_contract():
    """Unimplemented proposal: declarations only; never accepts or returns secrets.

    Existing import_manifest copies all live secrets. That cannot carry HA's salt,
    and no caller may apply this proposal until secure transfer and rollback exist.
    """
    return {
        'source_data': 'unverified',
        'source_salt': 'unverified_database_binding',
        'target_salt': 'preserve_until_verified_secret_transfer_exists',
        'target_credentials': 'preserve',
        'target_configuration': 'preserve',
        'conversion': 'disabled',
        'secret_transfer': 'not_implemented',
        'rollback': 'not_implemented',
    }


def convert(work, app, test_mode, out_dir):
    """Defense in depth if a caller incorrectly attempts to invoke conversion."""
    raise BackupError('incompatible', GUARD, app=app.id)
