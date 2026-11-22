"""Private owner glue: held source + fresh target + stdin curl login + build.

No CLI, credential-file reader, environment credentials, broker creation, install
or restore. Enter only in the authorized isolated owner workflow. The caller
supplies a bounded owner runner and actual target writer/issuance exclusion
context. Target observation necessarily reads the held target; source data reaches
candidate brokers only after successful combined-scanned preflight publication.

The vendor observer binds CID from bounded private inspect inside target exclusion
and the source hold. Its pinned-image file proof runs before target capture and
again before releasing exclusion. Early refusal prevents build; a late recheck
refuses the returned result but cannot undo an already attempted build. Published
preflight evidence is not a restore result or commercial acceptance.

Source-only credential references: ha_import_b1_e2e.py uses B1_EMQX_ADMIN_PW,
B1_EMQX_USER2 and B1_EMQX_USER2_PW from its merged b1-creds.env/ha-import-creds.env
mapping. That does NOT identify target login credentials. This module accepts
explicit RAM bytes and never opens either file or assumes an admin username.
"""
import io
from contextlib import contextmanager
import json
import re

from emqx_captured_candidate import build_captured_candidate
from emqx_owner_preflight import owner_preflight
from emqx_owner_source_capture import capture_owner_source
from emqx_owner_target import owner_target_readers, MAX_WIRE
from emqx_private_boundary import PrivateFailure, MAX_VALUE
from emqx_target_vendor_policy import bounded_vendor_callbacks, vendor_observer

HTTP_OUTPUT = MAX_VALUE + 512


def curl_login_transport(*, runner, broker, login_url):
    """Create a lazy private transport for existing login_registered/preflight.

    Those consumers register login input BEFORE invoking this callback and tokens
    BEFORE returning a capability. The runner must bound stdout/stderr and kill
    its process group on timeout (OwnerRunner's existing contract). Curl gets
    credentials only in stdin config; no raw stderr/response is published here.
    No retries, curlrc, redirects, proxy, arbitrary URL/path, or credential defaults.
    """
    try:
        if (not callable(getattr(runner, 'podman', None)) or type(broker) is not str
                or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', broker) is None
                or type(login_url) is not str):
            raise ValueError()
        match = re.fullmatch(r'http://127\.0\.0\.1:([0-9]{1,5})/api/v5/login', login_url)
        if match is None or not 1 <= int(match[1]) <= 65535:
            raise ValueError()
    except Exception:
        raise PrivateFailure('private-owner-login-refused') from None

    def transport(username, password):
        try:
            if any(type(value) is not bytes or not 1 <= len(value) <= MAX_VALUE
                   for value in (username, password)):
                raise ValueError()
            data = json.dumps({'username': username.decode('utf-8'),
                               'password': password.decode('utf-8')}, separators=(',', ':'))
            config = ['url = ' + json.dumps(login_url), 'silent', 'show-error',
                'max-time = 5', 'connect-timeout = 3', 'proxy = ""', 'noproxy = "*"',
                'proto = "=http"', 'max-redirs = 0', 'request = "POST"',
                'header = "Content-Type: application/json"', 'data = ' + json.dumps(data),
                'write-out = "\\n%{content_type}\\n%{http_code}"']
            response = runner.podman('exec', '-i', broker, 'curl', '-q', '--config', '-',
                input=('\n'.join(config) + '\n').encode(), timeout=10,
                max_output=HTTP_OUTPUT, check=False)
            if (response.returncode or type(response.stdout) is not bytes
                    or len(response.stdout) > HTTP_OUTPUT):
                raise ValueError()
            body, content_type, code = response.stdout.rsplit(b'\n', 2)
            if (len(body) > MAX_VALUE or len(content_type) > 128
                    or re.fullmatch(rb'[1-5][0-9]{2}', code) is None):
                raise ValueError()
            return int(code), content_type.decode('ascii').split(';', 1)[0].strip().lower(), io.BytesIO(body)
        except (KeyboardInterrupt, SystemExit):
            raise PrivateFailure('private-owner-login-cancelled') from None
        except Exception:
            raise PrivateFailure('private-owner-login-refused') from None
    return transport


def _held_vendor_observer(*, runner, broker):
    """Lazy actual CID binding: owner_target_readers invokes INSIDE quiescence.

    The real policy observer performs full repeated image/target/file provenance
    checks. This initial private inspect only pins its actual container identity;
    it is not a receipt, caller acknowledgement or alternative authorization.
    """
    private_eval, private_inspect = bounded_vendor_callbacks(runner=runner, broker=broker)

    @contextmanager
    def observe(*, generation, private_values):
        from emqx_owner_vendor_files import LIMIT
        from emqx_semantic_readers import _pairs
        def invalid_constant(_):
            raise ValueError()
        raw = private_inspect()
        if type(raw) is not bytes or not 0 < len(raw) <= LIMIT:
            raise ValueError()
        docs = json.loads(raw, object_pairs_hook=_pairs, parse_constant=invalid_constant)
        if (type(docs) is not list or len(docs) != 1 or type(docs[0]) is not dict
                or type(docs[0].get('Id')) is not str
                or re.fullmatch(r'[0-9a-f]{64}', docs[0]['Id']) is None
                or type(docs[0].get('Name')) is not str
                or docs[0]['Name'].lstrip('/') != broker):
            raise ValueError()
        with vendor_observer(broker=broker, owned_container_id=docs[0]['Id'],
                private_eval=private_eval, private_inspect=private_inspect)(
                    generation=generation, private_values=private_values) as observed:
            yield observed
    return observe


@contextmanager
def _joined_owner_preflight(target, backup, *, source_password, expected_sha256,
        spool_directory, source_options, runner, quiesce, login_url, username,
        password, evidence_directory, evidence_name, expected_source_profile=None):
    """Actual held producers shared by build and preflight-only owner callsites."""
    if (type(source_options) is not dict or set(source_options) - {
            'fixture_profile', 'file_dependency_profile', 'product_image'}
            or not callable(quiesce)):
        raise ValueError()
    broker = target.container
    transport = curl_login_transport(runner=runner, broker=broker, login_url=login_url)

    def evaluate(expression):
        response = runner.podman('exec', broker, 'emqx', 'eval', expression,
                                timeout=30, max_output=MAX_WIRE, check=False)
        if (response.returncode or type(response.stdout) is not bytes
                or len(response.stdout) > MAX_WIRE):
            raise ValueError()
        return response.stdout

    from emqx_preflight_stage import mark
    mark('source_capture')
    with capture_owner_source(backup, password=source_password,
            expected_sha256=expected_sha256, spool_directory=spool_directory,
            required_encryption='v3', **dict(source_options)) as (captured, binding):
        if expected_source_profile is not None:
            from emqx_arm_source_owner import validate_source_capture
            validate_source_capture(captured, binding, expected_source_profile)
        mark('source_validated')
        mark('target_capture')
        with owner_target_readers(private_eval=evaluate, quiesce=quiesce,
                vendor_observer=_held_vendor_observer(runner=runner, broker=broker)) as readers:
            session = owner_preflight(captured=captured, target_readers=readers,
                target_generation=readers.generation, private_transport=transport,
                username=username, password=password, evidence_directory=evidence_directory,
                evidence_name=evidence_name)
            mark('joined_ready')
            yield captured, binding, session


def build_owner_candidate(work, app, adapter, target, backup, staging, job_id, *,
                          source_password, expected_sha256, spool_directory,
                          source_options, runner, quiesce, login_url,
                          username, password, evidence_directory, evidence_name):
    """One authorized owner operation; return only private candidate outputs.

    Source_options selects existing fixture/file profiles only; it cannot override
    archive identity, password, spool, parser, transport or v3 authentication.
    Fresh owner_target_readers capture happens INSIDE the source context. Its
    actual quiesce() context must exclude writers/issuance except this authorized
    login; it stays held through login, combined scan, bridge build and cleanup.
    It is the caller's real context, never replaced by a flag or no-op fallback.
    No candidate/source broker operation is invoked if preflight refuses. A later
    build failure may leave the already-passed preflight evidence; it never means
    candidate/restore acceptance. Original source/target/core guards are unchanged.
    """
    try:
        with _joined_owner_preflight(target, backup,
                source_password=source_password, expected_sha256=expected_sha256,
                spool_directory=spool_directory, source_options=source_options,
                runner=runner, quiesce=quiesce, login_url=login_url, username=username,
                password=password, evidence_directory=evidence_directory,
                evidence_name=evidence_name) as (captured, binding, session):
            return build_captured_candidate(work, app, adapter, target, backup, staging,
                    job_id, captured=captured, private_binding=binding, session=session,
                    expected_sha256=expected_sha256)
    except (KeyboardInterrupt, SystemExit):
        raise PrivateFailure('private-owner-driver-cancelled') from None
    except Exception:
        raise PrivateFailure('private-owner-driver-refused') from None


def preflight_owner(target, backup, *, source_password, expected_sha256,
        spool_directory, source_options, runner, quiesce, login_url, username,
        password, evidence_directory, evidence_name, expected_source_profile):
    """Return exact scanned artifact bytes AFTER both held contexts clean up.

    No replay, source broker, candidate, install or restore call is reachable.
    Hashing/transport may happen only after this returns. A late lease failure
    discards the bytes; private temporary evidence is owned by the framed caller.
    """
    try:
        import os
        import stat
        from emqx_private_evidence import SOURCE_NAMES
        with _joined_owner_preflight(target, backup,
                source_password=source_password, expected_sha256=expected_sha256,
                spool_directory=spool_directory, source_options=source_options,
                runner=runner, quiesce=quiesce, login_url=login_url, username=username,
                password=password, evidence_directory=evidence_directory,
                evidence_name=evidence_name,
                expected_source_profile=expected_source_profile) as (_, _, session):
            from pathlib import Path
            fd = os.open(Path(evidence_directory)/evidence_name, os.O_RDONLY|os.O_NOFOLLOW)
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                        or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 65536):
                    raise ValueError()
                raw = stream.read(65537)
                if len(raw) != info.st_size or stream.read(1) != b'': raise ValueError()
                after = os.fstat(stream.fileno())
                fields = ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
                if any(getattr(info,k) != getattr(after,k) for k in fields): raise ValueError()
            from emqx_private_evidence import names_receipt
            expected = names_receipt('preflight','passed',session.coverage)
            if raw != expected: raise ValueError()
            session.registry.scan(raw)
        return raw
    except (KeyboardInterrupt, SystemExit):
        raise PrivateFailure('private-owner-preflight-cancelled') from None
    except Exception:
        raise PrivateFailure('private-owner-preflight-refused') from None
