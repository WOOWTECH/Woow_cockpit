"""Internal capabilities for a verified capture -> joined login -> build boundary.

Trusted in-process owner code only, not a sandbox against Python introspection.
No credential loading, transport, CLI, installation or public guard changes.
Caller keeps the source context and target quiescence/issuance lease held through
preflight and build. Candidate output is private, not restore authorization.
"""
import copy
import re
import weakref

from emqx_private_boundary import PrivateFailure
from emqx_real_candidate import build_verified_candidate

# Only a successfully returned owner_preflight session is inserted here. The
# weak key preserves identity without retaining discarded session capabilities.
_JOINED_SESSIONS = weakref.WeakKeyDictionary()


class CapturedBinding(dict):
    """Capture-issued callbacks. A plain/copy dict cannot carry this capability."""
    def __init__(self, captured, callbacks):
        super().__init__(callbacks)
        self._capture = captured
        self._callbacks = dict(callbacks)
        self._registry = captured.registry
        self._keys = captured.keys

    def __repr__(self):
        return '<EMQX private captured binding>'


def _actual_binding(captured, binding):
    from emqx_source_consumer import Capture
    if (not isinstance(captured, Capture) or type(binding) is not CapturedBinding
            or captured._private_binding is not binding or binding._capture is not captured
            or binding._registry is not captured.registry or binding._keys is not captured.keys
            or dict(binding) != binding._callbacks
            or not captured._used or not captured._source_ready
            or captured._closed or captured._stack is None):
        raise ValueError()


def _verify_owner_binding(captured, binding, expected_sha256):
    """Owner-only hook AFTER source_binding exits with its final stamp intact."""
    _actual_binding(captured, binding)
    if (captured._owner_source_proof is not None or type(expected_sha256) is not str
            or re.fullmatch(r'[0-9a-f]{64}', expected_sha256) is None
            or set(binding) != {'open', 'addon_member', 'addon_info'}):
        raise ValueError()
    # Store an internal record, never a caller's boolean/completeness assertion.
    captured._owner_source_proof = (binding, expected_sha256,
        binding['addon_member']('woow-emqx'), binding['addon_info']('woow-emqx'))


def _record_joined_session(captured, session):
    """Private hook called only after real login_preflight + publication return."""
    from emqx_runtime_workflow import PrivateSession, CombinedRegistry
    binding = captured._private_binding
    _actual_binding(captured, binding)
    if (type(session) is not PrivateSession or type(session.registry) is not CombinedRegistry
            or session.registry._source is not captured.registry):
        raise ValueError()
    session.registry.scan(b'')
    _JOINED_SESSIONS[session] = (captured, binding, session.registry,
        session.credential, session.registry._runtime, session.registry._persisted)
    return session


def _authorized(captured, binding, session, expected_sha256):
    _actual_binding(captured, binding)
    proof = captured._owner_source_proof
    if (proof is None or proof[0] is not binding or proof[1] != expected_sha256
            or not captured._source_only or not captured._target_attempted):
        raise ValueError()
    joined = _JOINED_SESSIONS.get(session)
    if (joined is None or joined[0] is not captured or joined[1] is not binding
            or session.registry is not joined[2] or session.credential is not joined[3]
            or session.registry._source is not captured.registry
            or session.registry._runtime is not joined[4]
            or session.registry._persisted is not joined[5]):
        raise ValueError()
    captured.registry.summary()  # actual seal, never a caller assertion
    session.registry.scan(b'')
    return proof


def build_captured_candidate(work, app, adapter, target, backup, staging, job_id, *,
                             captured, private_binding, session, expected_sha256):
    """Build/package only via unchanged encrypted-archive verification wrapper.

    No second Capture, skip flag, public import or install path. Source/key and
    successful joined-session identities must all match, in their live context.
    Original archive SHA/v3/metadata/EOF/final stamp are checked again by the
    existing builder. Its freshly verified addon must equal the captured addon.
    Original work callbacks/logs are untouched; copied work discards private logs.
    """
    try:
        proof = _authorized(captured, private_binding, session, expected_sha256)
        bound = copy.copy(work)
        bound.log = lambda *args, **kwargs: None

        def reuse(verified_source):
            _authorized(captured, private_binding, session, expected_sha256)
            if (verified_source['addon_member']('woow-emqx') != proof[2]
                    or verified_source['addon_info']('woow-emqx') != proof[3]):
                raise ValueError()
            return dict(private_binding)

        return build_verified_candidate(bound, app, adapter, target, backup, staging,
            job_id, expected_sha256=expected_sha256, keys=captured.keys,
            private_capture=reuse)
    except (KeyboardInterrupt, SystemExit):
        raise PrivateFailure('candidate-cancelled') from None
    except Exception:
        raise PrivateFailure('candidate-refused') from None
