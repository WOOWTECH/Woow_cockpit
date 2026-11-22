"""Internal join of held owner source/target contexts; no IO or transport defaults.

Call inside capture_owner_source's context with the actual Capture it yielded and
already-bound observed target readers. The owner MUST hold source lifetime and
one target mutation/issuance/quiescence lease through snapshot reads, login and
publication (and through any later replay). This function neither acquires that
lease nor establishes broker state, restore readiness or commercial acceptance.
"""
import io

from emqx_persisted_values import PersistedValues
from emqx_private_boundary import PrivateFailure, MAX_TOTAL
from emqx_runtime_credentials import RuntimeRegistry, TARGET_CATEGORIES, read_bounded
from emqx_runtime_workflow import SOURCE_CATEGORIES, login_preflight
from emqx_source_consumer import Capture
from emqx_target_capture import ObservedTargetReaders
from emqx_target_snapshots import register_target_snapshots


def owner_preflight(*, captured, target_readers, target_generation,
                    private_transport, username, password,
                    evidence_directory, evidence_name):
    """Complete the actual source registry and run existing registration/login.

    Reads each supplied category once, bounded64KiB, through EOF/finish/close.
    Only validated frozen original JSON bytes go to supply_target_documents;
    replay to validators/login is in memory, retaining the full target companion.
    Source counts are derived solely from the now-sealed real registry summary.
    No second Capture invocation, candidate build, broker start or restore occurs.
    Failure emits no evidence; a failed login may leave source registration sealed
    with valid target documents, but returns no session/login capability. Source
    target-completion remains one-shot; callers discard failed workflow contexts.
    """
    try:
        if (not isinstance(captured, Capture) or not captured._source_only
                or not captured._source_ready or captured._closed
                or captured._stack is None or captured._target_attempted
                or captured.registry._sealed
                or not callable(private_transport)):
            raise ValueError()
        if (not isinstance(target_readers, ObservedTargetReaders)
                or set(target_readers) != TARGET_CATEGORIES
                or not all(callable(reader) for reader in target_readers.values())
                or type(target_generation) is not str or not target_generation):
            raise ValueError()
        companion = getattr(target_readers, 'persisted_values', None)

        def generation_matches():
            if (not isinstance(companion, PersistedValues)
                    or getattr(target_readers, 'persisted_values', None) is not companion
                    or companion.scope != 'target'
                    or companion.generation != target_generation
                    or getattr(target_readers, 'generation', None) != target_generation
                    or not {'emqx_authn_mnesia', 'emqx_app'} <= companion.tables):
                raise ValueError()
            companion.scan(b'')

        generation_matches()
        documents, total = {}, 0
        for category in sorted(TARGET_CATEGORIES):
            stream = target_readers[category]()
            try:
                raw = read_bounded(stream)
                if hasattr(stream, 'finish'):
                    stream.finish()
            finally:
                stream.close()
            total += len(raw)
            if total > MAX_TOTAL:
                raise ValueError()
            documents[category] = raw
        generation_matches()
        frozen = ObservedTargetReaders({category: (lambda data=data: io.BytesIO(data))
                                        for category, data in documents.items()})
        frozen.persisted_values = companion
        frozen.generation = target_generation
        register_target_snapshots(RuntimeRegistry(), frozen)
        captured.supply_target_documents(documents)
        summary = captured.registry.summary()
        counts = {category: summary[category] for category in SOURCE_CATEGORIES}
        session = login_preflight(source_registry=captured.registry, source_counts=counts,
            target_readers=frozen, private_transport=private_transport,
            username=username, password=password, evidence_directory=evidence_directory,
            evidence_name=evidence_name)
        from emqx_captured_candidate import _record_joined_session
        return _record_joined_session(captured, session)
    except (KeyboardInterrupt, SystemExit):
        raise PrivateFailure('private-preflight-cancelled') from None
    except Exception:
        raise PrivateFailure('private-preflight-refused') from None
