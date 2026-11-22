"""Private registration preflight integrated with the parent's evidence publisher.

Runs owner target readers and login transport, then scans actual evidence bytes
through BOTH sealed source and runtime registries. This is registration/login
preflight only; it never declares restore/startup/MQTT/restart acceptance.
"""
from emqx_private_boundary import PrivateFailure, Registry
from emqx_runtime_credentials import RuntimeRegistry, login_registered, refused
from emqx_target_snapshots import register_target_snapshots
from emqx_private_evidence import publish

SOURCE_CATEGORIES = frozenset(('backup-key', 'source-options', 'source-cookie'))


class CombinedRegistry:
    def __init__(self, source, runtime):
        self._source, self._runtime = source, runtime

    def __repr__(self):
        return '<EMQX combined private registry>'

    def scan(self, payload):
        self._source.scan(payload)
        self._runtime.scan(payload)


class PrivateSession:
    def __init__(self, credential, registry, coverage, evidence):
        self.credential = credential
        self.registry = registry
        self.coverage = coverage
        self.evidence = evidence

    def __repr__(self):
        return '<EMQX private session>'


def login_preflight(*, source_registry, source_counts, target_readers,
                    private_transport, username, password, evidence_directory,
                    evidence_name='credential-preflight.json'):
    """Source owner supplies its sealed Registry and actual source reader counts.

    Counts cover only the three SOURCE_CATEGORIES; registration counts are not
    semantic completeness proof. Runtime category counts come from the actual
    snapshot registrations, plus login input/token registration in bootstrap.
    Incomplete source/target capture or failed login emits no evidence file.
    No default transport, source discovery, CLI, or product guard change.
    """
    try:
        if (not isinstance(source_registry, Registry) or not isinstance(source_counts, dict)
                or set(source_counts) != SOURCE_CATEGORIES
                or any(type(v) is not int or not 0 <= v <= 4096 for v in source_counts.values())
                or not source_counts['backup-key']):
            refused()
        # Existing Registry.scan enforces sealing; do this before owner callbacks.
        source_registry.scan(b'')
        runtime = RuntimeRegistry()
        register_target_snapshots(runtime, target_readers)
        credential = login_registered(runtime, private_transport,
                                      username=username, password=password)
        counts = runtime.summary()
        coverage = dict(source_counts)
        for category in ('mqtt-auth', 'api-keys', 'connectors', 'tls', 'target-bootstrap'):
            coverage[category] = counts[category]
        coverage['target-bootstrap'] += (counts.get('runtime-login-input', 0)
                                         + counts.get('runtime-login-token', 0))
        combined = CombinedRegistry(source_registry, runtime)
        evidence = publish(evidence_directory, evidence_name, registry=combined,
                           phase='preflight', result='passed', coverage=coverage)
        return PrivateSession(credential, combined, coverage, evidence)
    except (KeyboardInterrupt, SystemExit):
        raise PrivateFailure('runtime-private-cancelled') from None
    except Exception:
        raise PrivateFailure('runtime-private-refused') from None
