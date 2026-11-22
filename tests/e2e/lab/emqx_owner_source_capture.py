"""Owner-only private source registration; no lab entry, transfer or evidence IO.

Invoke inside the authorized isolated owner workflow. The caller supplies a
private encrypted staging archive, RAM password, immutable archive SHA and a
caller-owned0700 spool directory. Never pass original source secrets by argv or
environment. This module loads no credentials and emits no diagnostics.
"""
import contextlib

from woowbackup import hacommon
from ha_real_fixture import source_binding
from emqx_source_consumer import Capture
from emqx_native_hocon import native_hocon
from emqx_cold_history import native_cold_history
from emqx_private_boundary import PrivateFailure


@contextlib.contextmanager
def capture_owner_source(path, *, password, expected_sha256, spool_directory,
                         required_encryption=None):
    """Bind, authenticate, full-finish, parse and register product-used sources.

    Uses the actual bounded256MiB Capture spool and pinned native adapters.
    source_binding's final consistency check finishes BEFORE yielding. The
    yielded (capture, private_binding) has no target acknowledgements and is
    UNSEALED. summary/scan/replay refuse until capture.supply_target_documents
    receives the owner's actual complete target-category snapshots. Historical
    values are not final rows, complete target evidence or restore approval.

    All use stays inside this context so private spool bytes are cleaned on
    success, failure or cancellation. No candidate builder/broker is invoked.
    """
    try:
        if spool_directory is None:
            raise PrivateFailure('private-owner-source-refused')
        with Capture.source_only(password, hocon_parser=native_hocon,
                cold_decoder=native_cold_history, product_selection=True,
                spool_directory=spool_directory) as captured:
            with source_binding(path, 'emqx', hacommon.semver('5.8.9'),
                    expected_sha256, keys=captured.keys,
                    required_encryption=required_encryption) as source:
                private_binding = captured(source)
            yield captured, private_binding
    except (KeyboardInterrupt, SystemExit):
        raise PrivateFailure('private-owner-source-cancelled') from None
    except Exception:
        raise PrivateFailure('private-owner-source-refused') from None
