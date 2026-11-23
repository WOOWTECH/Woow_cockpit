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
from emqx_private_boundary import PrivateFailure, SourcePhaseFailure


@contextlib.contextmanager
def capture_owner_source(path, *, password, expected_sha256, spool_directory,
                         required_encryption=None, fixture_profile=None,
                         file_dependency_profile=None, product_image=None):
    """Bind, authenticate, full-finish, parse and register product-used sources.

    Uses the default256MiB spool unless the owner explicitly selects the
    digest-bound x86 fixture profile (exact expanded size, 120-second deadline).
    source_binding's final consistency check finishes BEFORE yielding. The
    yielded (capture, private_binding) has no target acknowledgements and is
    UNSEALED. summary/scan/replay refuse until capture.supply_target_documents
    receives the owner's actual complete target-category snapshots. Historical
    values are not final rows, complete target evidence or restore approval.

    file_dependency_profile is an independent explicit opt-in, activated only
    after real source_binding digest verification. product_image must match the
    native runner's immutable image pin. Private full-file receipts are retained
    on captured.hocon_file_receipts; they grant no target acknowledgement.

    All use stays inside this context so private spool bytes are cleaned on
    success, failure or cancellation. No candidate builder/broker is invoked.
    """
    stage = 'SETUP'
    captured = None
    try:
        if spool_directory is None:
            raise PrivateFailure('private-owner-source-refused')
        selected_parser = native_hocon
        def owner_parser(raw):
            return selected_parser(raw)
        with Capture.source_only(password, hocon_parser=owner_parser,
                cold_decoder=native_cold_history, product_selection=True,
                spool_directory=spool_directory) as captured:
            stage = 'BIND'
            with source_binding(path, 'emqx', hacommon.semver('5.8.9'),
                    expected_sha256, keys=captured.keys,
                    required_encryption=required_encryption) as source:
                stage = 'PROFILE'
                # source_binding has verified the actual archive digest here.
                if fixture_profile is not None:
                    from emqx_private_spool import fixture_limits
                    fixture_limits(fixture_profile, expected_sha256)
                if file_dependency_profile is not None:
                    from emqx_owner_file_hocon import PROFILE, IMAGE
                    from emqx_hocon_context import PROFILE as CONTEXT_PROFILE, HTTP_PROFILE, SQL_PROFILE
                    if file_dependency_profile not in (PROFILE, CONTEXT_PROFILE, HTTP_PROFILE, SQL_PROFILE) or product_image != IMAGE:
                        raise PrivateFailure('private-owner-source-refused')
                    if file_dependency_profile == CONTEXT_PROFILE:
                        from emqx_native_hocon import native_hocon_context
                        selected_parser = native_hocon_context
                    if file_dependency_profile == HTTP_PROFILE:
                        from emqx_native_hocon import native_hocon_http_context
                        selected_parser = native_hocon_http_context
                    if file_dependency_profile == SQL_PROFILE:
                        from emqx_native_hocon import native_hocon_sql_context
                        selected_parser = native_hocon_sql_context
                elif product_image is not None:
                    raise PrivateFailure('private-owner-source-refused')
                stage = 'CAPTURE'
                private_binding = captured(source, fixture_profile=fixture_profile,
                    verified_sha256=expected_sha256 if fixture_profile is not None else None,
                    file_dependency_profile=file_dependency_profile, product_image=product_image)
                stage = 'BIND_FINISH'
            stage = 'CAPABILITY'
            # Additive capability hook: only after final source_binding stamp.
            from emqx_captured_candidate import _verify_owner_binding
            _verify_owner_binding(captured, private_binding, expected_sha256)
            stage = 'OWNER_CONTEXT'
            yield captured, private_binding
            stage = 'CLEANUP'
    except (KeyboardInterrupt, SystemExit):
        raise SourcePhaseFailure('private-owner-source-cancelled', captured._source_phase if stage == 'CAPTURE' and captured else stage) from None
    except Exception:
        raise SourcePhaseFailure('private-owner-source-refused', captured._source_phase if stage == 'CAPTURE' and captured else stage) from None
