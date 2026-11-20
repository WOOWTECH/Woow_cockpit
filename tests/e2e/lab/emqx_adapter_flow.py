"""Product flow for a *pre-provisioned* isolated synthetic EMQX fixture.

No CLI is exposed yet: provisioning, runtime mount validation and MQTT assertions
must be implemented before invoking this against a broker. This module deliberately
does not turn a direct adapter restore into a claim of a successful flows rollback.
"""
from pathlib import Path


def package_candidate_and_restore(ctx, app, volumes, staging, *, before_restore):
    """Package adapter-produced candidate data and invoke the actual restore flow.

    `before_restore` prepares a one-shot failure on the synthetic unit only; it
    must leave the unit healthy for the flow's safety backup. The caller must
    catch flows.RolledBack and independently verify the recovered broker.
    """
    from woowbackup import flows

    staging = Path(staging)
    staging.mkdir(mode=0o700, parents=True, exist_ok=False)
    ctx.storage.ensure_layout()
    adapter = ctx.adapter(app)
    app_dir = staging / 'apps' / app.id
    app_dir.mkdir(mode=0o700, parents=True)
    manifest, entries = adapter.import_manifest(app_dir, volumes=volumes)
    packaged = flows._package(ctx, [app], staging, include_images=False,
                              note='synthetic EMQX candidate', backup_type='manual', key=None,
                              phases=False, manifest_apps=[manifest], entries=entries, downtime=0)
    before_restore()
    # run_restore takes its own real safety backup, calls adapter.restore and,
    # on a destructive failure, invokes flows._rollback and a fresh adapter.
    return flows.run_restore(ctx, {'backup_id': packaged['backup_id'], 'apps': [app.id],
                                   'accept_unauthenticated': True})
