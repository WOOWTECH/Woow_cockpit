"""Product flow for a *pre-provisioned* isolated synthetic EMQX fixture.

No CLI is exposed yet: provisioning, runtime mount validation and MQTT assertions
must be implemented before invoking this against a broker. This module deliberately
does not turn a direct adapter restore into a claim of a successful flows rollback.
"""
from pathlib import Path


def package_candidate(ctx, app, volumes, staging):
    """Package product-converted candidate volumes with the actual adapter."""
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
    return packaged['backup_id']


def restore_candidate(ctx, app, backup_id):
    """Run the product restore and its automatic rollback on a destructive failure."""
    from woowbackup import flows
    return flows.run_restore(ctx, {'backup_id': backup_id, 'apps': [app.id], 'accept_unauthenticated': True})
