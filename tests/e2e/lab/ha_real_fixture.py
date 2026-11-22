"""Offline real-HA fixture gate. No container/transport/restore operations.

Only metadata is exposed. Payload bytes are skipped by the strict product
reader, never extracted. This is NOT semantic validation or restore approval.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

from woowbackup import habackup, ha_emqx, ha_headscale, hasecuretar

MODULES = {'emqx': ha_emqx, 'headscale': ha_headscale}
MAX_ARCHIVE = 16 * 1024 ** 3


class Refused(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Refused(code)


def stamp(fd):
    st = os.fstat(fd)
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns


def digest(fd):
    result = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(fd, 1024 * 1024, offset)
        if not chunk:
            return result.hexdigest()
        result.update(chunk)
        offset += len(chunk)
        require(offset <= MAX_ARCHIVE, 'archive-too-large')


def inspect_open(opened, app, target_version, *, metadata_only=False, keys=None):
    module = MODULES[app]
    layout = opened.layout
    require(layout.size <= MAX_ARCHIVE, 'archive-too-large')
    members = [m for m in layout.members if m.role == 'addon'
               and (m.slug == module.SLUG or m.slug.endswith('_' + module.SLUG))]
    require(len(members) == 1, 'missing-or-ambiguous-addon')
    member = members[0]
    outer = next(a for a in layout.doc['addons'] if a['slug'] == member.slug)
    # Never echo names, images, paths, options or exception text from the archive.
    summary = {'schema': 1, 'app': app, 'archive_bytes': layout.size,
               'member_bytes': member.size, 'encryption': member.encryption,
               'restore_allowed': False, 'semantic_validation': 'pending'}
    if metadata_only:
        summary['status'] = 'outer-metadata-only'
        return summary, member, None
    require(not member.encrypted or keys is not None, 'encrypted-fixture-unsupported')
    report = habackup.Report()
    required = ({'data/emqx/node.name', 'data/emqx/data/configs/cluster.hocon'} if app == 'emqx'
                else {ha_headscale.DB, ha_headscale.NOISE, ha_headscale.CONFIG})
    include = tuple(required) + (('data/emqx/data/mnesia',) if app == 'emqx' else (ha_headscale.WAL, ha_headscale.DNS))
    found, mnesia = set(), set()
    with opened.open_addon(member.slug, keys=keys) as stream:
        for entry in habackup.iter_entries(stream, habackup.Select(include=include), report):
            if entry.name in required:
                require(entry.kind == 'file' and entry.size > 0, 'invalid-required-member')
                found.add(entry.name)
            if app == 'emqx' and entry.kind == 'file' and entry.size:
                prefix = 'data/emqx/data/mnesia/'
                if entry.name.startswith(prefix):
                    parts = entry.name[len(prefix):].split('/')
                    if len(parts) >= 2 and ha_emqx.NODE_RE.fullmatch(parts[0]):
                        mnesia.add(parts[0])
            # Do not read entry bodies; iter_entries drains and verifies the trailer.
    require(report.complete, 'incomplete-member')
    require(not report.skipped_symlinks and not report.skipped_other, 'unsupported-entry')
    require(found == required, 'missing-required-member')
    require(app != 'emqx' or len(mnesia) == 1, 'missing-or-ambiguous-mnesia')
    addon = report.addon
    require(addon is not None and addon.slug == module.SLUG, 'addon-identity-mismatch')
    require(addon.version == outer['version'], 'metadata-version-mismatch')
    require(module.VERSIONS.blocker(addon.version, target_version) is None, 'unsupported-version')
    require(addon.arch in ('amd64', 'aarch64'), 'unknown-source-architecture')
    require(addon.state == 'stopped', 'cold-backup-required')
    summary.update(status='metadata-contract-passed', addon_version=addon.version,
                   upstream_version=module.VERSIONS.upstream(addon.version),
                   source_arch=addon.arch, source_state=addon.state)
    return summary, member, addon


@contextlib.contextmanager
def source_binding(path, app, target_version, expected_sha256, *, keys=None, required_encryption=None):
    """Bind product work.open/addon_member/addon_info to the REAL selected member.

    Caller owns the isolated lab work/target and runtime checks. No converter is
    called here. Revalidates staged bytes; never trusts a JSON plan as approval.
    Each reopened consumer must exhaust habackup.iter_entries and require its
    report.complete. A prefix read/close does not verify that consumer's trailer
    or final encryption tag; preflight completion is not consumer completion.
    """
    with habackup.open_backup(path) as opened:
        before = stamp(opened.fd)
        require(digest(opened.fd) == expected_sha256, 'digest-mismatch')
        summary, member, addon = inspect_open(opened, app, target_version, keys=keys)
        require(required_encryption is None or summary['encryption'] == required_encryption,
                'unexpected-encryption')
        require(stamp(opened.fd) == before, 'source-changed')

        def addon_member(slug):
            require(slug == MODULES[app].SLUG, 'wrong-app-binding')
            return member.slug

        def addon_info(slug):
            addon_member(slug)
            return addon

        def open_member(slug):
            require(slug == member.slug, 'wrong-member-binding')
            return opened.open_addon(slug, keys=keys)

        yield {'open': open_member, 'addon_member': addon_member,
               'addon_info': addon_info}
        require(stamp(opened.fd) == before, 'source-changed')


def preflight(path, app, target_version, *, metadata_only=False, prepare=None, keys=None):
    require(not (metadata_only and prepare), 'metadata-only-cannot-prepare')
    with habackup.open_backup(path) as opened:
        before = stamp(opened.fd)
        summary, _, _ = inspect_open(opened, app, target_version, metadata_only=metadata_only, keys=keys)
        if metadata_only:
            return summary
        summary['sha256'] = digest(opened.fd)
        require(stamp(opened.fd) == before, 'source-changed')
        if prepare is not None:
            # New directory only: never overwrite or chmod somebody else's fixture.
            dest = Path(prepare)
            dest.mkdir(mode=0o700, parents=False, exist_ok=False)
            try:
                fd = os.open(dest / 'source.tar', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                copied = hashlib.sha256()
                with os.fdopen(fd, 'wb') as out:
                    offset = 0
                    while offset < before[2]:
                        chunk = os.pread(opened.fd, min(1024 * 1024, before[2] - offset), offset)
                        require(bool(chunk), 'source-changed')
                        out.write(chunk)
                        copied.update(chunk)
                        offset += len(chunk)
                    out.flush()
                    os.fsync(out.fileno())
                require(copied.hexdigest() == summary['sha256'] and stamp(opened.fd) == before, 'source-changed')
                fd = os.open(dest / 'preflight.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'w') as out:
                    json.dump(summary, out, sort_keys=True)
            except BaseException:
                shutil.rmtree(dest)
                raise
        return summary


def read_private_keys(stream):
    """Read bounded key text from private stdin, never argv/environment or output."""
    raw = stream.read(1025)
    require(isinstance(raw, bytes) and 0 < len(raw) <= 1024, 'invalid-private-key-input')
    try:
        password = raw.decode('ascii').rstrip('\r\n')
        require(bool(password) and '\n' not in password and '\r' not in password,
                'invalid-private-key-input')
        return hasecuretar.Keys(password)
    except Exception:
        raise Refused('invalid-private-key-input') from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('backup', type=Path)
    parser.add_argument('--app', choices=sorted(MODULES), required=True)
    parser.add_argument('--target-version', required=True)
    parser.add_argument('--metadata-only', action='store_true')
    parser.add_argument('--key-stdin', action='store_true', help='bounded private key input; never saved')
    parser.add_argument('--prepare', type=Path, help='new private directory; copies original archive, no restore')
    args = parser.parse_args(argv)
    try:
        require(not (args.key_stdin and args.metadata_only), 'metadata-does-not-need-key')
        keys = read_private_keys(sys.stdin.buffer) if args.key_stdin else None
        result = preflight(args.backup, args.app, args.target_version,
                           metadata_only=args.metadata_only, prepare=args.prepare, keys=keys)
    except Exception as exc:
        # Parser errors may contain secret-bearing archive paths: fixed codes only.
        result = {'status': 'refused', 'reason': str(exc) if isinstance(exc, Refused) else 'archive-or-io-error',
                  'restore_allowed': False}
        print(json.dumps(result, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
