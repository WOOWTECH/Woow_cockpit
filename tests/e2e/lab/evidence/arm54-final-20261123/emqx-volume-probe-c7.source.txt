"""Lane arm54-2 item D: why the product's EMQX candidate exited at boot on .54 (emqx-real-arm-attempt1), and whether
applying the tar's top-directory entry (tempctr fix) is enough. Product image, no HA data, no secret, network none,
private store only.

1. A volume seeded the way ha_emqx.import_target_snapshot seeds the candidate's data volume (first member '.', owned by
   the image's emqx user, 0700; then configs/), through `podman volume import`: the top directory's owner/mode is read
   back (Podman 6.1.1 is expected to keep root 0755).
2. The product image on that volume at /opt/emqx/data, read-only root (as the product's throwaway runs it): it must
   either reach `emqx ctl status` = started or exit; its exit code and the last log lines (fixed words only) are kept.
3. The same with the top entry applied (podman unshare chown/chmod = tempctr._apply_root): must reach started.
Everything is removed afterwards."""
import io
import json
import sys
import tarfile
import time

from arm54_final_runtime import LABEL, ROOT, RootfulRunner, report, store_objects

IMAGE = 'docker.io/emqx/emqx:5.8.9@sha256:35b46f7aa7a0d51f3959e4344221ac5ec7f948b03e43099286b6c40a07bb393b'
WORDS = ('eacces', 'permission denied', 'read-only file system', 'enoent', 'crash', 'error', 'failed', 'exit')


def seeded_tar(uid, gid):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w|', format=tarfile.PAX_FORMAT) as tar:
        for name in ('.', 'configs'):
            info = tarfile.TarInfo(name)
            info.type, info.uid, info.gid, info.mode, info.mtime = tarfile.DIRTYPE, uid, gid, 0o700, 0
            tar.addfile(info)
    return buf.getvalue()


def main():
    r = RootfulRunner()
    out = {'status': 'failed', 'commercial_acceptance': 'not-complete', 'image': IMAGE, 'trials': {}}
    started = time.monotonic()

    def podman(*args, **kw):
        return r.podman(*args, **kw)

    def top(volume):
        mount = podman('volume', 'inspect', '--format', '{{.Mountpoint}}', volume).stdout.decode().strip()
        stat = r.podman('unshare', 'stat', '-c', '%u %g %a', '--', mount).stdout.decode().split()
        return mount, stat

    def trial(tag, apply_root):
        data, log, name = 'a54-probe-data-' + tag, 'a54-probe-log-' + tag, 'a54-probe-' + tag
        for volume in (data, log):
            podman('volume', 'create', '--label', LABEL, volume)
        uid_gid = json.loads(podman('image', 'inspect', IMAGE).stdout)[0]['Config'].get('User')
        podman('volume', 'import', data, '-', input=seeded_tar(1000, 1000))
        mount, before = top(data)
        result = {'image_user': uid_gid, 'top_after_import': before}
        if apply_root:
            r.podman('unshare', 'chown', '--no-dereference', '1000:1000', '--', mount)
            r.podman('unshare', 'chmod', '0700', '--', mount)
            result['top_after_apply'] = top(data)[1]
        podman('run', '-d', '--name', name, '--label', LABEL, '--network', 'none', '--read-only', '--pull=never',
               '--memory', '768m', '-v', data + ':/opt/emqx/data', '-v', log + ':/opt/emqx/log', IMAGE, timeout=120)
        t0, state = time.monotonic(), 'timeout'
        while time.monotonic() - t0 < 240:
            p = podman('exec', name, 'emqx', 'ctl', 'status', check=False, timeout=60, max_output=65536)
            if p.returncode == 0 and b'is started' in (p.stdout or b''):
                state = 'started'
                break
            running = podman('inspect', name, '--format', '{{.State.Running}}', check=False).stdout.decode().strip()
            if running != 'true':
                state = 'exited'
                break
            time.sleep(3)
        info = json.loads(podman('inspect', name).stdout)[0]['State']
        logs = podman('logs', '--tail', '200', name, check=False, max_output=4 * 1024 * 1024)
        text = (logs.stdout + logs.stderr).decode('utf-8', 'replace').lower()
        result.update(state=state, seconds=round(time.monotonic() - t0, 1), exit_code=info.get('ExitCode'),
                      oom_killed=info.get('OOMKilled'),
                      log_words={w: text.count(w) for w in WORDS},
                      mnesia_eacces=('eacces' in text and 'mnesia' in text))
        podman('rm', '--force', name, check=False, timeout=60)
        for volume in (data, log):
            podman('volume', 'rm', '--force', volume, check=False)
        out['trials'][tag] = result
        return result

    try:
        before = store_objects(r)
        assert not before['containers'] and not before['volumes'] and before['images'], 'store-state'
        plain = trial('podman-as-is', False)
        fixed = trial('top-entry-applied', True)
        out['podman_keeps_root_0755'] = plain['top_after_import'] == ['0', '0', '755']
        out['candidate_like_broker_exits_without_fix'] = plain['state'] == 'exited'
        out['broker_starts_with_top_entry_applied'] = fixed['state'] == 'started'
        out['status'] = 'passed' if (out['podman_keeps_root_0755'] and out['broker_starts_with_top_entry_applied']
                                     and out['candidate_like_broker_exits_without_fix']) else 'partial'
    except Exception as error:  # noqa: BLE001
        out['error_code'] = type(error).__name__
        out['failed_check'] = str(error)[:80] if isinstance(error, AssertionError) else None
    finally:
        left = store_objects(r)
        for name in left['containers']:
            r.podman('rm', '--force', name, check=False, timeout=60)
        for volume in left['volumes']:
            r.podman('volume', 'rm', '--force', volume, check=False, timeout=60)
        out['store_after'] = {k: len(v) for k, v in store_objects(r).items()}
        out['elapsed_seconds'] = round(time.monotonic() - started, 1)
        report(ROOT / 'emqx-volume-probe-result.json', out)
        print(json.dumps(out, sort_keys=True))
    return 0 if out['status'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
