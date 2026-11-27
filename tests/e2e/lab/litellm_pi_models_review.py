#!/usr/bin/env python3
"""LiteLLM HA import security review (2026-11-23, iteration 2): the Pi agent provider-list reading of 3c1a0a4
(ha_litellm.pi_agent_sources / pi_agent_uses_litellm / key_users) against REAL files through the REAL owner file
helper (podman.FILE_HELPER, run as this lab user without runuser because the review does not run as root) and REAL
volumes of the isolated lab Podman store (~/.woowbk-lab/bin/labpodman; production volumes are invisible to it).

  python3 -I tests/e2e/lab/litellm_pi_models_review.py --code <dir with backup-engine/> > out.json

Every models.json holds generated CANARY key values; the harness then searches everything the product returned or
logged, and its own output, for them. Cases (each one "other app" with its own Pi agent directory):
  litellm_volume      provider baseUrl = this device's LiteLLM (http://litellm:4000/v1) in a lab volume: named
  other_provider      provider baseUrl = a public provider: not named
  url_carries_canary  LiteLLM baseUrl whose query string is a canary: named, canary never leaves
  custom_dir_env      Environment=PI_CODING_AGENT_DIR=/custom + Volume=<vol>:/custom: named
  home_path           Volume=%h/<dir>:/data/pi-agent (a host folder in the owner's home): named
  symlink_file        models.json is a symlink to a LiteLLM models.json elsewhere in the home: refused
  symlink_dir         Volume=%h/<link>:/data/pi-agent where <link> is a symlink to a LiteLLM dir: refused
  fifo                models.json is a FIFO (a container could plant one): no hang, not named
  oversized           2 MiB models.json (LiteLLM provider first): too large, not named, bounded read
  deep_nesting        100000 nested arrays (RecursionError in json): not named, no crash
  not_utf8            invalid UTF-8: not named
  traversal           Volume=%h/../../etc:/data/pi-agent: never read
  outside_home        Volume=/etc:/data/pi-agent: never read
  dash_volume         Volume=--format=x:/data/pi-agent (option-looking volume name): never passed to podman
Output: one JSON document of fixed facts (verdicts, elapsed seconds, canary search results; no canary value)."""
import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

LABPODMAN = Path.home() / '.woowbk-lab/bin/labpodman'
HOME = str(Path.home())
WORK_DIR_REL = '.woowbk-lab/review-pi-20261123'


def load_product(code):
    sys.path.insert(0, str(Path(code).resolve() / 'backup-engine'))
    from woowbackup import ha_litellm, podman  # noqa: E402
    from woowbackup.errors import BackupError  # noqa: E402
    return ha_litellm, podman, BackupError


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--code', required=True, help='a checkout (git archive) of the product commit under test')
    args = parser.parse_args()
    ha_litellm, podman, BackupError = load_product(args.code)
    canary = 'sk-woowbk-canary-' + secrets.token_hex(16)  # generated for this run only; never printed
    url_canary = 'woowbkurl' + secrets.token_hex(12)
    work_dir = Path(HOME) / WORK_DIR_REL
    if work_dir.exists():
        raise SystemExit('work dir exists; remove it first')
    work_dir.mkdir(mode=0o700)
    created_volumes = []
    facts = {'cases': {}}
    started = time.monotonic()

    class Account:
        def __init__(self, home):
            self.pw_uid, self.pw_gid, self.pw_dir = os.getuid(), os.getgid(), home

    class LabOwnerRunner(podman.OwnerRunner):
        """The product runner with the owner prefix minus runuser (the review is the owner) and podman = lab store."""
        calls = []

        def __init__(self, home):
            super().__init__('woowtechopenclaw', user_lookup=lambda _o: Account(home))

        def prefix(self):
            return [podman.ENV, '-i', f'PATH={podman.SAFE_PATH}', f'HOME={self.home}', 'LANG=C.UTF-8',
                    f'XDG_RUNTIME_DIR=/run/user/{self.uid}']

        def podman(self, *argv, **kwargs):
            LabOwnerRunner.calls.append(list(argv[:2]) + [str(a)[:80] for a in argv[2:]])
            return self.run([str(LABPODMAN), *argv], **kwargs)

    def models(base_url, extra=None):
        doc = {'providers': {'woow': {'baseUrl': base_url, 'apiKey': canary, 'api': 'openai-completions',
                                      'headers': {'Authorization': f'Bearer {canary}'},
                                      'models': [{'id': f'm-{canary}', 'name': canary}]}}}
        if extra:
            doc['providers'].update(extra)
        return json.dumps(doc).encode()

    def volume(name):
        full = f'woowbk-review-pi-{name}'.replace('_', '-')
        subprocess.run([str(LABPODMAN), 'volume', 'create', full], check=True, capture_output=True, timeout=120)
        created_volumes.append(full)
        out = subprocess.run([str(LABPODMAN), 'volume', 'inspect', '--format', '{{.Mountpoint}}', full], check=True,
                             capture_output=True, timeout=120).stdout.decode().strip()
        return full, Path(out)

    litellm_url = 'http://litellm:4000/v1'
    cases = {}  # name -> (quadlet text, expectation)
    # lab volumes
    for name, payload in (('litellm_volume', models(litellm_url)),
                          ('other_provider', models('https://api.openai.com/v1')),
                          ('url_carries_canary', models(f'http://litellm:4000/v1?k={url_canary}')),
                          ('custom_dir_env', models(litellm_url)),
                          ('oversized', models(litellm_url) + b' ' * (2 * 1024 * 1024)),
                          ('deep_nesting', b'[' * 100000 + b']' * 100000),
                          ('not_utf8', b'{"providers": {"w": {"baseUrl": "http://litellm:4000/v1", "k": "\xff\xfe"}}}')):
        full, mount = volume(name)
        (mount / 'models.json').write_bytes(payload)
        target = '/custom' if name == 'custom_dir_env' else '/data/pi-agent'
        env = 'Environment=PI_CODING_AGENT_DIR=/custom\n' if name == 'custom_dir_env' else ''
        cases[name] = (f'[Container]\nImage=localhost/x:1\n{env}Volume={full}:{target}:Z\n',
                       name not in ('other_provider', 'oversized', 'deep_nesting', 'not_utf8'))
    full, mount = volume('fifo')
    os.mkfifo(mount / 'models.json')
    cases['fifo'] = (f'[Container]\nImage=localhost/x:1\nVolume={full}:/data/pi-agent\n', False)
    full, mount = volume('symlink_file')
    elsewhere = work_dir / 'elsewhere'
    elsewhere.mkdir(mode=0o700)
    (elsewhere / 'models.json').write_bytes(models(litellm_url))
    os.symlink(elsewhere / 'models.json', mount / 'models.json')
    cases['symlink_file'] = (f'[Container]\nImage=localhost/x:1\nVolume={full}:/data/pi-agent\n', False)
    # host folders in the owner's home (%h/)
    real = work_dir / 'home-path'
    real.mkdir(mode=0o700)
    (real / 'models.json').write_bytes(models(litellm_url))
    cases['home_path'] = (f'[Container]\nImage=localhost/x:1\nVolume=%h/{WORK_DIR_REL}/home-path:/data/pi-agent:Z\n',
                          True)
    os.symlink(real, work_dir / 'link')
    cases['symlink_dir'] = (f'[Container]\nImage=localhost/x:1\nVolume=%h/{WORK_DIR_REL}/link:/data/pi-agent\n', False)
    cases['traversal'] = ('[Container]\nImage=localhost/x:1\nVolume=%h/../../etc:/data/pi-agent\n', False)
    cases['outside_home'] = ('[Container]\nImage=localhost/x:1\nVolume=/etc:/data/pi-agent\n', False)
    cases['dash_volume'] = ('[Container]\nImage=localhost/x:1\nVolume=--format=x:/data/pi-agent\n', False)

    owner_runner = LabOwnerRunner(HOME)
    litellm_home = work_dir / 'litellm-owner-home'  # LiteLLM's own runner: no drop-ins there (never the real ones)
    litellm_home.mkdir(mode=0o700)
    litellm_runner = LabOwnerRunner(str(litellm_home))

    class App:
        def __init__(self, app_id):
            self.id, self.name, self.owner, self.config_files = app_id, f'App {app_id}', 'woowtechopenclaw', ()

    class Ctx:
        def __init__(self, catalog):
            self._catalog = catalog

        def catalog(self):
            return self._catalog

    class Work:
        def __init__(self, catalog, quadlets):
            self.ctx, self._quadlets, self.notes = Ctx(catalog), quadlets, []

        def runner(self, app):
            return litellm_runner if app.id == 'litellm' else owner_runner

        def quadlets(self, app):
            return self._quadlets.get(app.id, {})

        def log(self, text):
            self.notes.append(str(text))

    texts_out = []
    for name, (unit, expected) in cases.items():
        app = App(name.replace('_', '-'))
        quadlets = {f'{app.id}.container': unit.encode()}
        work = Work({'litellm': App('litellm'), app.id: app}, {app.id: quadlets})
        sources = ha_litellm.pi_agent_sources(quadlets, HOME)
        t0 = time.monotonic()
        error = None
        try:
            uses = ha_litellm.pi_agent_uses_litellm(work, app, quadlets)
        except Exception as exc:  # noqa: BLE001 - recorded: key_users catches it and skips the app
            uses, error = None, type(exc).__name__
            texts_out.append(repr(exc))
        direct = round(time.monotonic() - t0, 2)
        t0 = time.monotonic()
        names = ha_litellm.key_users(work, App('litellm'))
        line = ha_litellm.key_users_line(names)
        texts_out += [json.dumps(names, ensure_ascii=False), line or '', *work.notes]
        facts['cases'][name] = {
            'sources': [[kind, 'woowbk-review-pi-*' if str(src).startswith('woowbk-review-pi-') else
                         ('<review dir>' if WORK_DIR_REL in str(src) else str(src)[:60])] for kind, src in sources],
            'pi_agent_uses_litellm': uses, 'exception': error, 'seconds': direct,
            'key_users_named': app.name in names, 'key_users_seconds': round(time.monotonic() - t0, 2),
            'expected_named': expected, 'as_expected': (app.name in names) == expected,
            'log_lines': len(work.notes)}
    facts['podman_calls'] = sorted({' '.join(call[:2]) for call in LabOwnerRunner.calls})
    facts['podman_volume_args'] = sorted({call[-1] if not call[-1].startswith('woowbk-review-pi-') else
                                          'woowbk-review-pi-*' for call in LabOwnerRunner.calls})
    facts['all_as_expected'] = all(case['as_expected'] for case in facts['cases'].values())
    import hashlib
    repo = Path(__file__).resolve().parents[3]
    head = subprocess.run(['git', '-C', str(repo), 'rev-parse', 'HEAD'], capture_output=True, text=True,
                          timeout=60).stdout.strip()
    dirty = subprocess.run(['git', '-C', str(repo), 'status', '--porcelain', '--untracked-files=no'],
                           capture_output=True, text=True, timeout=60).stdout.strip()
    product = Path(args.code).resolve() / 'backup-engine/woowbackup/ha_litellm.py'
    facts['source'] = {'harness_commit': head, 'harness_tracked_changes': bool(dirty),
                       'product_ha_litellm_sha256': hashlib.sha256(product.read_bytes()).hexdigest()}
    facts['elapsed_seconds'] = round(time.monotonic() - started, 1)
    # cleanup (lab volumes and the review dir only)
    for full in created_volumes:
        subprocess.run([str(LABPODMAN), 'volume', 'rm', '-f', full], capture_output=True, timeout=120)
    left = subprocess.run([str(LABPODMAN), 'volume', 'ls', '--format', '{{.Name}}'], capture_output=True,
                          timeout=120).stdout.decode().split()
    facts['review_volumes_left'] = sorted(v for v in left if v.startswith('woowbk-review-pi-'))
    shutil.rmtree(work_dir)
    facts['review_dir_left'] = work_dir.exists()
    out = json.dumps(facts, indent=1, sort_keys=True, ensure_ascii=False)
    blob = '\n'.join(texts_out) + out
    facts['canary_found_in_product_output_or_logs'] = canary in blob or url_canary in blob
    facts['canary_found_in_this_document'] = None  # set below, after the final rendering
    out = json.dumps(facts, indent=1, sort_keys=True, ensure_ascii=False)
    facts['canary_found_in_this_document'] = canary in out or url_canary in out
    out = json.dumps(facts, indent=1, sort_keys=True, ensure_ascii=False)
    sys.stdout.write(out + '\n')


if __name__ == '__main__':
    main()
