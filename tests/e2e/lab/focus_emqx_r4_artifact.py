"""Bounded artifact/OCI validators and an explicit native hook for an owned reviewed candidate.

Validators only read/hash data. export_candidate calls the real product postcheck/stop/export APIs.
"""
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

BASE = 'sha256:3d718d475d99c635dadfa271c8bd6854931ec5904172d36f3b716455bd551362'
IMAGES = {
    'broker': 'sha256:3f60addfad2bfc6c09400aa48cfbc1b2b2aab04fb6a64d6392c016e02d7fb57b',
    'entrance': 'sha256:47ce8258a10e28ce4b4498588c25ef77ae328f4c56cbe3e8d5dcf4f6d8019997',
    'client': 'sha256:93a0bdfcbd9b7a86b36127cb81f54e1afd2019f12f39033458df405a027c03e3',
}
CLIENT_REF = 'docker.io/library/eclipse-mosquitto:2.0.22@sha256:212f89e1eaeb2c322d6441b64396e3346026674db8fa9c27beac293405c32b3c'
PROFILE = 'emqx-r4-package-v1'
CASES = ('plain', 'dead_row', 'noauth')
MAX_DATA = 256 * 1024**2
MAX_STAGE = 512 * 1024**2
HASH = re.compile(r'[0-9a-f]{64}\Z')
TABLES = ('emqx_authn_mnesia', 'emqx_authn_scram_mnesia', 'emqx_acl', 'emqx_admin', 'emqx_app', 'emqx_psk',
          'emqx_banned_rules')
import focus_emqx_r4_profile as profile

PACKAGE_ENV = dict(profile.ENV)


def digest(stream, limit):
    h = hashlib.sha256(); size = 0
    while True:
        data = stream.read(min(1024**2, limit + 1 - size))
        if not data: return h.hexdigest(), size
        size += len(data)
        if size > limit: raise ValueError('bounded_input_exceeded')
        h.update(data)


def regular(path, limit):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError('bounded_regular_input_required')
    return path


def sha_file(path, limit):
    with regular(path, limit).open('rb') as stream: return digest(stream, limit)[0]


def check_record(record):
    if (record.get('kind') != 'emqx-readback' or record.get('version') != 1
            or not record.get('config_roots') or not isinstance(record.get('tables'), dict)):
        raise ValueError('complete_vendor_record_required')
    if not all(HASH.fullmatch(x) for x in record['config_roots'].values()): raise ValueError('root_receipt')
    if set(record['tables']) != set(TABLES): raise ValueError('all_table_receipts_required')
    for value in record['tables'].values():
        if (not isinstance(value, list) or len(value) != 2 or type(value[0]) is not int or value[0] < 0
                or not isinstance(value[1], str) or not HASH.fullmatch(value[1].lower())):
            raise ValueError('table_receipt')
    if record['tables']['emqx_admin'][0] <= 0: raise ValueError('nonempty_admin_required')


def verify_data_tar(path):
    path = regular(path, MAX_DATA); seen = set(); total = 0
    allowed = {'configs', 'mnesia', 'authn', 'authz', 'certs', 'psk', 'node.name', 'woow-ha-import.json'}
    with tarfile.open(path, mode='r:') as archive:
        for member in archive:
            p = PurePosixPath(member.name)
            if member.name in ('.', './'):
                if not member.isdir(): raise ValueError('root_directory_only')
                name = '.'
            else:
                if p.is_absolute() or '..' in p.parts or not p.parts or p.parts[0] not in allowed:
                    raise ValueError('unexpected_candidate_path')
                name = str(p)
            if name in seen or not (member.isdir() or member.isfile()) or member.size < 0 or member.sparse:
                raise ValueError('duplicate_or_nonregular_candidate_member')
            if name.endswith(('.beam', '.so', '.sh', '.py', '.sql')) or any('cookie' in x.lower() for x in p.parts):
                raise ValueError('candidate_code_or_cookie_forbidden')
            if member.mode & 0o7000 or member.uid != 1000 or member.gid != 1000:
                raise ValueError('candidate_metadata')
            seen.add(name); total += member.size
            if total > MAX_DATA or len(seen) > 8192: raise ValueError('candidate_expansion_budget')
    if 'configs/cluster.hocon' not in seen or not any(x.startswith('mnesia/') for x in seen):
        raise ValueError('candidate_database_and_config_required')
    return {'members': len(seen), 'bytes': total, 'sha256': sha_file(path, MAX_DATA)}


def verify_candidate(data_path, manifest_path, *, case, source_commit, data_sha, manifest_sha):
    if case not in CASES or not re.fullmatch('[0-9a-f]{40}', source_commit): raise ValueError('case_or_commit')
    if sha_file(manifest_path, 256 * 1024) != manifest_sha: raise ValueError('manifest_lease_binding')
    doc = json.loads(Path(manifest_path).read_bytes())
    if (doc.get('kind') != 'owned-generated-emqx-candidate' or doc.get('version') != 1
            or doc.get('profile') != PROFILE or doc.get('case') != case or doc.get('source_commit') != source_commit
            or doc.get('image') != IMAGES['broker'] or doc.get('data_sha256') != data_sha
            or doc.get('profile_sha256') != profile.receipt()['sha256']
            or doc.get('origin') != 'controlled-generated-only' or doc.get('restart_checked') is not True
            or doc.get('vendor_postcheck') is not True or doc.get('exact_configuration_and_tables') is not True):
        raise ValueError('candidate_provenance')
    check_record(doc['record'])
    check_record(doc['target_record'])
    facts = verify_data_tar(data_path)
    if facts['sha256'] != data_sha: raise ValueError('candidate_lease_binding')
    return doc


def export_candidate(tmp, destination, *, case, source_commit, record, target_record):
    """Producer hook for a reviewed PACKAGE-SHAPED generated target, before TempObjects cleanup.

    No CLI accepts an arbitrary source volume. The caller must own the actual emqx-new candidate and supply its prior
    native restart receipt. These artifacts cannot be produced from the queued broker-only target profile.
    """
    from woowbackup import ha_emqx as emqx
    if case not in CASES or not re.fullmatch('[0-9a-f]{40}', source_commit): raise ValueError('case_or_commit')
    directory = Path(destination)
    if directory.exists(): raise ValueError('fresh_artifact_directory_required')
    directory.mkdir(mode=0o700)
    current = emqx.candidate_readback(tmp)
    check_record(current)
    if emqx.compare_readback(record, current): raise ValueError('candidate_changed_after_restart')
    read = lambda cmd: tmp.exec('emqx-new', cmd, timeout=120, max_output=emqx.MAX_HOCON, check=False)
    config = emqx.boot_form(read)
    if (config.get('dashboard', {}).get('listeners', {}).get('http', {}).get('bind') != '0.0.0.0:18093'
            or config.get('listeners', {}).get('ws', {}).get('entrance', {}).get('bind') != '127.0.0.1:8093'):
        raise ValueError('package_target_profile_required')
    from types import SimpleNamespace
    quadlet = ('[Container]\nImage='+IMAGES['broker']+'\nContainerName='+tmp.name('emqx-new')+'\n'
               'Volume='+tmp.name('emqx-new')+':/opt/emqx/data\n'
               'Volume='+tmp.name('emqx-new-log')+':/opt/emqx/log\n').encode()
    adapter=SimpleNamespace(runner=tmp.runner,read_quadlets=lambda:{'fixture.container':quadlet})
    app=SimpleNamespace(id='emqx',volumes=[{'name':tmp.name('emqx-new')},{'name':tmp.name('emqx-new-log')}],
                        postgres=None,data_dirs=[])
    messages=[];emqx.verify_restored(adapter,app,current,log=messages.append)
    if len(messages)!=1 or '核對一致' not in messages[0]:raise ValueError('vendor_postcheck_required')
    verify_profile_material(tmp)
    check_record(target_record)
    # Stop the actual owned candidate, not a copied expected configuration.
    tmp.stop('emqx-new', timeout=60)
    data = directory / 'candidate.tar'
    with data.open('xb') as out: tmp.volume_export('emqx-new', out, max_output=MAX_DATA)
    facts = verify_data_tar(data)
    doc = {'kind': 'owned-generated-emqx-candidate', 'version': 1, 'profile': PROFILE, 'case': case,
           'source_commit': source_commit, 'image': IMAGES['broker'], 'origin': 'controlled-generated-only',
           'restart_checked': True, 'vendor_postcheck': True, 'exact_configuration_and_tables': True,
           'record': current, 'target_record': target_record, 'profile_sha256':profile.receipt()['sha256'],
           'data_sha256': facts['sha256']}
    (directory / 'candidate.json').write_text(json.dumps(doc, sort_keys=True) + '\n')
    return {'data_sha256': facts['sha256'], 'manifest_sha256': sha_file(directory / 'candidate.json', 256 * 1024)}


def verify_profile_material(tmp):
    """Actual fixed synthetic files in the candidate, never arbitrary caller-supplied paths."""
    wanted=profile.material_hashes()
    result=tmp.exec('emqx-new',['sha256sum',*wanted],timeout=60,max_output=8192,check=False)
    if result.returncode:raise ValueError('actual_package_material_missing')
    found={}
    for line in result.stdout.decode().splitlines():
        digest_value,path=line.split(None,1);found[path.lstrip('*')]=digest_value
    if found!=wanted:raise ValueError('actual_package_material_hash_mismatch')
    mode=tmp.exec('emqx-new',['stat','-c','%a:%u:%g','/opt/emqx/etc/woow-mqtt-bootstrap.csv'],
                  timeout=60,max_output=1024,check=False)
    if mode.returncode or mode.stdout.strip()!=b'400:1000:1000':raise ValueError('actual_bootstrap_metadata_mismatch')


def verify_oci(path, identity):
    """Verify compressed blob digests AND ordered uncompressed layer hashes against the pinned image config.

    Reads/hashes layer bytes, never extracts them. Only one platform manifest per archive is accepted.
    """
    path = regular(path, MAX_STAGE); blobs = {}; total = 0
    with tarfile.open(path, mode='r:') as archive:
        for item in archive:
            name = str(PurePosixPath(item.name)); total += item.size
            if len(blobs) >= 512: raise ValueError('oci_member_budget')
            if item.isdir(): continue
            if name in blobs or not item.isfile() or item.size < 0 or total > MAX_STAGE:
                raise ValueError('oci_member_budget_or_type')
            if name not in ('index.json', 'oci-layout') and not re.fullmatch('blobs/sha256/[0-9a-f]{64}', name):
                raise ValueError('unexpected_oci_member')
            blobs[name] = item
        def body(name, maximum=1024**2):
            item = blobs[name]
            if item.size > maximum: raise ValueError('oci_json_budget')
            return archive.extractfile(item).read()
        if json.loads(body('oci-layout')).get('imageLayoutVersion') != '1.0.0': raise ValueError('oci_layout')
        index = json.loads(body('index.json'))
        if len(index.get('manifests', [])) != 1: raise ValueError('single_platform_archive_required')
        def descriptor(desc):
            value = desc['digest']
            if not re.fullmatch('sha256:[0-9a-f]{64}', value): raise ValueError('oci_digest')
            name = 'blobs/sha256/' + value[7:]
            if blobs[name].size != desc['size']: raise ValueError('oci_descriptor_size')
            with archive.extractfile(blobs[name]) as stream:
                if digest(stream, MAX_STAGE)[0] != value[7:]: raise ValueError('oci_blob_digest')
            return name
        manifest_name = descriptor(index['manifests'][0]); manifest = json.loads(body(manifest_name))
        config_name = descriptor(manifest['config'])
        if 'sha256:' + config_name.rsplit('/', 1)[1] != identity: raise ValueError('pinned_config_mismatch')
        config = json.loads(body(config_name))
        if config.get('os') != 'linux' or config.get('architecture') != 'amd64': raise ValueError('image_platform')
        layers = manifest['layers']; diffids = config['rootfs']['diff_ids']
        if len(layers) != len(diffids) or not 1<=len(layers)<=64: raise ValueError('image_layers')
        expanded = 0
        for desc, expected in zip(layers, diffids):
            name = descriptor(desc)
            with archive.extractfile(blobs[name]) as raw:
                first = raw.read(2); raw.seek(0)
                stream = gzip.GzipFile(fileobj=raw) if first == b'\x1f\x8b' else raw
                actual, size = digest(stream, 1024**3 - expanded); expanded += size
                if 'sha256:' + actual != expected: raise ValueError('image_diffid')
        return {'config': identity, 'archive_sha256': sha_file(path, MAX_STAGE), 'expanded_bytes': expanded,
                'manifest_digest': 'sha256:' + manifest_name.rsplit('/', 1)[1],
                'archive_bytes':path.stat().st_size,'layer_digests':[x['digest'] for x in layers],'diff_ids':diffids}
