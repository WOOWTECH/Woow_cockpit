"""Private reader for files created by this invocation's OwnerProvision only.

No policy bypass or restore/manifest rebinding. Caller holds SAME target writer
exclusion throughout. Bootstrap is a freshly issued Podman secret, not a host
file. The actual fixture mounts base.hocon; emqx.conf aliases are unsupported.
Trusted callbacks execute bounded eval/inspect against the capability's broker:
10s/MAX_WIRE and 5s/64KiB respectively, stderr discarded, process-group timeout
cleanup. No caller-selected host paths, default credentials, CLI or stdout.
"""
import base64
import hashlib
import json
import os
import re
import stat
import weakref

from emqx_native_runtime import IMAGE
from emqx_bootstrap_csv import collect_bootstrap_csv
from emqx_owner_vendor_files import _BODY, _decode, LIMIT, MAX_OUTPUT, MAX_WIRE, CONTRACT
from emqx_private_boundary import PrivateFailure
from emqx_semantic_readers import Values, _pairs, _term

ACL = '/opt/emqx/etc/lab-acl.conf'
BOOTSTRAP = '/opt/emqx/etc/lab-bootstrap.csv'
BASE = '/opt/emqx/etc/base.hocon'
PATHS = tuple(sorted((ACL, BOOTSTRAP, BASE)))
_RECORDS = weakref.WeakKeyDictionary()


class FixtureFiles:
    __slots__ = ('__weakref__',)

    def __repr__(self):
        return '<FixtureFiles private>'


def _fail():
    raise PrivateFailure('private-fixture-files-refused') from None


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _source_files(provision):
    """Read only newly issued fixed leaves through no-follow directory FDs."""
    f, runner = provision.fixture, provision.runner
    descriptors = []
    try:
        parent = os.open(runner.home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(parent)
        for part in ('.config', f.prefix):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            descriptors.append(child)
            parent = child
        directories = tuple(_identity(os.fstat(fd)) for fd in descriptors)
        if any(os.fstat(fd).st_uid != os.geteuid() for fd in descriptors):
            raise ValueError()
        result = {}
        for inside, leaf in ((BASE, 'base.hocon'), (ACL, 'acl.conf')):
            before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                    before.st_uid != os.geteuid() or not 0 < before.st_size <= LIMIT):
                raise ValueError()
            fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                identity = _identity(before)
                if _identity(os.fstat(fd)) != identity:
                    raise ValueError()
                chunks, size = [], 0
                while True:
                    chunk = os.read(fd, min(16384, LIMIT + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > LIMIT:
                        raise ValueError()
                if (size != before.st_size or _identity(os.fstat(fd)) != identity or
                        _identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)) != identity):
                    raise ValueError()
                result[inside] = (b''.join(chunks), identity)
            finally:
                os.close(fd)
        if directories != tuple(_identity(os.fstat(fd)) for fd in descriptors):
            raise ValueError()
        # Directory names must still address the same FDs, not renamed replacements.
        for parent_fd, child_fd, name in zip(descriptors, descriptors[1:], ('.config', f.prefix)):
            if _identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) != _identity(os.fstat(child_fd)):
                raise ValueError()
        return result
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def _secret(provision):
    # Only the just-created secret name. Values return privately, never diagnostics.
    raw = provision.runner.podman('secret', 'inspect', '--showsecret', provision.fixture.secret,
        timeout=5, max_output=2 * LIMIT).stdout
    if type(raw) is not bytes or not 0 < len(raw) <= 2 * LIMIT:
        raise ValueError()
    rows = json.loads(raw, object_pairs_hook=_pairs)
    if type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict:
        raise ValueError()
    doc = rows[0]
    if (type(doc.get('ID')) is not str or re.fullmatch(r'[a-z0-9]{16,64}', doc['ID']) is None or
            doc['Spec']['Name'] != provision.fixture.secret or type(doc.get('SecretData')) is not str):
        raise ValueError()
    data = doc['SecretData'].encode('utf-8')
    if not 0 < len(data) <= LIMIT:
        raise ValueError()
    return doc['ID'], data


def _issue(provision, base, acl, bootstrap):
    """Private issuance callsite: only after successful actual OwnerProvision.create."""
    try:
        from emqx_adapter_owner import OwnerProvision
        if (type(provision) is not OwnerProvision or getattr(provision, 'file_capability', None) is not None or
                provision.fixture.image_id != IMAGE.removeprefix('sha256:') or
                any(type(x) is not bytes or not 0 < len(x) <= LIMIT for x in (base, acl, bootstrap))):
            raise ValueError()
        created = set(provision.created)
        f = provision.fixture
        required = {('config', '.config/' + f.prefix), ('secret', f.secret),
                    ('unit', '.config/containers/systemd/' + f.prefix + '.container')}
        if not required <= created:
            raise ValueError()
        files = _source_files(provision)
        if files[BASE][0] != base or files[ACL][0] != acl:
            raise ValueError()
        secret_id, data = _secret(provision)
        if data != bootstrap:
            raise ValueError()
        _csv(bootstrap, Values())
        token = FixtureFiles()
        _RECORDS[token] = {'owner': weakref.ref(provision), 'files': files,
            'secret': (secret_id, data), 'cid': None, 'fixture': f, 'runner': provision.runner,
            'home': provision.runner.home}
        return token
    except BaseException:
        _fail()


def revoke(token):
    _RECORDS.pop(token, None)


def _record(token):
    if type(token) is not FixtureFiles or token not in _RECORDS:
        raise ValueError()
    record = _RECORDS[token]
    provision = record['owner']()
    if (provision is None or provision.file_capability is not token or
            provision.fixture is not record['fixture'] or provision.runner is not record['runner'] or
            provision.runner.home != record['home']):
        raise ValueError()
    return record, provision


def _csv(raw, values):
    # Custom invocation fixture remains seeded; vendor header-only allowance is
    # never selected for this capability.
    return collect_bootstrap_csv(raw, values)


def public_expression():
    """Fixed single-line public producer; no private file contents in argv."""
    body = _BODY.replace('PATH_LIST', '[' + ','.join(json.dumps(p) for p in PATHS) + ']')
    body = body.replace('/opt/emqx/etc/acl.conf', ACL)
    # Both complete HOCON syntax strings (including overwritten leaves) and the
    # transformed document. No include, substitution, file/env resolution step.
    body = body.replace('_ -> [] end,', '''"/opt/emqx/etc/base.hocon" ->
        HT=hocon_token:scan(Raw,#{}),true=length(HT)=<32768,
        lists:foreach(fun(X)->case element(1,X) of include->throw(reference);variable->throw(reference);_->ok end end,HT),
        Tree=hocon_token:parse(hocon_token:trans_key(hocon_token:rm_trailing_comma(HT)),#{}),
        Doc=hocon:transform(hocon:concat(hocon:expand(Tree)),#{format=>map}),
        Leaves=fun L(_,D) when D>32 -> throw(depth);
            L(#{'$hcTyp':=K},_) when K=:=include;K=:=variable -> throw(reference);
            L(#{'$hcTyp':=K,'$hcVal':=V},D) when K=:=object;K=:=array -> L(V,D+1);
            L(#{'$hcVal':=V},D) -> L(V,D);
            L({keypath,V},D) -> L(V,D);
            L(V,_) when is_binary(V) -> [V];
            L(V,D) when is_tuple(V) -> lists:append([L(X,D)||X<-tuple_to_list(V)]);
            L(V,D) when is_map(V) -> lists:append([L(K,D)++L(X,D)||{K,X}<-maps:to_list(V)]);
            L(V,D) when is_list(V) -> case io_lib:printable_unicode_list(V) andalso V=/=[] of
                true -> [unicode:characters_to_binary(V)];
                false -> lists:append([L(X,D)||X<-V]) end;
            L(_,_) -> [] end,
        Syntax=Leaves(Tree,0),true=length(Syntax)=<8192,
        [Typed(Syntax,0),Typed(Doc,0)]; _ -> [] end,''')
    source = ('begin ' + body +
        'io:put_chars([<<"WOOWFIXTURE:">>,base64:encode(Out),<<":END">>]), ok end.')
    return ' '.join(line.strip() for line in source.splitlines())


def _decode_files(raw):
    # Reuse strict bounded file/identity decoder; it expects only ACL terms, so
    # validate base syntax/document terms separately while preserving exact document shape.
    doc = json.loads(raw, object_pairs_hook=_pairs)
    if type(doc) is not dict or type(doc.get('files')) is not list:
        raise ValueError()
    config_terms = None
    for item in doc['files']:
        if type(item) is dict and item.get('path') == BASE:
            config_terms = item.get('terms')
            if type(config_terms) is not list or len(config_terms) != 2:
                raise ValueError()
            item['terms'] = []
    decoded = _decode(json.dumps(doc, separators=(',', ':')).encode(), PATHS)
    if config_terms is None:
        raise ValueError()
    for item, _ in decoded:
        if item['path'] == BASE:
            item['terms'] = config_terms
    return decoded


def _inspect(callback, record, provision):
    raw = callback()
    if type(raw) is not bytes or not 0 < len(raw) <= LIMIT:
        raise ValueError()
    rows = json.loads(raw, object_pairs_hook=_pairs)
    if type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict:
        raise ValueError()
    doc = rows[0]
    f = provision.fixture
    f.validate_inspection(doc)
    if (type(doc.get('Image')) is not str or doc['Image'] not in (IMAGE, IMAGE.removeprefix('sha256:')) or
            type(doc.get('Id')) is not str or re.fullmatch('[0-9a-f]{64}', doc['Id']) is None or
            doc['State']['Running'] is not True or doc['HostConfig'].get('PidsLimit') != 512 or
            type(doc['Config']['Env']) is not list or
            any(type(x) is not str for x in doc['Config']['Env']) or
            [x for x in doc['Config']['Env'] if x.split('=', 1)[0] == 'EMQX_NODE__NAME'] !=
                ['EMQX_NODE__NAME=emqx@127.0.0.1']):
        raise ValueError()
    if record['cid'] is not None and doc['Id'] != record['cid']:
        raise ValueError()
    mounts = doc['Mounts']
    expected = {BASE: provision.runner.home + '/.config/' + f.prefix + '/base.hocon',
                ACL: provision.runner.home + '/.config/' + f.prefix + '/acl.conf'}
    for path in PATHS:
        matches = []
        for mount in mounts:
            dest = mount['Destination']
            if (type(dest) is not str or not dest.startswith('/') or
                    (dest != '/' and any(p in ('', '.', '..') for p in dest[1:].split('/')))):
                raise ValueError()
            if dest == '/' or dest == path or path.startswith(dest + '/'):
                matches.append(mount)
        if (len(matches) != 1 or matches[0]['Destination'] != path or
                matches[0]['Type'] != 'bind' or matches[0]['RW'] is not False or
                type(matches[0].get('Source')) is not str):
            raise ValueError()
        if path in expected and matches[0]['Source'] != expected[path]:
            raise ValueError()
    secrets = doc['Config']['Secrets']
    if type(secrets) is not list:
        raise ValueError()
    bootstrap = [x for x in secrets if type(x) is dict and x.get('Name') == f.secret]
    if len(bootstrap) != 1 or bootstrap[0].get('ID') != record['secret'][0]:
        raise ValueError()
    record['cid'] = doc['Id']
    return (doc['Id'], IMAGE, doc['Config'], doc['HostConfig'], mounts)


def observe_fixture_files(token, *, private_eval, private_inspect, private_values):
    """Prove all three fixed dependencies atomically; receipt is NOT policy consent."""
    try:
        record, provision = _record(token)
        if not callable(private_eval) or not callable(private_inspect) or type(private_values) is not Values:
            raise ValueError()
        before = _inspect(private_inspect, record, provision)
        if _source_files(provision) != record['files'] or _secret(provision) != record['secret']:
            raise ValueError()
        wire = private_eval(public_expression())
        if type(wire) is not bytes or len(wire) > MAX_WIRE:
            raise ValueError()
        match = re.fullmatch(rb'WOOWFIXTURE:([A-Za-z0-9+/=]+):ENDok\n?', wire)
        if match is None:
            raise ValueError()
        raw = base64.b64decode(match[1], validate=True)
        if not 0 < len(raw) <= MAX_OUTPUT:
            raise ValueError()
        decoded = _decode_files(raw)
        if (before != _inspect(private_inspect, record, provision) or
                _source_files(provision) != record['files'] or _secret(provision) != record['secret']):
            raise ValueError()
        pending = Values()
        receipts = []
        for item, content in decoded:
            expected = record['secret'][1] if item['path'] == BOOTSTRAP else record['files'][item['path']][0]
            if content != expected:
                raise ValueError()
            pending.add(content)
            if item['path'] == BOOTSTRAP:
                _csv(content, pending)
            else:
                for term in item['terms']:
                    _term(term, pending, historical=True)
            receipts.append({'path': item['path'], 'container_id': record['cid'],
                'image': IMAGE, 'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest(),
                'identity': tuple(item['identity'])})
        # Recheck capability lifetime after callbacks; cleanup may have revoked it.
        if _record(token)[0] is not record:
            raise ValueError()
        trial = Values()
        for value in private_values.values + pending.values:
            trial.add(value)
        for value in pending.values:
            private_values.add(value)
        return tuple(receipts)
    except BaseException:
        _fail()
