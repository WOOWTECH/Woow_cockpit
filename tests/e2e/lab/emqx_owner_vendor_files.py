"""Private fixed vendor-file proof, never reference-policy authorization.

Owner must hold target writer exclusion throughout and supply REAL bounded
private eval/inspect callbacks for the named container (not acknowledgments).
Only unmounted image files are supported. Invocation ACL/bootstrap mounts need
an independent owner-bound complete-file reader; this observer rejects them.
FreshTarget is build-only: this receipt cannot rebind a restore manifest to other
volumes/nodes/mounts. No CLI, stdout, host paths, environment expansion or API.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from emqx_native_runtime import IMAGE, run_native
from emqx_private_boundary import PrivateFailure
from emqx_semantic_readers import Values, _pairs, _term
from emqx_target_snapshots import pem

LIMIT = 65536
MAX_OUTPUT = 1048576
MAX_WIRE = 4 * ((MAX_OUTPUT + 2) // 3) + 64
CONTRACT = 'emqx-owner-vendor-files-v1'
PATHS = ('/opt/emqx/etc/acl.conf', '/opt/emqx/etc/certs/cacert.pem',
         '/opt/emqx/etc/certs/cert.pem', '/opt/emqx/etc/certs/key.pem')
ALIASES = {p: p for p in PATHS}
ALIASES.update({p.replace('/opt/emqx/etc', '${EMQX_ETC_DIR}', 1): p for p in PATHS})


def _paths(references):
    if type(references) not in (tuple, list) or not 1 <= len(references) <= 8:
        raise ValueError()
    if any(type(p) is not str or p not in ALIASES for p in references):
        raise ValueError()
    return tuple(sorted({ALIASES[p] for p in references}))


# Public code only. Stable identity excludes atime/access, which reads may alter.
_BODY = r'''
    Stable = fun(I) -> [element(N,I) || N <- [10,11,12,2,6,7,8,9,13,14]] end,
    Info = fun(P) -> {ok,I} = file:read_link_info(P,[{time,posix}]), I end,
    Typed = fun T(_,D) when D > 16 -> throw(depth);
        T(V,_) when is_binary(V) -> #{type => <<"binary">>,value => base64:encode(V)};
        T(V,_) when is_atom(V) -> #{type => <<"atom">>,value => atom_to_binary(V,utf8)};
        T(V,_) when is_integer(V) -> #{type => <<"integer">>,value => V};
        T(V,_) when is_float(V) -> #{type => <<"float">>,value => V};
        T(V,D) when is_tuple(V) -> #{type => <<"tuple">>,value => [T(X,D+1)||X<-tuple_to_list(V)]};
        T(V,D) when is_list(V) -> #{type => <<"list">>,value => [T(X,D+1)||X<-V]};
        T(V,D) when is_map(V) -> #{type => <<"map">>,value => [[T(K,D+1),T(X,D+1)]||{K,X}<-maps:to_list(V)]};
        T(_,_) -> throw(unsupported) end,
    Terms = fun Parse([],[],Acc) -> lists:reverse(Acc);
        Parse([T|Rest],Pending,Acc) -> case element(1,T) of
            dot -> {ok,V}=erl_parse:parse_term(lists:reverse([T|Pending])),
                   Parse(Rest,[],[Typed(V,0)|Acc]);
            _ -> Parse(Rest,[T|Pending],Acc) end;
        Parse(_,_,_) -> throw(incomplete) end,
    Files = [begin
        Dirs = case filename:dirname(P) of
            "/opt/emqx/etc/certs" -> ["/opt","/opt/emqx","/opt/emqx/etc","/opt/emqx/etc/certs"];
            _ -> ["/opt","/opt/emqx","/opt/emqx/etc"] end,
        DirIDs = [begin DI=Info(D), directory=element(3,DI), Stable(DI) end || D<-Dirs],
        Before=Info(P), regular=element(3,Before), 1=element(9,Before),
        Size=element(2,Before), true=Size>0 andalso Size=<65536,
        ID=Stable(Before),
        {ok,F}=file:open(P,[read,binary,raw]),
        Raw = try
            {ok,FI}=file:read_file_info(F,[{time,posix}]), regular=element(3,FI), ID=Stable(FI),
            {ok,B}=file:read(F,65537), true=byte_size(B)=:=Size,
            eof=file:read(F,1),
            {ok,FA}=file:read_file_info(F,[{time,posix}]), ID=Stable(FA), B
        after ok=file:close(F) end,
        After=Info(P), regular=element(3,After), ID=Stable(After),
        DirIDs=[begin DI2=Info(D),directory=element(3,DI2),Stable(DI2) end || D<-Dirs],
        Parsed=case P of "/opt/emqx/etc/acl.conf" ->
            {ok,Tokens,_}=erl_scan:string(unicode:characters_to_list(Raw)),
            true=length(Tokens)=<16384, TS=Terms(Tokens,[],[]),true=TS=/=[],TS;
            _ -> [] end,
        #{path=>list_to_binary(P),bytes=>Size,identity=>ID,
          content_b64=>base64:encode(Raw),
          sha256=>list_to_binary(string:lowercase(binary_to_list(binary:encode_hex(crypto:hash(sha256,Raw))))),terms=>Parsed}
    end || P <- PATH_LIST],
    Out=jsone:encode(#{contract=><<"emqx-owner-vendor-files-v1">>,complete=>true,files=>Files}),
    true=byte_size(Out)=<1048576,
'''


def _body(paths):
    # Every literal comes from PATHS, never caller/archive text.
    return _BODY.replace('PATH_LIST', '[' + ','.join(json.dumps(p) for p in paths) + ']')


def public_expression(references):
    """Fixed public expression; runner must bound time, output and stderr privately."""
    try:
        source = ('begin ' + _body(_paths(references)) +
                  'io:put_chars([<<"WOOWVENDOR:">>,base64:encode(Out),<<":END">>]), ok end.')
        # CLI eval rejects multiline arguments. Only this fixed public source is
        # folded; no caller/private content is interpolated or rewritten.
        return ' '.join(line.strip() for line in source.splitlines())
    except Exception:
        raise PrivateFailure('private-vendor-files-refused') from None


def _image_files(paths):
    with tempfile.TemporaryDirectory(prefix='emqx-vendor-files-') as directory:
        os.chmod(directory, 0o700)
        script = Path(directory) / 'observe.escript'
        script.write_text('#!/usr/bin/env escript\n%%! +S 1:1 +A 1 +hmax 8388608 -noshell\n'
            'main([]) -> try code:add_paths(filelib:wildcard("/opt/emqx/lib/*/ebin")),\n' +
            _body(paths) + 'io:put_chars(Out) catch _:_ -> halt(2) end;\nmain(_) -> halt(2).\n')
        script.chmod(0o600)
        with tempfile.TemporaryFile() as output:
            if run_native(Path(directory), script.name, output=output) != 0:
                raise ValueError()
            output.seek(0)
            raw = output.read(MAX_OUTPUT + 1)
            return _decode(raw, paths)


def _decode(raw, paths):
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_OUTPUT:
        raise ValueError()
    doc = json.loads(raw, object_pairs_hook=_pairs)
    if (type(doc) is not dict or set(doc) != {'contract', 'complete', 'files'} or
            doc['contract'] != CONTRACT or doc['complete'] is not True or
            type(doc['files']) is not list or len(doc['files']) != len(paths)):
        raise ValueError()
    result = []
    for path, item in zip(paths, doc['files']):
        if type(item) is not dict or set(item) != {'path', 'bytes', 'identity', 'content_b64', 'sha256', 'terms'}:
            raise ValueError()
        if item['path'] != path or type(item['bytes']) is not int or not 1 <= item['bytes'] <= LIMIT:
            raise ValueError()
        identity = item['identity']
        if (type(identity) is not list or len(identity) != 10 or
                any(type(v) is not int or v < 0 or v >= 2**64 for v in identity) or
                identity[3] != item['bytes'] or identity[7] != 1 or
                identity[6] & 0o170000 != 0o100000):
            raise ValueError()
        content = base64.b64decode(item['content_b64'], validate=True)
        if len(content) != item['bytes'] or hashlib.sha256(content).hexdigest() != item['sha256']:
            raise ValueError()
        if type(item['terms']) is not list or (path.endswith('acl.conf') != bool(item['terms'])):
            raise ValueError()
        result.append((item, content))
    return result


def _provenance(private_inspect, broker, cid, paths):
    raw = private_inspect()
    if type(raw) is not bytes or not 1 <= len(raw) <= LIMIT:
        raise ValueError()
    docs = json.loads(raw, object_pairs_hook=_pairs)
    if type(docs) is not list or len(docs) != 1 or type(docs[0]) is not dict:
        raise ValueError()
    doc = docs[0]
    host = doc['HostConfig']
    image = doc['Image']
    if (type(image) is not str or image not in (IMAGE, IMAGE.removeprefix('sha256:')) or
            doc['Id'] != cid or doc['Name'].lstrip('/') != broker or
            doc['State']['Running'] is not True or host['NetworkMode'] != 'none' or
            host['PortBindings'] not in ({}, None) or host['LogConfig']['Type'] != 'none'):
        raise ValueError()
    env = doc['Config']['Env']
    if type(env) is not list or any(type(v) is not str for v in env):
        raise ValueError()
    etc = [v for v in env if v.split('=', 1)[0] == 'EMQX_ETC_DIR']
    if etc not in ([], ['EMQX_ETC_DIR=/opt/emqx/etc']):
        raise ValueError()
    mounts = doc['Mounts']
    if type(mounts) is not list:
        raise ValueError()
    for mount in mounts:
        dest = mount['Destination']
        if (mount['Type'] not in ('bind', 'volume', 'tmpfs') or type(dest) is not str or
                not dest.startswith('/') or (dest != '/' and any(x in ('', '.', '..') for x in dest[1:].split('/')))):
            raise ValueError()
        if any(dest == '/' or p == dest or p.startswith(dest + '/') for p in paths):
            raise ValueError()
    # Compare complete provenance fields, including sources/IDs, without printing them.
    return (doc['Id'], doc['Name'], IMAGE, env, host, mounts)


class VendorFiles:
    """Private receipts only, not permission to relax any semantic guard."""
    def __init__(self, receipts):
        self.receipts = tuple(receipts)

    def __repr__(self):
        return '<VendorFiles private>'


def observe_vendor_files(references, *, private_eval, private_inspect, broker,
                         owned_container_id, private_values):
    """Compare complete stable image/broker reads and register all private values.

    Both callbacks must execute against the same held owner target; they cannot
    be authenticated by JSON assertions. No boolean provenance acknowledgment is
    accepted. Image observation uses the existing bounded immutable native runner.
    Owner eval must bound execution to 10 seconds, stdout to MAX_WIRE, discard
    stderr and terminate its process group on timeout. Inspect must bound execution
    to 5 seconds and stdout to LIMIT, discarding stderr. Callbacks receive no
    credential material. These are trusted owner-runner obligations, not JSON
    attestations; Python additionally checks every returned byte bound.
    """
    try:
        paths = _paths(references)
        if (not callable(private_eval) or not callable(private_inspect) or
                type(private_values) is not Values or type(broker) is not str or
                re.fullmatch(r'woowbk-emqx-(?:fresh|workload)-[0-9a-f]{12}', broker) is None or
                type(owned_container_id) is not str or
                re.fullmatch(r'[0-9a-f]{64}', owned_container_id) is None):
            raise ValueError()
        before = _provenance(private_inspect, broker, owned_container_id, paths)
        image = _image_files(paths)
        wire = private_eval(public_expression(list(paths)))
        if type(wire) is not bytes or len(wire) > MAX_WIRE:
            raise ValueError()
        match = re.fullmatch(rb'WOOWVENDOR:([A-Za-z0-9+/=]+):ENDok\n?', wire)
        if match is None:
            raise ValueError()
        actual = _decode(base64.b64decode(match[1], validate=True), paths)
        if before != _provenance(private_inspect, broker, owned_container_id, paths):
            raise ValueError()
        pending = Values()
        receipts = []
        for (baseline, raw), (observed, content) in zip(image, actual):
            if raw != content or baseline['terms'] != observed['terms']:
                raise ValueError()
            pending.add(content)
            if observed['path'].endswith('acl.conf'):
                for term in observed['terms']:
                    _term(term, pending, historical=True)
            else:
                for value in pem(content, 'key' if observed['path'].endswith('/key.pem') else 'cert'):
                    pending.add(value)
            receipts.append({'path': observed['path'], 'image': IMAGE,
                'container_id': owned_container_id, 'bytes': len(content),
                'sha256': observed['sha256'], 'image_identity': tuple(baseline['identity']),
                'target_identity': tuple(observed['identity'])})
        trial = Values()
        for value in private_values.values + pending.values:
            trial.add(value)
        for value in pending.values:
            private_values.add(value)
        return VendorFiles(receipts)
    except Exception:
        raise PrivateFailure('private-vendor-files-refused') from None
