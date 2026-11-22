"""Original SHA-bound B1 retained payload consensus, NOT final-row truth.

Offline native DETS/disk_log decoder only; no broker, replay, target, CLI, env,
credential-file reader or output. Fixed B1 source profiles, all used cold files,
authenticated addon EOF, complete strict tar traversal, native EOF and original
archive final stamp must succeed before private payload bytes escape. Every
historical retained record for a requested topic must have exactly one payload.
Deletion/order/expiry are not replayed; final presence still requires live MQTT.
"""
import base64
import json
import re
import tarfile
import time

from emqx_cold_history import native_cold_history, read_cold_history
from emqx_source_consumer import cold_kind
from emqx_source_profiles import source_profile
from emqx_private_spool import capture
from emqx_semantic_readers import MAX_INPUT, Values
from emqx_persisted_values import PersistedValues
from emqx_private_boundary import PrivateFailure
from ha_real_fixture import source_binding
from woowbackup import hacommon, habackup, ha_emqx, hasecuretar

MODES = ('--source-vendor-acl-sql-aliases','--x86-source-vendor-acl-sql-aliases')
SECONDS = 120


class RetainedHistory:
    def __init__(self, pairs, scanner, digest):
        self._pairs, self._scanner = tuple(pairs), scanner
        self.source_sha256 = digest

    @property
    def final_state(self):
        return False

    def __repr__(self):
        return '<B1 private original retained payload history>'

    def private_pairs(self):
        """RAM-only client frame inputs, never stdout/argv/env/evidence."""
        return self._pairs

    def scan(self, payload):
        self._scanner.scan(payload)


def _binary(term):
    if type(term) is not dict or term.get('type') != 'binary':
        raise ValueError()
    return base64.b64decode(term['value'],validate=True)


def _records(term, matches):
    kind, value = term['type'], term['value']
    if kind == 'tuple' and value and value[0] == {'type':'atom','value':'retained_message'}:
        # Pinned emqx_retainer_mnesia retained_message{topic,msg,expiry_time}.
        if len(value) != 4 or value[1]['type'] != 'list' or value[2]['type'] != 'tuple':
            raise ValueError()
        key = b'/'.join(_binary(x) for x in value[1]['value'])
        msg = value[2]['value']
        # Pinned emqx_message.hrl: tag,id,qos,from,flags,headers,topic,payload,ts,extra.
        if len(msg) != 10 or msg[0] != {'type':'atom','value':'message'}:
            raise ValueError()
        topic, payload = _binary(msg[6]), _binary(msg[7])
        if key != topic:
            raise ValueError()
        if topic in matches:
            if not 0 < len(payload) <= 4096:
                raise ValueError()
            matches[topic].add(payload)
            if len(matches[topic]) != 1:
                raise ValueError()
    if kind in ('tuple','list'):
        for child in value:
            _records(child,matches)
    elif kind == 'map':
        for key, child in value:
            _records(key,matches);_records(child,matches)


def collect_original_retained_payloads(*, source_mode, password, topics, spool_directory, source_path=None):
    """Topics are the TWO source-summary topics, supplied privately by owner.

    Does not read summary/credentials or guess topic names. Existing source_mode
    fixes the original SHA/architecture. source_path optionally selects a staged
    copy of that EXACT cipher; no supplied digest/decoder. source_binding opens
    read-only/O_NOFOLLOW, requires a regular file, binds all reads to its FD and
    checks the original full SHA plus before/after identity stamps. Same default256MiB / explicit290785280-byte x86 spool profile,
    12GiB reserve and private700/600 cleanup. <=64 cold files, each8MiB,total32MiB;
    120s cooperative deadline checked around IO/native calls (native wall20s/file).
    This may conservatively refuse divergent history despite a valid final row.
    """
    try:
        if (source_mode not in MODES or type(password) is not str or not password or
                type(topics) not in (tuple,list) or len(topics)!=2 or
                any(type(x) is not bytes or re.fullmatch(rb'b1/retained/[A-Za-z0-9_/-]{1,110}',x) is None for x in topics) or
                len(set(topics)) != 2):
            raise ValueError()
        profile=source_profile(source_mode)
        deadline=time.monotonic()+SECONDS
        def timely():
            if time.monotonic() >= deadline:raise ValueError()
        keys=hasecuretar.Keys(password)
        values=Values();values.add(password.encode())
        matches={topic:set() for topic in topics}
        with source_binding(profile.archive if source_path is None else source_path,'emqx',hacommon.semver('5.8.9'),profile.sha256,
                            keys=keys,required_encryption='v3') as source:
            timely()
            if source['addon_info']('woow-emqx').arch != profile.arch:
                raise ValueError()
            slug=source['addon_member']('woow-emqx')
            with source['open'](slug) as incoming:
                options = ({'fixture_profile':profile.fixture_profile,'verified_sha256':profile.sha256}
                           if profile.fixture_profile is not None else {})
                with capture(incoming,spool_directory,**options) as (captured,_digest,_size):
                    timely()
                    report=habackup.Report()
                    for _ in habackup.iter_entries(captured,report=report,addon=True):timely()
                    if not report.complete:raise ValueError()
                    captured.seek(0);cold={};size=0
                    with tarfile.open(fileobj=captured,mode='r:') as archive:
                        for entry in archive:
                            timely();name=habackup.normalize(entry.name)
                            if entry.isdir() or not name.startswith(ha_emqx.DATA+'/mnesia/'):continue
                            if not entry.isfile() or name in cold or not 0 < entry.size <= MAX_INPUT:
                                raise ValueError()
                            size+=entry.size
                            if len(cold)>=64 or size>32*1024**2:raise ValueError()
                            handle=archive.extractfile(entry)
                            try:raw=handle.read(MAX_INPUT+1)
                            finally:handle.close()
                            if len(raw)!=entry.size:raise ValueError()
                            cold[name]=(raw,cold_kind(name,len(raw)))
                    if sum(kind=='schema-dat' for _,kind in cold.values())!=1:raise ValueError()
                    for raw,kind in cold.values():
                        timely();encoded=native_cold_history(raw,kind);timely()
                        observed=read_cold_history(raw,kind,lambda *_:encoded)
                        for value in observed.values:values.add(value)
                        # Already validated duplicate-free contract, digest and ALL typed terms.
                        for term in json.loads(encoded)['terms']:_records(term,matches)
                    timely()
        # source_binding's final stamp must succeed before returning any pair.
        timely()
        if any(len(found)!=1 for found in matches.values()):raise ValueError()
        pairs=tuple((topic,next(iter(matches[topic]))) for topic in topics)
        for topic,payload in pairs:values.add(topic);values.add(payload)
        return RetainedHistory(pairs,PersistedValues('source-retained-history','source',{},values.values),profile.sha256)
    except (KeyboardInterrupt,SystemExit):
        raise PrivateFailure('retained-history-cancelled') from None
    except Exception:
        raise PrivateFailure('retained-history-refused') from None
