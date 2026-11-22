"""Composition of actual issued-fixture reads and immutable vendor-file reads.

No JSON receipt import, caller paths or mount waiver. Requires the original
WeakKey-issued OwnerProvision token; both helpers read the same held broker.
"""
import re
import weakref
import copy
from emqx_native_runtime import IMAGE
from emqx_target_capture import unsupported
from emqx_target_vendor_policy import DisabledVendorTLS, REFERENCES


_OBSERVATIONS = weakref.WeakKeyDictionary()


class HeldFixtureObservation:
    __slots__ = ('receipts','fixture_receipts','token','broker','cid','generation','__weakref__')

    def __repr__(self):
        return '<HeldFixtureObservation private>'


def capture_composed_files(token, *, generation, broker, owned_container_id,
                           private_eval, private_inspect, private_values):
    from emqx_owner_fixture_files import observe_fixture_files
    from emqx_owner_vendor_files import observe_vendor_files
    observed = HeldFixtureObservation()
    observed.fixture_receipts = observe_fixture_files(token, private_eval=private_eval,
        private_inspect=private_inspect, private_values=private_values)
    vendor = observe_vendor_files(REFERENCES, private_eval=private_eval,
        private_inspect=private_inspect, private_values=private_values, broker=broker,
        owned_container_id=owned_container_id, fixture_capability=token)
    observed.receipts = vendor.receipts
    observed.token, observed.broker = token, broker
    observed.cid, observed.generation = owned_container_id, generation
    _OBSERVATIONS[observed] = (token, broker, owned_container_id, generation,
        copy.deepcopy(observed.receipts), copy.deepcopy(observed.fixture_receipts))
    FixtureFilePolicy(observed,generation)
    return observed


class FixtureFilePolicy(DisabledVendorTLS):
    def __init__(self, observed, generation):
        from emqx_owner_fixture_files import _record, PATHS, ACL, BOOTSTRAP
        if (type(observed) is not HeldFixtureObservation or type(generation) is not str
                or re.fullmatch('[0-9a-f]{32}',generation) is None
                or observed.generation != generation or observed not in _OBSERVATIONS):
            unsupported()
        issued=_OBSERVATIONS[observed]
        if (issued[0] is not observed.token or issued[1:] != (observed.broker, observed.cid,
                observed.generation, observed.receipts, observed.fixture_receipts)):
            unsupported()
        record,_ = _record(observed.token)
        if (record['cid'] != observed.cid or record['fixture'].prefix != observed.broker
                or re.fullmatch('woowbk-emqxlab-[0-9a-f]{8}',observed.broker) is None):
            unsupported()
        super().__init__(observed)
        if len(observed.receipts) != 5 or any(r['container_id'] != observed.cid for r in observed.receipts):
            unsupported()
        receipts=observed.fixture_receipts
        if type(receipts) is not tuple or len(receipts) != len(PATHS):
            unsupported()
        paths=set()
        for item in receipts:
            if (type(item) is not dict or set(item) != {'path','container_id','image','bytes','sha256','identity'}
                    or item['path'] not in PATHS or item['path'] in paths
                    or item['container_id'] != observed.cid or item['image'] != IMAGE
                    or type(item['bytes']) is not int or not 0 < item['bytes'] <= 65536
                    or type(item['sha256']) is not str or re.fullmatch('[0-9a-f]{64}',item['sha256']) is None
                    or type(item['identity']) is not tuple or len(item['identity']) != 10
                    or any(type(v) is not int or not 0 <= v < 2**64 for v in item['identity'])
                    or item['identity'][3] != item['bytes']):
                unsupported()
            paths.add(item['path'])
        if paths != set(PATHS):
            unsupported()
        self.acl_literals += (ACL,)
        self.bootstrap_literals += (BOOTSTRAP,)
