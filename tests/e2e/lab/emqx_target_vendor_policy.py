"""Narrow reference authorization from a trusted, held vendor observation lease.

The callback must observe pinned image and actual owned broker files, register
complete bytes/PEM representations in supplied Values, and repeat observation on
lease exit. A receipt is not a standalone JSON authorization capability.
"""
import re
from emqx_native_runtime import IMAGE
from emqx_target_capture import unsupported

FILES = {'certfile': 'cert.pem', 'keyfile': 'key.pem', 'cacertfile': 'cacert.pem'}
REFERENCES = tuple('${EMQX_ETC_DIR}/certs/' + name for name in FILES.values())


class DisabledVendorTLS:
    def __init__(self, observed):
        self.paths = set()
        receipts = observed.receipts
        if type(receipts) not in (tuple, list) or len(receipts) != 3:
            unsupported()
        cid = None
        for item in receipts:
            if type(item) is not dict:
                unsupported()
            path = item.get('path')
            if (path not in {'/opt/emqx/etc/certs/' + name for name in FILES.values()}
                    or path in self.paths or item.get('image') != IMAGE
                    or type(item.get('bytes')) is not int or not 1 <= item['bytes'] <= 65536
                    or type(item.get('sha256')) is not str
                    or re.fullmatch('[0-9a-f]{64}', item['sha256']) is None
                    or type(item.get('container_id')) is not str
                    or re.fullmatch('[0-9a-f]{64}', item['container_id']) is None
                    or not item.get('image_identity') or not item.get('target_identity')):
                unsupported()
            if cid is not None and cid != item['container_id']:
                unsupported()
            cid = item['container_id']
            self.paths.add(path)

    def allows(self, config, path, text):
        if (len(path) != 5 or path[0] != 'listeners' or path[1] not in ('ssl', 'wss')
                or path[2:4] != ('default', 'ssl_options') or path[4] not in FILES):
            return False
        listener = config['listeners'][path[1]]['default']
        filename = FILES[path[4]]
        return (listener.get('enable') == 'false'
                and text == '${EMQX_ETC_DIR}/certs/' + filename
                and '/opt/emqx/etc/certs/' + filename in self.paths)


def vendor_observer(*, broker, owned_container_id, private_eval, private_inspect):
    """Bind Bernoulli's actual observer to one owner lease; never accept JSON code.

    Immutable IMAGE is the fixed expected public-content authority: helper reads
    that image, compares every byte with the actual broker and registers bytes.
    No caller-selected digest can replace this comparison.
    """
    from contextlib import contextmanager

    @contextmanager
    def observe(*, generation, private_values):
        from emqx_owner_vendor_files import observe_vendor_files
        if type(generation) is not str or re.fullmatch('[0-9a-f]{32}', generation) is None:
            unsupported()
        def capture():
            return observe_vendor_files(REFERENCES, private_eval=private_eval,
                private_inspect=private_inspect, broker=broker,
                owned_container_id=owned_container_id, private_values=private_values)
        before = capture()
        DisabledVendorTLS(before)
        yield before
        after = capture()
        if before.receipts != after.receipts:
            unsupported()
    return observe
