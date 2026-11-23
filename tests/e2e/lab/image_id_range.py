#!/usr/bin/env python3
"""Find the entries of a saved image whose owner is outside a nested rootless ID range (read only).

    python3 -I tests/e2e/lab/image_id_range.py <docker-dir> <max-id>
    podman save --format docker-archive <image ID> | python3 -I tests/e2e/lab/image_id_range.py - <max-id>

<docker-dir> is what `podman save --format docker-dir [--compress]` wrote (manifest.json plus one file per blob, named
by its hex digest); `-` reads a docker-archive stream from stdin instead (nothing is written to disk). <max-id> is the
highest container uid/gid the loading account can map (a lab device's appowner with subuid START:COUNT maps container
ids 0..COUNT). Every layer is read as a tar stream (gzip or plain) and each entry whose uid or gid is above <max-id> is
counted: podman load would fail on it ("potentially insufficient UIDs or GIDs available in user namespace") unless the
load ignores chown errors, which makes those entries belong to the container's root instead. Prints one JSON line:
layers, entries, out_of_range, the owner pairs with their counts, the top directories (first two path parts) with
their counts, and up to ten sample paths. Exit 0 when nothing is out of range, 3 when something is, 2 on a bad
argument."""
import json
import os
import sys
import tarfile
from collections import Counter


class Tally:
    def __init__(self, max_id):
        self.max_id, self.layers, self.entries = max_id, 0, 0
        self.owners, self.tops, self.sample = Counter(), Counter(), []

    def layer(self, fileobj):
        self.layers += 1
        with tarfile.open(fileobj=fileobj, mode='r|*') as tar:
            for member in tar:
                self.entries += 1
                if member.uid <= self.max_id and member.gid <= self.max_id:
                    continue
                name = member.name.lstrip('./').rstrip('/')
                self.owners[f'{member.uid}:{member.gid}'] += 1
                self.tops['/' + '/'.join(name.split('/')[:2])] += 1
                if len(self.sample) < 10:
                    self.sample.append('/' + name)

    def result(self):
        return {'layers': self.layers, 'entries': self.entries, 'max_id': self.max_id,
                'out_of_range': sum(self.owners.values()), 'owners': dict(self.owners.most_common()),
                'top': dict(self.tops.most_common(10)), 'sample': self.sample}


def scan_dir(directory, tally):
    with open(os.path.join(directory, 'manifest.json'), encoding='utf-8') as handle:
        manifest = json.load(handle)
    for layer in manifest['layers']:
        with open(os.path.join(directory, layer['digest'].split(':', 1)[1]), 'rb') as handle:
            tally.layer(handle)


def scan_archive(stream, tally):
    """A docker-archive: an outer tar whose layer members are tar files (<hex>.tar or <hex>/layer.tar)."""
    with tarfile.open(fileobj=stream, mode='r|') as outer:
        for member in outer:
            if member.isfile() and member.name.endswith('.tar'):
                tally.layer(outer.extractfile(member))


def main(argv):
    if len(argv) != 3 or not argv[2].isdigit() or (
            argv[1] != '-' and not os.path.isfile(os.path.join(argv[1], 'manifest.json'))):
        print(__doc__.split('\n\n')[1], file=sys.stderr)
        return 2
    tally = Tally(int(argv[2]))
    if argv[1] == '-':
        scan_archive(sys.stdin.buffer, tally)
    else:
        scan_dir(argv[1], tally)
    result = tally.result()
    print(json.dumps(result, ensure_ascii=False))
    return 3 if result['out_of_range'] else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
