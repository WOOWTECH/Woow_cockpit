#!/usr/bin/env python3
"""Read-only observer of the engine's SQLite sandbox children inside a lab device (integration lane, 2026-11-23).

It runs INSIDE the device as root, fed on stdin, next to a real import run:

  labpodman exec -i woowbk-dev-c python3 -I - SECONDS NAME=SHA256 ... < tests/e2e/lab/sandbox_netns_sampler.py

NAME=SHA256 names a child by the sha256 of its program text (argv[4] of `python3 -I -S -c PROGRAM ...`), e.g.
n8n=<sha256 of woowbackup.ha_n8n.SQLITE_CHILD>. Every 10 ms it lists /proc, follows each matching child until its
effective uid is no longer 0 (the child drops to nobody only after it left the network namespace and chrooted:
ha_n8n.SQLITE_CHILD / hasqlite.CHILD), and prints one JSON line for it: whether its network namespace differs from
the device's PID 1 and whether its root is no longer "/". A child that ends before it drops is reported as such.
It only reads /proc (cmdline, status, the ns/net and root links); it never signals, traces or changes anything.
The program text, paths and arguments are not printed (only the name, counts and booleans).
"""
import hashlib
import json
import os
import sys
import time


def read_child(proc, pid, expect):
    """(name, argc) when /proc/<pid> is one of the expected sandbox children, else None."""
    try:
        with open(os.path.join(proc, pid, 'cmdline'), 'rb') as handle:
            argv = handle.read().split(b'\0')
    except OSError:
        return None
    if argv and argv[-1] == b'':
        argv = argv[:-1]
    if len(argv) < 5 or argv[1:4] != [b'-I', b'-S', b'-c']:
        return None
    digest = hashlib.sha256(argv[4]).hexdigest()
    for name, want in expect.items():
        if want == digest:
            return name, len(argv) - 5
    return None


def observe(proc, pid):
    """(effective uid, netns link, root link) or None when the process is gone or unreadable."""
    try:
        with open(os.path.join(proc, pid, 'status'), encoding='ascii', errors='replace') as handle:
            uids = next(line.split()[1:3] for line in handle if line.startswith('Uid:'))
        netns = os.readlink(os.path.join(proc, pid, 'ns', 'net'))
        root = os.readlink(os.path.join(proc, pid, 'root'))
    except (OSError, StopIteration, IndexError):
        return None
    return int(uids[1]), netns, root


def scan(proc, expect, init_netns, pending, done, emit, now=lambda: time.strftime('%H:%M:%S')):
    """One pass over `proc`; `pending` maps pid -> (name, argc), `done` holds finished pids."""
    live = set()
    for pid in os.listdir(proc):
        if not pid.isdigit() or pid in done:
            continue
        live.add(pid)
        if pid not in pending:
            found = read_child(proc, pid, expect)
            if found is None:
                continue
            pending[pid] = found
        name, argc = pending[pid]
        state = observe(proc, pid)
        if state is None:
            continue
        euid, netns, root = state
        if euid == 0:
            continue                      # not dropped yet: keep following it
        done.add(pid)
        del pending[pid]
        emit({'t': now(), 'child': name, 'args': argc, 'euid': euid, 'netns_isolated': netns != init_netns,
              'chrooted': root != '/'})
    for pid in list(pending):
        if pid not in live:
            name, argc = pending.pop(pid)
            done.add(pid)
            emit({'t': now(), 'child': name, 'args': argc, 'ended_before_drop': True})


def main(argv):
    seconds = float(argv[1])
    expect = dict(item.split('=', 1) for item in argv[2:])
    proc = '/proc'
    init_netns = os.readlink(os.path.join(proc, '1', 'ns', 'net'))

    def emit(doc):
        print(json.dumps(doc, sort_keys=True), flush=True)

    emit({'start': True, 'children': sorted(expect), 'euid': os.geteuid()})
    pending, done = {}, {str(os.getpid())}
    scans = 0
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        scan(proc, expect, init_netns, pending, done, emit)
        scans += 1
        time.sleep(0.01)
    emit({'end': True, 'scans': scans, 'still_pending': len(pending)})
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
