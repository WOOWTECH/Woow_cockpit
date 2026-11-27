"""Device-side owned process group supervisor; no I/O until supervise().

The controller embeds this exact committed module in its fixed device program.
Tests use real Python child processes, never Podman or a device.
"""
import os
from pathlib import Path
import signal
import subprocess
import time


def group_members(pgid):
    result = []
    for path in Path('/proc').iterdir():
        if not path.name.isdigit(): continue
        try:
            fields = (path/'stat').read_text().rpartition(') ')[2].split()
            if int(fields[2]) == pgid and fields[0] != 'Z': result.append(int(path.name))
        except (FileNotFoundError, ProcessLookupError, PermissionError, IndexError, ValueError): pass
    return result


def supervise(argv, log, *, timeout=600, grace=30, checkpoint=lambda _v:None, guard=lambda:True, identity=None):
    """Own a new group, terminate/wait it on timeout, signal, resource loss or early parent exit.

    No arbitrary PID is accepted from a receipt. A recovery with an unproved
    terminal group refuses further cleanup; it never kills a reused PID.
    """
    child = None; timed_out = False; interrupted = False; resource_lost = False; orphaned = False
    started = time.monotonic(); old = {}
    spawn = {}
    if identity is not None:
        if (type(identity.get('uid')) is not int or identity['uid']<=0
                or type(identity.get('gid')) is not int or identity['gid']<0):
            raise ValueError('builder must use an explicit ordinary owner')
        spawn = dict(user=identity['uid'],group=identity['gid'],extra_groups=[],
                     cwd=identity['home'],env=identity['env'])
    def stop(_signum,_frame):
        nonlocal interrupted
        interrupted = True
    try:
        for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):
            old[sig] = signal.signal(sig,stop)
        child = subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True,**spawn)
        if identity is not None:
            owner = Path('/proc',str(child.pid)).stat()
            if owner.st_uid!=identity['uid'] or owner.st_gid!=identity['gid'] or os.getpgid(child.pid)!=child.pid:
                raise RuntimeError('builder process owner/group mismatch')
        checkpoint({'pid':child.pid,'pgid':child.pid,'terminal':False,
                    'uid':identity['uid'] if identity is not None else os.getuid()})
        while child.poll() is None:
            if interrupted: break
            if time.monotonic()-started >= timeout: timed_out = True; break
            if not guard(): resource_lost = True; break
            time.sleep(min(0.1,timeout))
    finally:
        if child is not None:
            # A successful parent may still have live children; those also
            # belong to this exact newly created group and must settle.
            members = group_members(child.pid)
            orphaned = child.poll() is not None and bool(members)
            if child.poll() is None or members:
                try: os.killpg(child.pid,signal.SIGTERM)
                except ProcessLookupError: pass
                deadline = time.monotonic()+grace
                while group_members(child.pid) and time.monotonic()<deadline: time.sleep(0.05)
                if group_members(child.pid):
                    try: os.killpg(child.pid,signal.SIGKILL)
                    except ProcessLookupError: pass
            child.wait(timeout=max(1,grace))
            deadline = time.monotonic()+max(1,grace)
            while group_members(child.pid) and time.monotonic()<deadline: time.sleep(0.05)
            terminal = not group_members(child.pid)
            checkpoint({'pid':child.pid,'pgid':child.pid,'terminal':terminal,'returncode':child.returncode,
                        'timed_out':timed_out,'interrupted':interrupted,'resource_lost':resource_lost,'orphaned':orphaned})
        for sig,handler in old.items(): signal.signal(sig,handler)
    return {'ok':terminal and child.returncode==0 and not (timed_out or interrupted or resource_lost or orphaned),
            'terminal':terminal,'returncode':child.returncode,'timed_out':timed_out,
            'interrupted':interrupted,'resource_lost':resource_lost,'orphaned':orphaned}
