"""Memory of the name table at 4,000,000 entries (IN-34), and of a whole walk over a synthetic tar of N entries."""
import io, json, resource, sys, time
sys.path.insert(0, '/tmp/parity-read-20261125/backup-engine')
from woowbackup import habackup
def rss():
    for line in open('/proc/self/status'):
        if line.startswith('VmRSS'): return int(line.split()[1]) / 1024
class Tar:
    """A plain tar of N empty files, produced while it is read."""
    def __init__(self, n):
        self.n, self.i, self.buf = n, 0, b''
        self.done = False
    def header(self, i):
        name = b'data/filestore/db/%02x/%040x' % (i // 16 % 256, i)
        h = bytearray(512); h[0:len(name)] = name; h[100:108] = b'0000644\0'; h[108:116] = b'0000000\0'; h[116:124] = b'0000000\0'
        h[124:136] = b'00000000000\0'; h[136:148] = b'00000000000\0'; h[148:156] = b' ' * 8; h[156:157] = b'0'; h[257:265] = b'ustar\x0000'
        h[148:156] = b'%06o\0 ' % sum(h)
        return bytes(h)
    def read(self, n=-1):
        while len(self.buf) < n and not self.done:
            part = []
            for _ in range(2048):
                if self.i >= self.n:
                    part.append(bytes(1024)); self.done = True; break
                part.append(self.header(self.i)); self.i += 1
            self.buf += b''.join(part)
        out, self.buf = self.buf[:n], self.buf[n:]
        return out
n = int(sys.argv[1])
base = rss(); t0 = time.process_time(); count = 0
report = habackup.Report()
try:
    for e in habackup.iter_entries(Tar(n), habackup.Select(include=()), report, addon=False):
        count += 1
    result = 'complete'
except habackup.BackupError as error:
    result = error.code + ': ' + error.details['reason']
peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
print(json.dumps({'entries': report.entries, 'result': result, 'base_mib': round(base), 'peak_mib': round(peak), 'per_entry_bytes': round((peak - base) * 1048576 / max(1, report.entries), 1), 'cpu_seconds': round(time.process_time() - t0)}))
