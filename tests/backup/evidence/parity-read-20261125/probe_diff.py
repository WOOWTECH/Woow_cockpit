"""The probe behind a plain tar (_Reader.another_header) of the engine given as argv[1] against the probe of iteration 2 (every word 'ustar' looked at), on random
data with good and damaged headers, words and zeros at any offset, readers that have read some bytes and buffers of any size. Counts only.
usage: probe_diff.py ENGINE_DIR ROUNDS"""
import io, random, sys
sys.path.insert(0, sys.argv[1]); sys.path.insert(0, '/tmp/parity-read-20261125')
from unittest import mock
from woowbackup import habackup
from tests.backup import hafixtures as hx


def old_probe(reader):
    block, magic_at = habackup.BLOCK, habackup.TAR_MAGIC_AT
    while True:
        reader._fill(block)
        end = reader.off + reader._avail() // block * block
        if end == reader.off:
            return False
        at = reader.buf.find(b'ustar', reader.off, end)
        while at >= 0:
            head = at - magic_at
            if head >= reader.off and (head - reader.off) % block == 0 and habackup._checksum_ok(reader.buf[head:head + block]):
                return True
            at = reader.buf.find(b'ustar', at + 1, end)
        reader.off = end


rounds = int(sys.argv[2])
rng = random.Random(77)
headers = [hx.raw_header('a'), hx.raw_header('b' * 90, magic=hx.GNU), hx.raw_header('c', typeflag=b'5', mode=0o755),
           hx.raw_header('d', size=9999999), hx.raw_header('e', magic=hx.V7), hx.raw_header('é' * 20)]
word_block = bytes(257) + b'ustar' + bytes(250)
answers, different = {True: 0, False: 0}, 0
for round_ in range(rounds):
    skip = rng.randrange(0, 1300)
    data = bytearray(rng.randbytes(skip))
    for _ in range(rng.randrange(1, 14)):
        if rng.random() < 0.55:
            data += bytes(-(len(data) - skip) % 512)
        kind = rng.randrange(9)
        if kind == 0:
            data += bytes(rng.randrange(0, 4000))
        elif kind == 1:
            data += rng.randbytes(rng.randrange(0, 2500))
        elif kind == 2:
            data += b'ustar' * rng.randrange(1, 700)
        elif kind == 3:
            data += rng.choice(headers)
        elif kind == 4:
            block = bytearray(rng.choice(headers)); block[rng.randrange(512)] ^= 1 << rng.randrange(8); data += block
        elif kind == 5:
            data += word_block * rng.randrange(1, 5)
        elif kind == 6:
            data += rng.choice(headers)[:rng.randrange(1, 512)]
        elif kind == 7:
            data += bytes(rng.randrange(0, 900)) + rng.choice(headers)
        else:
            block = bytearray(rng.choice(headers)); block[148:156] = b'%06o\0 ' % rng.randrange(0, 99999); data += block   # a wrong sum
    data = bytes(data)
    chunk = rng.choice((200, 300, 512, 513, 777, 1000, 4096, 65536, 1 << 20))
    with mock.patch.object(habackup, 'CHUNK', chunk):
        new, old = habackup._Reader(io.BytesIO(data)), habackup._Reader(io.BytesIO(data))
        new.read_exact(skip); old.read_exact(skip)
        expected = old_probe(old)
        got = new.another_header()
    answers[expected] += 1
    different += got != expected
print({'rounds': rounds, 'answers': answers, 'different': different})
