"""CPU seconds of the probe behind a plain tar (_Reader.another_header) on crafted fillers, for the engine tree given as argv[1] (backup-engine/ of a
checkout): per GiB, measured on 64 MiB of each filler (BytesIO in memory, so only the probe and its reading are measured). Prints one line per filler.
usage: probe_cost.py ENGINE_DIR LABEL"""
import io, os, sys, time
sys.path.insert(0, sys.argv[1])
from woowbackup import habackup
label, size, block = sys.argv[2], 64 << 20, 512
in_step = bytes(257) + b'ustar' + bytes(block - 257 - 5)
fillers = (('ustar words', lambda: b'ustar' * (size // 5)), ('a word in every block, bad sum', lambda: in_step * (size // block)),
           ('zeros', lambda: bytes(size)), ('random', lambda: os.urandom(size)))
for name, make in fillers:
    data = make()
    reader = habackup._Reader(io.BytesIO(data))
    start = time.process_time()
    answer = reader.another_header()
    seconds = time.process_time() - start
    print(f'{label:22s} {name:32s} answer={answer} cpu={seconds:6.2f}s for 64 MiB = {seconds * 16:6.1f} s per GiB')
