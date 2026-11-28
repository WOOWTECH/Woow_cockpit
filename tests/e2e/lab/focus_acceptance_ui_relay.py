"""Single-case private transport to a lab device's real Cockpit (dev-d unless told); no listener on import.

TLS/WebSocket bytes are opaque. Only host127.0.0.1 binds; the device child is an
unprivileged TCP client to127.0.0.1:9090. No shell, port publish or device config.
Relay() and command() without a device are exactly the dev-d transport of R8, R1 and page-emqx.
"""
import asyncio
from pathlib import Path
import re
import threading

DEVICE = 'woowbk-dev-d'
DEVICE_RE = re.compile(r'woowbk-dev-[a-z]\Z')   # lib.sh device_vars: NAME=woowbk-dev-$DEV
LP = Path.home() / '.woowbk-lab/bin/labpodman'
REMOTE = r'''
import os, socket, threading
s = socket.create_connection(("127.0.0.1", 9090), timeout=15)
s.settimeout(None)
def inbound():
    try:
        while True:
            b = os.read(0, 65536)
            if not b: break
            s.sendall(b)
    except OSError: pass
    finally:
        try: s.shutdown(socket.SHUT_WR)
        except OSError: pass
t = threading.Thread(target=inbound, daemon=True)
t.start()
try:
    while True:
        b = s.recv(65536)
        if not b: break
        while b:
            n = os.write(1, b)
            b = b[n:]
finally: s.close()
'''


def device_name(device):
    """The lab device name itself (woowbk-dev-<letter>); anything else is refused before a process starts."""
    if not isinstance(device, str) or not DEVICE_RE.fullmatch(device):
        raise ValueError('lab device name woowbk-dev-<letter> required')
    return device


def command(device=DEVICE):
    return [str(LP), 'exec', '-i', '--user', 'devadmin', device_name(device),
            'python3', '-I', '-c', REMOTE]


class Relay:
    def __init__(self, device=DEVICE):
        self.device = device_name(device)
        self.ready = threading.Event()
        self.error = None
        self.thread = None
        self.children = set()
        self.tasks = set()
        self.connections = 0
        self.refused = 0

    async def connection(self, reader, writer):
        if len(self.tasks) >= 32:
            self.refused += 1
            writer.close()
            await writer.wait_closed()
            return
        task = asyncio.current_task()
        self.tasks.add(task)
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *command(self.device), stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            self.children.add(proc)
            self.connections += 1

            async def up():
                try:
                    while data := await reader.read(65536):
                        proc.stdin.write(data)
                        await proc.stdin.drain()
                finally:
                    proc.stdin.close()

            async def down():
                while data := await proc.stdout.read(65536):
                    writer.write(data)
                    await writer.drain()
                if writer.can_write_eof():
                    writer.write_eof()

            # Either a closed browser or a completed Cockpit response releases
            # its exec child. Concurrent pumps preserve WebSocket full duplex.
            pumps = [asyncio.create_task(up()), asyncio.create_task(down())]
            try:
                await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
                # stdin EOF is a half-close: allow the last response to drain.
                if pumps[0].done() and not pumps[1].done():
                    await asyncio.wait_for(pumps[1], 30)
            finally:
                for pump in pumps:
                    if not pump.done():
                        pump.cancel()
                await asyncio.gather(*pumps, return_exceptions=True)
        except (OSError, ConnectionError, asyncio.TimeoutError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass
            if proc is not None:
                if proc.returncode is None:
                    proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), 5)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                self.children.discard(proc)
            self.tasks.discard(task)

    async def serve(self):
        self.loop = asyncio.get_running_loop()
        self.stop = asyncio.Event()
        server = await asyncio.start_server(self.connection, host='127.0.0.1', port=0,
                                            family=__import__('socket').AF_INET)
        with server.sockets[0].dup() as bound:
            assert bound.getsockname()[0] == '127.0.0.1'
            self.port = bound.getsockname()[1]
        self.ready.set()
        async with server:
            await self.stop.wait()
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    def worker(self):
        try:
            asyncio.run(self.serve())
        except Exception as error:
            self.error = type(error).__name__
            self.ready.set()

    def __enter__(self):
        self.thread = threading.Thread(target=self.worker, daemon=True)
        self.thread.start()
        if not self.ready.wait(15) or self.error:
            raise RuntimeError('private relay startup failed')
        self.base = f'https://127.0.0.1:{self.port}'
        return self

    def __exit__(self, *_):
        self.loop.call_soon_threadsafe(self.stop.set)
        self.thread.join(15)
        if self.thread.is_alive() or self.children:
            raise RuntimeError('private relay cleanup incomplete')
