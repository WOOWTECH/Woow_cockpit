"""Bounded, read-only observations of this run's synthetic clients. No login/reset."""
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import time

spec = importlib.util.spec_from_file_location('auto_check', Path(__file__).with_name('headscale-auto-reconnect-check.py'))
auto_check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auto_check)


def require(ok, code):
    if not ok:
        raise RuntimeError(code)


def network_address(info, name, address):
    address = ipaddress.IPv4Address(address)
    require(info['name'] == name and info['internal'] is True and
            info.get('labels', {}).get('io.woowtech.test') == 'headscale-derp',
            'continuity_network_not_isolated')
    require(any(address in (net := ipaddress.ip_network(s['subnet'])) and
                address not in (net.network_address, net.broadcast_address)
                for s in info['subnets'] if ':' not in s['subnet']), 'continuity_ip_outside_network')
    return str(address)


def process_identity(data, network):
    require(data['State']['Running'] is True and not data['HostConfig'].get('PortBindings') and
            set(data['NetworkSettings']['Networks']) == {network}, 'continuity_client_runtime_changed')
    identity = (data['Id'], data['State']['StartedAt'], data['State']['Pid'])
    require(all(identity), 'continuity_process_identity_missing')
    return identity


class Continuity:
    def __init__(self, runner, root, address, *, clock=time.monotonic, sleep=time.sleep):
        self.runner, self.clock, self.sleep = runner, clock, sleep
        suffix = Path(root).name.rsplit('.', 1)[1]
        require(re.fullmatch(r'[A-Za-z0-9]{8}', suffix), 'continuity_invalid_suffix')
        self.network = 'hs-test-' + suffix
        self.clients = ['hs-a-' + suffix, 'hs-b-' + suffix]
        self.deadline = clock() + 30
        info = self.json('network', 'inspect', self.network)[0]
        self.address = network_address(info, self.network, address)
        self.before, self.processes = [], []
        for client in self.clients:
            path = Path(root) / (client + '.before.json')
            require(not path.is_symlink() and path.is_file() and path.stat().st_size <= 65536,
                    'continuity_invalid_baseline')
            with path.open('rb') as stream:
                data = stream.read(65537)
            require(len(data) <= 65536, 'continuity_baseline_limit')
            self.before.append(json.loads(data))
            self.processes.append(process_identity(self.json('container', 'inspect', client)[0], self.network))
        self.targets = [str(next(ipaddress.IPv4Address(ip) for ip in b['Self']['TailscaleIPs'] if ':' not in ip))
                        for b in self.before]
        require(len(set(self.targets)) == 2, 'continuity_duplicate_clients')

    def command(self, *args):
        remaining = self.deadline - self.clock()
        require(remaining > 0, 'continuity_deadline')
        return self.runner.podman(*args, timeout=min(5, remaining), max_output=65536, check=False)

    def json(self, *args):
        result = self.command(*args)
        require(result.returncode == 0, 'continuity_observation_failed')
        return json.loads(result.stdout)

    def verify(self, server, phase):
        require(phase in ('installed', 'rolled_back', 'restarted'), 'continuity_invalid_phase')
        start = self.clock()
        self.deadline = start + 60
        network_address(self.json('network', 'inspect', self.network)[0], self.network, self.address)
        attempts = 0
        while self.clock() < self.deadline:
            attempts += 1
            # A replaced/restarted client is a hard failure, never a retryable reconnect.
            for client, before in zip(self.clients, self.processes):
                now = process_identity(self.json('container', 'inspect', client)[0], self.network)
                require(now == before, 'continuity_client_process_replaced')
            statuses = [self.json('exec', client, 'tailscale', '--socket=/tmp/tailscaled.sock',
                                  'status', '--json') for client in self.clients]
            nodes = self.json('exec', server, 'headscale', 'nodes', 'list', '-o', 'json')
            connected = auto_check.check(nodes, list(zip(self.before, statuses)))
            if connected:
                for client, target in zip(self.clients, reversed(self.targets)):
                    ping = self.command('exec', client, 'tailscale', '--socket=/tmp/tailscaled.sock',
                                        'ping', '--c=1', '--timeout=3s', '--until-direct=false', target)
                    connected = connected and ping.returncode == 0 and re.fullmatch(
                        rb'pong from [^\r\n]+ via DERP\(lab\) in [0-9.]+(?:ms|s)\n?', ping.stdout) is not None
                if connected:
                    for client, before in zip(self.clients, self.processes):
                        now = process_identity(self.json('container', 'inspect', client)[0], self.network)
                        require(now == before, 'continuity_client_process_replaced')
                    require(self.clock() <= self.deadline, 'continuity_deadline')
                    print(f'HEADSCALE_CLIENT_CONTINUITY={phase}:PASS attempts={attempts} '
                          f'elapsed={self.clock()-start:.1f}s', flush=True)
                    return
            self.sleep(min(1, max(0, self.deadline - self.clock())))
        raise RuntimeError('continuity_deadline')
