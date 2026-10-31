from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sys
import time

from ..adapters.linux import interface_name
from ..adapters.parsers import parse_iw_devices, parse_wiphy, parse_wifi_scan
from ..core.models import CommandResult, Manifest


def decoded(result, default=None):
    if result.status != 'OK': return default
    try: return json.loads(result.stdout)
    except ValueError: return default


def read_file(path):
    try: return Path(path).read_text().strip()
    except (OSError, UnicodeError): return None


class DiscoveryPlugin:
    def prepare(self, params, config): return params


class HostDiscovery(DiscoveryPlugin):
    manifest = Manifest('recon.host', 'Host inventory', 'host',
        'Local compute, OS, memory, storage, virtualization and tool availability.',
        capabilities=('local_inventory',), tools=('lscpu', 'lsblk', 'nvidia-smi'))

    async def run(self, ctx, params):
        ctx.progress('Collecting host inventory')
        specs = {'cpu': ['lscpu', '-J'], 'storage': ['lsblk', '-J', '-o', 'NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,MODEL'],
                 'virtualization_environment': ['systemd-detect-virt'],
                 'gpu': ['nvidia-smi', '--query-gpu=name,memory.total,driver_version', '--format=csv,noheader']}
        async def collect(name, cmd):
            accepted = (0, 1) if name == 'virtualization_environment' else (0,)
            return name, await ctx.runner.command(cmd, accepted=accepted)
        results = dict(await asyncio.gather(*(collect(k, v) for k, v in specs.items())))
        virtual = results['virtualization_environment']
        if virtual.returncode == 1 and virtual.stdout.strip() != 'none':
            virtual.status = 'ERROR'
        meminfo = {}
        for line in (read_file('/proc/meminfo') or '').splitlines():
            key, _, value = line.partition(':'); meminfo[key] = value.strip()
        tools = ('iw', 'ip', 'ethtool', 'rfkill', 'lsusb', 'lspci', 'udevadm', 'bluetoothctl',
                 'btmgmt', 'tcpdump', 'dumpcap', 'tshark', 'hostapd', 'esptool', 'arduino-cli')
        data = {'platform': {'system': platform.system(), 'release': platform.release(),
                'architecture': platform.machine(), 'hostname': platform.node(), 'python': sys.version.split()[0]},
                'cpu': decoded(results['cpu']), 'memory_proc': meminfo,
                'uptime_seconds': (read_file('/proc/uptime') or '').split(' ')[0],
                'storage': decoded(results['storage']),
                'virtualization_environment': virtual.stdout.strip() if virtual.status == 'OK' else None,
                'kvm_device_exists': Path('/dev/kvm').exists(),
                'kvm_current_user_access': os.access('/dev/kvm', os.R_OK | os.W_OK),
                'gpu_csv': results['gpu'].stdout.strip() if results['gpu'].status == 'OK' else None,
                'tools': {t: shutil.which(t) for t in tools}}
        return ctx.observation(self.manifest.id, data,
            warnings=['Tool presence and device enumeration do not establish functional attack or capture support.'])


class HardwareDiscovery(DiscoveryPlugin):
    manifest = Manifest('recon.hardware', 'Hardware and radio inventory', 'hardware',
        'PCI/USB, network drivers, wiphy modes, regulatory flags, Bluetooth and serial bridges.',
        capabilities=('local_inventory', 'advertised_radio_capabilities'),
        tools=('iw', 'ip', 'lsusb', 'lspci', 'ethtool', 'rfkill', 'bluetoothctl'))

    async def run(self, ctx, params):
        ctx.progress('Reading device and driver capabilities')
        specs = {'usb': ['lsusb'], 'usb_topology': ['lsusb', '-t'], 'pci': ['lspci', '-nnk'],
                 'iw_devices': ['iw', 'dev'], 'iw_phys': ['iw', 'list'],
                 'regulatory': ['iw', 'reg', 'get'], 'rfkill': ['rfkill', '--json'],
                 'bluetooth': ['bluetoothctl', 'show'], 'bluetooth_settings': ['btmgmt', 'info']}
        async def collect(k, cmd): return k, await ctx.runner.command(cmd)
        results = dict(await asyncio.gather(*(collect(k, v) for k, v in specs.items())))
        interfaces = []
        for path in sorted(Path('/sys/class/net').glob('*')):
            entry = {'interface': path.name, 'wireless': (path / 'wireless').exists(),
                     'address': read_file(path / 'address'), 'operstate': read_file(path / 'operstate'),
                     'mtu': read_file(path / 'mtu')}
            entry['driver_raw'] = None
            if (path / 'device').exists():
                driver = await ctx.runner.command(['ethtool', '-i', path.name])
                entry['driver_raw'] = driver.stdout if driver.status == 'OK' else None
            interfaces.append(entry)
        serial = []
        paths = sorted([*Path('/dev').glob('ttyACM*'), *Path('/dev').glob('ttyUSB*')])
        for path in paths:
            properties = await ctx.runner.command(['udevadm', 'info', '--query=property', '--name', str(path)])
            props = dict(line.split('=', 1) for line in properties.stdout.splitlines() if '=' in line)
            serial.append({'port': str(path), 'properties': props,
                'readable': os.access(path, os.R_OK), 'writable': os.access(path, os.W_OK),
                'device_identity_verified': False})
        data = {'interfaces': interfaces,
                'wifi_devices': parse_iw_devices(results['iw_devices'].stdout),
                'wifi_phys': parse_wiphy(results['iw_phys'].stdout),
                'regulatory_raw': results['regulatory'].stdout,
                'usb_raw': results['usb'].stdout, 'usb_topology_raw': results['usb_topology'].stdout,
                'pci_raw': results['pci'].stdout, 'rfkill': decoded(results['rfkill']),
                'bluetooth_raw': results['bluetooth'].stdout,
                'bluetooth_controller_settings_raw': results['bluetooth_settings'].stdout,
                'serial_ports': serial,
                'scope': 'Host-visible devices; firmware identity has not been checked.'}
        return ctx.observation(self.manifest.id, data,
            warnings=['Listed radio modes are driver advertisements, not successful functional tests.',
                      'A USB serial bridge is not proof that the attached MCU is an ESP32-S3.'])


class NetworkDiscovery(DiscoveryPlugin):
    manifest = Manifest('recon.network', 'Local network context', 'network',
        'Interface addresses, routes, local neighbour cache and current Wi-Fi association.',
        capabilities=('local_network_state', 'cached_neighbour_observations'), tools=('ip', 'iw'))

    async def run(self, ctx, params):
        ctx.progress('Reading local addresses, routes and neighbour cache')
        specs = {'links': ['ip', '-j', '-details', 'link', 'show'],
                 'addresses': ['ip', '-j', 'address', 'show'],
                 'routes_v4': ['ip', '-j', '-4', 'route', 'show', 'table', 'all'],
                 'routes_v6': ['ip', '-j', '-6', 'route', 'show', 'table', 'all'],
                 'neighbours': ['ip', '-j', 'neigh', 'show'], 'wireless': ['iw', 'dev']}
        async def collect(k, cmd): return k, await ctx.runner.command(cmd)
        results = dict(await asyncio.gather(*(collect(k, v) for k, v in specs.items())))
        data = {k: decoded(v) for k, v in results.items() if k != 'wireless'}
        data['wireless'] = parse_iw_devices(results['wireless'].stdout)
        data['associated_links'] = {}
        for phy in data['wireless']:
            for interface in phy['interfaces']:
                name = interface_name(interface['name'])
                link = await ctx.runner.command(['iw', 'dev', name, 'link'])
                data['associated_links'][name] = link.stdout if link.status == 'OK' else None
        targets = []
        for neighbour in data.get('neighbours') or []:
            ip = neighbour.get('dst')
            if not ip: continue
            identity = f'{neighbour.get("dev", "?")}:{ip}'
            targets.append({'protocol': 'network', 'identity': identity, 'label': ip,
                'data': {**neighbour, 'source': 'local_neighbour_cache',
                         'service_discovery_performed': False,
                         'note': 'Cache state is not proof of current reachability or camera identity.'}})
        return ctx.observation(self.manifest.id, data, targets=targets,
            warnings=['No subnet probing or service identification was performed; neighbour entries may be stale.'])


class WifiDiscovery(DiscoveryPlugin):
    manifest = Manifest('recon.wifi', 'Detailed Wi-Fi discovery', 'wifi',
        'Active or passive Wi-Fi discovery and advertised security settings.',
        hardware=('linux_wifi_interface',), parameters=('interface', 'cached', 'active', 'passive', 'timeout'),
        capabilities=('bss_discovery', 'rsn_wpa_advertisement_parsing'),
        target_types=('wifi_bss',), tools=('iw', 'ip'))

    def prepare(self, params, config):
        params['interface'] = interface_name(params.get('interface') or config['wifi']['interface'])
        if sum(bool(params.get(key)) for key in ('cached', 'active', 'passive')) > 1:
            raise ValueError('Choose one scan mode: -c, -A or -P')
        if params['interface'] == config['wifi']['protected_interface'] and not params.get('cached'):
            raise ValueError('Fresh scans on the protected internet interface are blocked; use --cached or select the USB adapter.')
        params['timeout'] = int(params.get('timeout', 45))
        if not 5 <= params['timeout'] <= 120:
            raise ValueError('Scan timeout must be 5–120 seconds')
        return params


    @staticmethod
    def busy(result):
        text = result.stderr.lower()
        return 'busy' in text or 'operation already in progress' in text

    async def scan(self, ctx, iface, method, timeout):
        command = ['iw', 'dev', iface, 'scan']
        if method == 'cached':
            return await ctx.runner.command(command + ['dump'], timeout=timeout)
        command += ['flush']
        if method == 'passive':
            command += ['passive']
        deadline = time.monotonic() + timeout
        retries = []
        result = None
        for attempt in range(3):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            result = await ctx.runner.command(command, timeout=remaining, privileged=True)
            if result.status == 'OK' and 'scan aborted' in result.stdout.lower():
                result.status = 'ABORTED'
                result.stderr = 'Scan aborted by the driver'
            if result.status == 'OK':
                if result.stdout.strip() and not re.search(r'^BSS\s+', result.stdout, re.M):
                    result.status = 'ERROR'
                    result.stderr = 'Unrecognized scan output'
                    return result
                for previous in retries:
                    previous.recovered = True
                return result
            retry = result.status == 'ABORTED' or self.busy(result)
            if not retry or attempt == 2 or deadline - time.monotonic() <= 0.5:
                return result
            retries.append(result)
            ctx.progress('Scan interrupted; retrying.' if result.status == 'ABORTED' else 'Interface busy; retrying.')
            await asyncio.sleep(0.5)
        if result is None:
            result = CommandResult(command, 'TIMEOUT', stderr='Scan timeout reached')
            ctx.runner.results.append(result)
        return result

    async def run(self, ctx, params):
        iface = params['interface']
        method = 'cached' if params.get('cached') else 'passive' if params.get('passive') else 'active'
        info = await ctx.runner.command(['iw', 'dev', iface, 'info'])
        if info.status != 'OK':
            return ctx.observation(self.manifest.id, {'interface': iface}, status='ERROR')
        if not params.get('cached') and 'type managed' not in info.stdout:
            raise ValueError('Fresh BSS scan requires managed mode. Restore the dedicated interface to managed mode first.')
        phy = await ctx.runner.command(['iw', 'list'])
        reg = await ctx.runner.command(['iw', 'reg', 'get'])
        flags_path = Path('/sys/class/net') / iface / 'flags'
        flags = read_file(flags_path)
        original_up = bool(int(flags, 16) & 1) if flags else True
        changed = False
        try:
            if not original_up and not params.get('cached'):
                up = await ctx.runner.command(['ip', 'link', 'set', iface, 'up'], privileged=True)
                if up.status != 'OK':
                    return ctx.observation(self.manifest.id, {'interface': iface},
                        warnings=['Run sudo -v, then retry.'], status='ERROR')
                changed = True
            ctx.progress(f'{method.capitalize()} BSS discovery on {iface}')
            result = await self.scan(ctx, iface, method, params['timeout'])
        finally:
            if changed:
                restored = await asyncio.shield(ctx.runner.command(['ip', 'link', 'set', iface, 'down'], privileged=True))
                ctx.progress('Original interface down-state restored' if restored.status == 'OK' else 'Could not restore the interface; use -j for the command error')
        if result.status != 'OK':
            return ctx.observation(self.manifest.id, {'interface': iface, 'method': method}, status='ERROR',
                warnings=['Interface busy. Close other scans or use -c.'] if self.busy(result) else [])
        aps = parse_wifi_scan(result.stdout, iface, method)
        targets = [{'protocol': 'wifi', 'identity': ap['bssid'],
                    'label': ap['ssid'] or '<hidden/empty>', 'data': ap} for ap in aps]
        data = {'interface': iface, 'method': method, 'access_points': aps, 'count': len(aps),
                'source_interface_info_raw': info.stdout, 'advertised_phys': parse_wiphy(phy.stdout),
                'regulatory_raw': reg.stdout,
                'interpretation': 'Received/cached advertisements only; no password, exploitability or distance inference.'}
        return ctx.observation(self.manifest.id, data, targets=targets,
            status=('PARTIAL' if any((r.status != 'OK' and not getattr(r, 'recovered', False)) or r.truncated for r in ctx.runner.results)
                    else 'OBSERVED' if aps else 'EMPTY'),
            warnings=['Cached results can be stale; last_seen_ms_ago is retained when iw supplies it.'] if method == 'cached' else [])


PLUGINS = (HostDiscovery, HardwareDiscovery, NetworkDiscovery, WifiDiscovery)
