from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import re
import tempfile
import time

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text

from ..adapters.agent import Agent, board_configuration, choose_port, ports
from ..adapters.packets import inspect_wifi
from ..adapters.capture import capture_wifi
from ..adapters.linux import Runner
from ..adapters.resources import Resource
from ..core.assessment import security_label
from ..core.runtime import execute
from ..plugins import discover
from .presentation import safe, table, show_observation

errors = Console(stderr=True, highlight=False)


def subcommands(parser):
    return next(a.choices for a in parser._actions if isinstance(a, argparse._SubParsersAction))


def outputs(parser):
    from .app import output_options
    output_options(parser)
    parser.add_argument('-o', '--output', type=Path, metavar='FILE', help='Save JSON to a new file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show progress on stderr')


def extend_parser(parser):
    from .app import bssid, scan_options
    commands = subcommands(parser)
    recon = next(a for a in commands['recon']._actions if isinstance(a, argparse._SubParsersAction))
    for kind, description in (('espwifi', 'Scan 2.4 GHz Wi-Fi with the ESP32'), ('ble', 'Read BLE advertisements'), ('nrf', 'Measure nRF channel activity')):
        item = recon.add_parser(kind, help=description)
        outputs(item)
        item.add_argument('--port', default='auto', help='USB serial port (default: auto)')
        if kind == 'nrf':
            item.add_argument('--samples', type=int, default=64, help='Samples per channel (1–512)')
        else:
            item.add_argument('-A', '--active', action='store_true', help='Send scan requests; passive by default')
            if kind == 'ble':
                item.add_argument('--duration', type=int, default=10, help='Scan seconds (1–300)')
    item = recon.add_parser('services', help='Check TCP services on explicit IP targets')
    item.add_argument('target', help='IP address or CIDR, up to 256 addresses')
    item.add_argument('-p', '--ports', default='22,80,443,554,8000,8080,8443', help='Comma-separated ports or ranges')
    item.add_argument('--timeout', type=float, default=1, help='Connection timeout in seconds')
    item.add_argument('--concurrency', type=int, default=32, help='Parallel connections (1–128)')
    outputs(item)
    item = recon.add_parser('cameras', help='Query local ONVIF video-transmitter advertisements')
    item.add_argument('--address', required=True, help='Local IPv4 address of the interface to query')
    item.add_argument('--duration', type=float, default=5, help='Discovery seconds (1–30)')
    outputs(item)
    actions = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    device = actions.add_parser('device', help='Inspect or flash the ESP32')
    device_actions = device.add_subparsers(dest='action', required=True)
    p = device_actions.add_parser('ports', help='List USB serial ports')
    p.add_argument('-j', '--json', action='store_true', help='Print JSON')
    for action in ('info', 'flash'):
        p = device_actions.add_parser(action, help='Read firmware capabilities' if action == 'info' else 'Build and upload the agent')
        p.add_argument('--port', default='auto', help='USB serial port')
        if action == 'info':
            p.add_argument('-j', '--json', action='store_true', help='Print JSON')
        else:
            p.add_argument('--fqbn', help='Override board settings; USB connection detected by default')
    inspect = actions.add_parser('inspect', help='Decode saved packets')
    p = inspect.add_subparsers(dest='kind', required=True).add_parser('wifi', help='Decode saved 802.11 packets with TShark')
    p.add_argument('file', type=Path, help='PCAP or PCAPNG file')
    p.add_argument('--limit', type=int, help='Read at most this many input frames; default: entire file')
    p.add_argument('--filter', help='Wireshark display filter')
    p.add_argument('-j', '--json', action='store_true', help='Print decoded fields as JSON')
    p.add_argument('-o', '--output', type=Path, help='Save decoded fields to a new JSON file')
    p = actions.add_parser('correlate', help='Match addresses across saved discovery reports')
    p.add_argument('reports', nargs='+', type=Path, help='JSON discovery reports')
    p.add_argument('-j', '--json', action='store_true', help='Print JSON')
    p.add_argument('-o', '--output', type=Path, help='Save matches as JSON')
    capture = actions.add_parser('capture', help='Capture packets to an explicit file')
    p = capture.add_subparsers(dest='kind', required=True).add_parser('wifi', help='Capture Wi-Fi frames in monitor mode')
    p.add_argument('-i', '--interface', required=True, help='Dedicated Wi-Fi adapter')
    p.add_argument('-o', '--output', type=Path, required=True, help='New PCAP file')
    p.add_argument('--channel', type=int, help='Fixed Wi-Fi channel')
    p.add_argument('--duration', type=float, default=30, help='Capture seconds (1–3600)')
    p.add_argument('--max-mb', type=int, default=64, help='Stop near this file size in MiB')
    p.add_argument('-B', '--bssid', type=bssid, help='Filter frames by BSSID')
    p.add_argument('--filter', help='Additional tcpdump filter')
    p.add_argument('-j', '--json', action='store_true', help='Print capture statistics as JSON')
    monitor = actions.add_parser('monitor', help='Watch periodic discovery results')
    p = monitor.add_subparsers(dest='kind', required=True).add_parser('wifi', help='Repeat managed-mode Wi-Fi scans')
    scan_options(p)
    p.add_argument('--duration', type=float, default=60, help='Watch seconds (5–3600)')
    p.add_argument('--interval', type=float, default=5, help='Delay between scans in seconds')
    p.add_argument('-S', '--ssid', help='Filter by SSID substring')
    p.add_argument('-B', '--bssid', type=bssid, help='Filter by BSSID')
    p.add_argument('-f', '--findings', action='store_true', help='Show networks with findings')
    p.add_argument('-j', '--json', action='store_true', help='Stream JSON records, one per line')
    p.add_argument('-o', '--output', type=Path, help='Save the final Wi-Fi report')
    p.add_argument('-v', '--verbose', action='store_true', help='Show scan progress on stderr')


def extra_command(args):
    return args.command in ('device', 'capture', 'inspect', 'monitor', 'correlate') or args.command == 'recon' and args.kind in ('espwifi', 'ble', 'nrf', 'services', 'cameras')


def show_extra(payload, details=False):
    if details:
        print(json.dumps(payload, indent=2, ensure_ascii=True))
        return
    kind, data = payload['plugin'], payload['data']
    if kind == 'recon.ble':
        records = sorted(data['records'], key=lambda r: (-r['rssi'], r['address']))
        method = data.get('method', 'unknown')
        duration = data.get('duration_seconds', '?')
        if records:
            types = {0: 'Public', 1: 'Random', 2: 'Public identity', 3: 'Random identity'}
            table('BLE', ('Address', 'Type', 'Name', 'Signal', 'Services'),
                  ((r['address'], types.get(r.get('address_type'), 'Unknown'),
                    r['advertisement'].get('name') or '—', str(r['rssi']) + ' dBm',
                    ', '.join(r['advertisement'].get('service_uuids', [])) or '—') for r in records))
            print(f"{len(records)} BLE addresses · {duration}s · {method} · {safe(data['port'])}")
        else:
            print(f"No BLE advertisements received · {duration}s · {method} · {safe(data['port'])}")
    elif kind == 'recon.espwifi':
        if data['records']:
            table('Wi-Fi · ESP32', ('SSID', 'BSSID', 'Ch', 'Signal', 'Security'),
                  ((r.get('ssid') or '<hidden>', r['address'], r['channel'], str(r['rssi']) + ' dBm', r['security'])
                   for r in sorted(data['records'], key=lambda r: (-r['rssi'], r['address']))))
        else:
            print(f"No Wi-Fi networks received · {data['method']} · {safe(data['port'])}")
    elif kind == 'recon.nrf':
        active = sorted((r for r in data['records'] if r['hits']), key=lambda r: (-r['hits'], r['channel']))
        if active:
            table('nRF · received-power activity', ('Ch', 'MHz', 'Hits', 'Samples', 'Hit rate'),
                  ((r['channel'], r['frequency_mhz'], r['hits'], r['samples'], f"{100*r['hits']/r['samples']:.1f}%") for r in active))
            print(f"{len(active)} channels with hits · {data.get('samples', '?')} samples/channel · {safe(data['port'])}")
        else:
            print('No detector hits during this survey.')
    elif kind == 'recon.services':
        if data['services']:
            table('TCP services', ('Address', 'Port', 'Observed', 'Port hint'),
                  ((r['address'], r['port'], r['service'], r['port_hint'] or '—') for r in data['services']))
        else:
            print('No open TCP ports observed.')
        print(f"{data['checked']} checked · {data['refused']} refused · {data['unanswered']} unanswered")
    elif kind == 'recon.cameras':
        if data['devices']:
            table('ONVIF responders', ('Address', 'Advertised endpoint'),
                  ((r['address'], ', '.join(r['urls']) or '—') for r in data['devices']))
        else:
            print('No ONVIF discovery responses received · ' + safe(data['local_address']))
    for warning in payload.get('warnings', []):
        errors.print(safe(warning), markup=False)


async def flash(port, fqbn):
    port = choose_port(port)
    connection = 'custom board settings'
    if not fqbn:
        fqbn, connection = board_configuration(port)
    runner = Runner(limit=8*1024*1024)
    cores = await runner.command(['arduino-cli', 'core', 'list'])
    if cores.status != 'OK':
        raise ValueError(cores.stderr.strip() or 'arduino-cli not found')
    if not re.search(r'^esp32:esp32\s+3\.3\.12\b', cores.stdout, re.M):
        raise ValueError('Install Arduino ESP32 core 3.3.12 before flashing')
    sketch = Path(__file__).resolve().parents[1] / 'firmware' / 'agent'
    with Resource('serial:' + str(Path(port).resolve())), tempfile.TemporaryDirectory(prefix='vulnfin-build-') as build:
        print('Building firmware · ' + connection + '.')
        result = await runner.command(['arduino-cli', 'compile', '--fqbn', fqbn, '--build-path', build, str(sketch)], timeout=600)
        if result.status != 'OK':
            raise ValueError(result.stderr.strip() or result.stdout.strip() or 'Firmware build failed')
        print('Uploading to ' + safe(port) + '.')
        result = await runner.command(['arduino-cli', 'upload', '--port', port, '--fqbn', fqbn, '--input-dir', build, str(sketch)], timeout=120)
        if result.status != 'OK':
            raise ValueError(result.stderr.strip() or result.stdout.strip() or 'Firmware upload failed')
    print('Firmware uploaded. Run vulnfin device info --port ' + safe(port))
    return 0


async def watch_wifi(args):
    from .app import output_path, write_new, filtered_wifi, scan_params
    if not 5 <= args.duration <= 3600 or not 0.5 <= args.interval <= 300:
        raise ValueError('Duration must be 5–3600 seconds; interval must be 0.5–300 seconds')
    path = output_path(args.output) if args.output else None
    plugin = next(p for p in discover() if p.manifest.id == 'recon.wifi')
    records, last = {}, None
    seen = {}
    interrupted = False
    failed = False
    completed = 0
    deadline = time.monotonic() + args.duration
    output = Console(highlight=False)
    live = Live(console=output, auto_refresh=False) if output.is_terminal and not args.json else None
    def display():
        view = Table('SSID', 'BSSID', 'Ch', 'Signal', 'Age', 'Security', title='Wi-Fi')
        for ap in sorted(records.values(), key=lambda a: -(a.get('signal_dbm') if a.get('signal_dbm') is not None else -999)):
            view.add_row(*(Text(safe(v)) for v in (ap.get('ssid') or '<hidden>', ap['bssid'], ap.get('channel'), ap.get('signal_dbm'), f"{ap['last_seen_ms_ago']/1000 + time.monotonic()-seen[ap['bssid']]:.1f}s" if ap.get('last_seen_ms_ago') is not None else 'unknown', security_label(ap))))
        return view
    if live:
        live.start()
    try:
        while deadline - time.monotonic() >= 1:
            remaining = deadline - time.monotonic()
            params = scan_params(args)
            params['timeout'] = max(5, min(args.timeout, int(remaining)))
            try:
                observation = await asyncio.wait_for(execute(plugin, params, verbose=args.verbose), remaining)
            except asyncio.TimeoutError:
                failed = last is None
                if failed and not args.json:
                    errors.print('No scan completed within the requested duration.', markup=False)
                break
            payload = observation.to_dict()
            if observation.status == 'ERROR':
                failed = True
                if args.json:
                    print(json.dumps({'event': 'error', 'observation': payload}), flush=True)
                else:
                    show_observation(payload)
                break
            filters = argparse.Namespace(ssid=args.ssid, bssid=None, findings=args.findings)
            last = filtered_wifi(payload, filters)
            if args.bssid:
                last['data']['access_points'] = [a for a in last['data']['access_points'] if a['bssid'].lower() == args.bssid]
                last['data']['count'] = len(last['data']['access_points'])
            completed += 1
            for ap in last['data'].get('access_points', []):
                old = records.get(ap['bssid'])
                if len(records) >= 2048 and old is None:
                    raise ValueError('Too many BSSIDs; shorten the watch or filter by SSID')
                ap['first_observed_at'] = old.get('first_observed_at', payload['observed_at']) if old else payload['observed_at']
                ap['observed_at'] = payload['observed_at']
                records[ap['bssid']] = ap
                seen[ap['bssid']] = time.monotonic()
                if args.json and (old is None or any(old.get(k) != ap.get(k) for k in ('ssid', 'channel', 'signal_dbm', 'security'))):
                    print(json.dumps({'event': 'new' if old is None else 'update', 'observed_at': payload['observed_at'], 'target': ap}, ensure_ascii=True), flush=True)
            if live:
                live.update(display(), refresh=True)
            await asyncio.sleep(min(args.interval, max(0, deadline-time.monotonic())))
    except asyncio.CancelledError:
        interrupted = True
    finally:
        if live:
            live.stop()
    if last is not None:
        last['data']['access_points'] = list(records.values())
        last['data']['count'] = len(records)
        last['data']['monitor'] = {'scans': completed, 'interrupted': interrupted, 'historical_union': True, 'failed': failed}
        last['targets'] = []
        if path:
            write_new(path, last)
            errors.print('Saved: ' + safe(path), markup=False)
    if args.json:
        print(json.dumps({'event': 'finished', 'scans': completed, 'bssids': len(records), 'interrupted': interrupted, 'failed': failed}), flush=True)
    elif not live:
        output.print(display())
        print(f'{completed} scans · {len(records)} BSSIDs observed')
    return 130 if interrupted else 1 if failed else 0


async def dispatch_extra(args):
    from .app import output_path, write_new
    if args.command == 'correlate':
        from ..adapters.correlation import correlate
        path = output_path(args.output) if args.output else None
        result = correlate(args.reports)
        if path:
            write_new(path, result)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            table('Address matches', ('Protocol', 'Identity', 'Sources', 'Observations'),
                  ((r['protocol'], r['identity'], ', '.join(r['sources']), len(r['observations'])) for r in result['records']))
        return 0
    if args.command == 'device':
        if args.action == 'ports':
            found = ports()
            if args.json:
                print(json.dumps(found, indent=2))
            else:
                table('USB serial', ('Port', 'Description'), ((p['port'], p['description']) for p in found))
            return 0
        if args.action == 'flash':
            return await flash(args.port, args.fqbn)
        async with Agent(args.port) as agent:
            if args.json:
                print(json.dumps(agent.hello, indent=2))
            else:
                data = agent.hello
                table('Device', ('Field', 'Value'), [('Port', agent.port), ('Chip', data.get('chip')),
                      ('Flash', f"{data.get('flash_bytes', 0)/1048576:g} MiB"), ('PSRAM', f"{data.get('psram_bytes', 0)/1048576:g} MiB"),
                      *[(('NRF SPI' if name == 'nrf' else name.upper()),
                         ('Responding' if name == 'nrf' else 'Supported') if supported else 'Unavailable')
                        for name, supported in data['capabilities'].items()]])
        return 0
    if args.command == 'inspect':
        path = output_path(args.output) if args.output else None
        payload = await inspect_wifi(args.file, limit=args.limit, expression=args.filter)
        if path:
            write_new(path, payload)
            errors.print('Saved: ' + safe(path), markup=False)
        if args.json:
            print(json.dumps(payload, indent=2, ensure_ascii=True))
        else:
            rows = payload['data']['packets']
            if rows:
                table('Wi-Fi packets', ('#', 'Type', 'Transmitter', 'Receiver', 'BSSID', 'SSID'),
                      ((r['number'], r['type'], r['transmitter'] or '—', r['receiver'] or '—',
                        r['bssid'] or '—', r['ssid'] if r['ssid'] is not None else '—') for r in rows))
            scope = f" · input limit {args.limit}" if args.limit is not None else ""
            print(f"{len(rows)} Wi-Fi packets{scope} · {safe(args.file)}")
        return 0
    if args.command == 'capture':
        result = await capture_wifi(args.interface, args.output, channel=args.channel, duration=args.duration,
                                    bssid=args.bssid, expression=args.filter, max_mb=args.max_mb)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"{result['packets']} packets · {result['bytes']} bytes · {safe(result['file'])}")
            for message in [result.get('error'), *result['cleanup_errors']]:
                if message:
                    errors.print(safe(message), markup=False)
        return 1 if result['error'] or result['cleanup_errors'] else 130 if result['interrupted'] else 0
    if args.command == 'monitor':
        return await watch_wifi(args)
    path = output_path(args.output) if args.output else None
    plugin = next(p for p in discover() if p.manifest.id == 'recon.' + args.kind)
    names = plugin.manifest.parameters
    params = {name: getattr(args, name) for name in names if hasattr(args, name)}
    observation = await execute(plugin, params, verbose=args.verbose)
    payload = observation.to_dict()
    if path:
        write_new(path, payload)
        errors.print('Saved: ' + safe(path), markup=False)
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=True))
    else:
        show_extra(payload, args.details)
    return 1 if observation.status in ('ERROR', 'CANCELLED') else 0
