from __future__ import annotations

import asyncio
import json
from pathlib import Path

from ..core.findings import Assessment, advisories, analyse, load_reports, provenance
from ..core.models import utcnow
from ..core.runtime import execute
from ..adapters.probes import PROTOCOLS, assess_endpoint, onvif_probe, request_path, server_name
from ..plugins.services import addresses, port_list
from ..plugins import discover
from .presentation import safe, table, show_assessment as show


def extend_parser(parser):
    from .app import bssid, output_options, scan_options
    root = next(a for a in parser._actions if hasattr(a, 'choices') and isinstance(a.choices, dict))
    assess = root.add_parser('assess', help='Check recon results and service security')
    kinds = assess.add_subparsers(dest='kind', required=True)
    checks = kinds.add_parser('checks', help='List implemented checks and requirements')
    checks.add_argument('-j', '--json', action='store_true', help='Print available checks as JSON')
    p = kinds.add_parser('report', help='Analyse saved reports without sending traffic')
    p.add_argument('files', type=Path, nargs='+', help='1–8 discovery or packet-inspection JSON reports')
    p = kinds.add_parser('wifi', help='Check Wi-Fi security settings')
    p.add_argument('-I', '--input', type=Path, help='Saved Wi-Fi report; no radio traffic')
    scan_options(p)
    p.add_argument('-B', '--bssid', type=bssid, help='Filter by exact BSSID')
    p.add_argument('-S', '--ssid', help='Filter by SSID substring')
    p = kinds.add_parser('services', help='Check services on specified IPs and ports')
    scope = p.add_mutually_exclusive_group(required=True)
    scope.add_argument('target', nargs='?', help='IP address or CIDR, up to 256 addresses')
    scope.add_argument('-I', '--input', type=Path, help='Use the open endpoints in a saved service report')
    p.add_argument('-p', '--ports', help='Ports or ranges; default: 22,80,443,554,8000,8080,8443')
    p.add_argument('--nmap', action='store_true', help='Add Nmap service detection and focused SSH/SMB/RDP/VNC checks')
    p.add_argument('--protocol', choices=PROTOCOLS, default='auto', help='Protocol override for nonstandard ports')
    p.add_argument('--timeout', type=float, default=3, help='Per-operation timeout, 0.2–10 seconds')
    p.add_argument('--concurrency', type=int, default=8, help='Concurrent endpoints, 1–32')
    p.add_argument('--server-name', help='Intended DNS name for TLS validation and HTTP Host')
    p.add_argument('--path', default='/', help='HTTP application base path')
    p = kinds.add_parser('cameras', help='Check one explicit ONVIF device-information endpoint')
    p.add_argument('address', help='Camera IP address, not the local interface address')
    p.add_argument('--port', type=int, default=80, help='Endpoint TCP port')
    p.add_argument('--https', action='store_true', help='Use HTTPS')
    p.add_argument('--server-name', help='Intended DNS name')
    p.add_argument('--path', default='/onvif/device_service', help='Explicit ONVIF device-service path')
    p.add_argument('--timeout', type=float, default=3, help='Per-operation timeout, 0.2–10 seconds')
    p = kinds.add_parser('ble', help='Check BLE advertisements or device access')
    scope = p.add_mutually_exclusive_group(required=True)
    scope.add_argument('-I', '--input', type=Path, help='Saved ESP BLE report; no radio traffic')
    scope.add_argument('--scan', action='store_true', help='Collect fresh advertisements through the ESP32')
    scope.add_argument('--address', type=bssid, help='Connect to this BLE address using Linux Bluetooth')
    p.add_argument('--type', choices=('public', 'random'), help='Required address type for a GATT connection')
    p.add_argument('--adapter', default='hci0', help='Linux Bluetooth adapter for GATT checks')
    p.add_argument('--read', action='append', default=[], metavar='UUID', help='Read this characteristic; repeat up to 16 times; values omitted')
    p.add_argument('--timeout', type=float, default=30, help='Overall GATT timeout, 5–120 seconds')
    p.add_argument('--port', default='auto', help='ESP USB serial port for --scan')
    p.add_argument('--duration', type=int, default=10, help='ESP advertisement scan seconds, 1–300')
    p.add_argument('-A', '--active', action='store_true', help='Use active ESP advertisement scanning')
    p = kinds.add_parser('packets', help='Assess exposed metadata in a saved Wi-Fi capture')
    p.add_argument('file', type=Path, help='PCAP or PCAPNG file')
    p.add_argument('--limit', type=int, help='Explicit input-frame limit; default: full capture')
    p.add_argument('--filter', help='Wireshark display filter')
    for action in kinds.choices.values():
        if action.prog.endswith(' checks'):
            continue
        output_options(action)
        action.add_argument('-o', '--output', type=Path, help='Save findings and check results to a new JSON file')
        action.add_argument('-v', '--verbose', action='store_true', help='Show progress on stderr')
        action.add_argument('--advisories', type=Path, help='Local exact-version advisory JSON; no online lookup')



async def dispatch(args):
    from .app import errors, output_path, scan_params, write_new
    if args.kind == 'checks':
        from ..core.findings import catalogue
        rows = catalogue()
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            table('Available checks', ('Surface', 'Checks', 'Method', 'Needs'),
                  ((r['surface'], r['description'], 'Offline' if r['traffic'] == 'evidence only' else 'Connects', r['requirements']) for r in rows))
        return 0
    path = output_path(args.output) if args.output else None
    report = Assessment()
    advisory_rows = advisories(args.advisories, report)
    progress = lambda message: errors.print(safe(message), markup=False) if args.verbose else None
    if args.kind == 'report':
        sources = load_reports(args.files)
        for source, payload, digest in sources:
            analyse(report, payload, source, advisory_rows, digest)
    elif args.kind == 'wifi':
        if args.input:
            if args.interface or args.cached or args.active or args.passive or args.timeout != 45:
                raise ValueError('Live scan options cannot be combined with -I')
            source, payload, digest = load_reports([args.input])[0]
            if payload['plugin'] not in ('recon.wifi', 'recon.espwifi'):
                raise ValueError('Use a Wi-Fi recon report')
        else:
            plugin = next(p for p in discover() if p.manifest.id == 'recon.wifi')
            payload = (await execute(plugin, scan_params(args), verbose=args.verbose)).to_dict()
            source, digest = 'live:recon.wifi', None
        key = 'access_points' if payload['plugin'] == 'recon.wifi' else 'records'
        rows = payload['data'].get(key, [])
        if args.bssid:
            rows = [r for r in rows if str(r.get('bssid', r.get('address', ''))).lower() == args.bssid]
        if args.ssid is not None:
            rows = [r for r in rows if args.ssid.casefold() in str(r.get('ssid') or '').casefold()]
        payload = {**payload, 'data': {**payload['data'], key: rows}}
        analyse(report, payload, source, advisory_rows, digest)
    elif args.kind == 'services':
        if not 0.2 <= args.timeout <= 10 or not 1 <= args.concurrency <= 32:
            raise ValueError('Timeout must be 0.2–10 seconds; concurrency must be 1–32')
        name = server_name(args.server_name)
        request_path(args.path)
        if args.nmap:
            import shutil
            if not shutil.which('nmap'):
                raise ValueError('nmap not found. Install nmap with the system package manager')
        observed_protocols = {}
        if args.input:
            if args.ports:
                raise ValueError('-p cannot be combined with a saved endpoint report')
            source, payload, digest = load_reports([args.input])[0]
            if payload['plugin'] != 'recon.services':
                raise ValueError('Use a recon.services report')
            from ..core.findings import endpoint
            targets = sorted({(endpoint(r.get('address'), r.get('port'))['address'], r['port']) for r in payload['data']['services'] if r.get('state') == 'open'})
            observed_protocols = {(r['address'], r['port']): r.get('service') for r in payload['data']['services'] if r.get('state') == 'open'}
            provenance(report, source, payload, digest)
        else:
            hosts = addresses(args.target)
            numbers = port_list(args.ports or '22,80,443,554,8000,8080,8443')
            targets = [(host, port) for host in hosts for port in numbers]
        if len(targets) > 2048:
            raise ValueError('Choose at most 2048 endpoints per assessment')
        if name and len({host for host, _ in targets}) != 1:
            raise ValueError('--server-name requires a single IP address')
        report.sources.append({'source': 'live:services', 'observed_at': utcnow(), 'endpoints': len(targets)})
        queue = asyncio.Queue()
        for target in targets:
            queue.put_nowait(target)
        async def worker():
            while not queue.empty():
                host, port = queue.get_nowait()
                selected = args.protocol
                if selected == 'auto' and observed_protocols.get((host, port)) in PROTOCOLS[1:]:
                    selected = observed_protocols[(host, port)]
                if args.nmap:
                    from ..adapters.service_checks import nmap_probe
                    identified = await nmap_probe(report, host, port, advisory_rows)
                    if selected == 'auto' and identified:
                        selected = identified
                    if port in (445, 3389, 5900) and not identified and selected == 'auto':
                        queue.task_done()
                        continue
                await assess_endpoint(report, host, port, args.timeout, protocol=selected,
                    name=name, path=args.path, advisory_rows=advisory_rows, progress=progress)
                queue.task_done()
        tasks = [asyncio.create_task(worker()) for _ in range(min(args.concurrency, len(targets)))]
        try:
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        if not targets:
            report.check('service.connection', None, 'not_run', 'No open endpoints in the supplied report.')
    elif args.kind == 'cameras':
        from ..core.findings import endpoint
        target = endpoint(args.address, args.port)
        if not 0.2 <= args.timeout <= 10:
            raise ValueError('Timeout must be 0.2–10 seconds')
        name = server_name(args.server_name)
        request_path(args.path)
        report.sources.append({'source': 'live:onvif', 'observed_at': utcnow(), 'target': target})
        await onvif_probe(report, target['address'], target['port'], args.timeout, secure=args.https, name=name, path=args.path)
    elif args.kind == 'ble':
        if args.address:
            if not args.type:
                raise ValueError('--type public or random is required for a GATT connection')
            if args.active or args.port != 'auto' or args.duration != 10:
                raise ValueError('ESP scan options do not apply to Linux GATT connections')
            if not 5 <= args.timeout <= 120:
                raise ValueError('GATT timeout must be 5–120 seconds')
            from ..adapters.gatt import assess_gatt
            report.sources.append({'source': 'live:ble:' + args.adapter, 'observed_at': utcnow()})
            await assess_gatt(report, args.address, args.type, args.adapter, args.timeout, args.read)
        else:
            if args.type or args.read or args.adapter != 'hci0' or args.timeout != 30:
                raise ValueError('GATT options require --address')
            if args.input:
                if args.active or args.port != 'auto' or args.duration != 10:
                    raise ValueError('ESP scan options cannot be combined with -I')
                source, payload, digest = load_reports([args.input])[0]
                if payload['plugin'] != 'recon.ble':
                    raise ValueError('Use a BLE recon report')
            else:
                plugin = next(p for p in discover() if p.manifest.id == 'recon.ble')
                payload = (await execute(plugin, {'port': args.port, 'duration': args.duration, 'active': args.active}, verbose=args.verbose)).to_dict()
                source, digest = 'live:recon.ble', None
            analyse(report, payload, source, advisory_rows, digest)
    elif args.kind == 'packets':
        from ..adapters.packets import inspect_wifi
        payload = await inspect_wifi(args.file, limit=args.limit, expression=args.filter)
        analyse(report, payload, str(args.file), advisory_rows)
    payload = report.result()
    if path:
        write_new(path, payload)
        errors.print('Saved: ' + safe(path), markup=False)
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=True))
    else:
        show(payload, details=args.details)
    outcomes = [c['outcome'] for c in payload['data']['checks']]
    return 1 if not outcomes or any(o in ('failed', 'inconclusive') for o in outcomes) or not any(o in ('completed', 'observed', 'closed', 'empty') for o in outcomes) else 0
