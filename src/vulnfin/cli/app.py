from __future__ import annotations

import argparse
import asyncio
from dataclasses import asdict
import json
import math
import os
from pathlib import Path
import re
import shutil
import sys

from rich.console import Console

from ..core.assessment import wifi_observations
from ..core.runtime import configuration, execute
from ..plugins import discover
from .presentation import show_observation, table, safe, show_wifi_target

errors = Console(stderr=True, highlight=False)


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message.split(' (choose from ')[0])


def output_options(parser):
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('-j', '--json', action='store_true', help='Print JSON')
    modes.add_argument('-d', '--details', action='store_true', help='Show detailed evidence')


def bssid(value):
    if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', value):
        raise argparse.ArgumentTypeError('expected a BSSID such as 02:11:22:33:44:55')
    return value.lower()


def timeout(value):
    try:
        seconds = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError('timeout must be 5–120 seconds') from None
    if not 5 <= seconds <= 120:
        raise argparse.ArgumentTypeError('timeout must be 5–120 seconds')
    return seconds


def scan_options(parser):
    parser.add_argument('-i', '--interface', metavar='IFACE', help='Wireless interface')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('-c', '--cached', action='store_true', help='Read cached scan results')
    modes.add_argument('-A', '--active', action='store_true', help='Use active discovery (default)')
    modes.add_argument('-P', '--passive', action='store_true', help='Listen without sending scan probes')
    parser.add_argument('-t', '--timeout', type=timeout, default=45, metavar='SEC', help='Scan timeout (default: 45)')


def parser():
    p = Parser(prog='vulnfin', description='Vulnfin')
    commands = p.add_subparsers(dest='command')
    commands.add_parser('help', help='Show command help').add_argument('path', nargs='*')
    info = commands.add_parser('info', help='Show configured interfaces')
    info.add_argument('-j', '--json', action='store_true', help='Print JSON')
    auth = commands.add_parser('auth', help='Refresh sudo credentials')
    auth.add_argument('action', nargs='?', choices=('refresh', 'status'), default='refresh')
    recon = commands.add_parser('recon', help='Discover networks and hardware')
    categories = recon.add_subparsers(dest='kind', required=True)
    for kind, description in (
        ('wifi', 'Find nearby Wi-Fi networks'),
        ('network', 'Show local addresses, routes and neighbours'),
        ('hardware', 'Show connected devices and radio capabilities'),
        ('host', 'Show system information'),
    ):
        item = categories.add_parser(kind, help=description)
        output_options(item)
        item.add_argument('-o', '--output', type=Path, metavar='FILE', help='Save results as JSON; existing files are kept')
        item.add_argument('-v', '--verbose', action='store_true', help='Show progress on stderr')
        if kind == 'wifi':
            scan_options(item)
            item.add_argument('-S', '--ssid', help='Filter results by SSID substring')
            item.add_argument('-B', '--bssid', type=bssid, help='Inspect one BSSID after the scan')
            item.add_argument('-f', '--findings', action='store_true', help='Show networks with security findings')
    target = commands.add_parser('target', help='Inspect a Wi-Fi target')
    actions = target.add_subparsers(dest='action', required=True)
    show = actions.add_parser('show', help='Inspect a BSSID from a scan or saved results')
    show.add_argument('bssid', type=bssid, help='Exact BSSID')
    scan_options(show)
    show.add_argument('-I', '--input', type=Path, metavar='FILE', help='Read saved results instead of scanning')
    show.add_argument('-v', '--verbose', action='store_true', help='Show progress on stderr')
    output_options(show)
    plugins = commands.add_parser('plugins', help='Browse available modules')
    actions = plugins.add_subparsers(dest='action', required=True)
    actions.add_parser('list', help='List modules')
    actions.add_parser('show', help='Show module details').add_argument('id')
    return p


def output_path(path):
    path = path.expanduser()
    if path.exists() or path.is_symlink():
        raise ValueError('Output file already exists: ' + str(path))
    if not path.parent.is_dir():
        raise ValueError('Output directory not found: ' + str(path.parent))
    return path


def write_new(path, data):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(data, stream, indent=2, ensure_ascii=True)
        stream.write('\n')


def select_wifi_target(payload, identity):
    matches = [ap for ap in payload['data']['access_points'] if ap['bssid'].lower() == identity.lower()]
    if not matches:
        raise ValueError('BSSID not found: ' + identity)
    if len(matches) != 1:
        raise ValueError('Multiple records for BSSID: ' + identity)
    return matches[0]


def read_report(path):
    with path.expanduser().open('r', encoding='utf-8') as stream:
        payload = json.load(stream)
    if not isinstance(payload, dict) or payload.get('plugin') != 'recon.wifi':
        raise ValueError('Not a Vulnfin Wi-Fi report')
    data = payload.get('data')
    if not isinstance(data, dict) or not isinstance(data.get('access_points'), list):
        raise ValueError('Report has no Wi-Fi results')
    for ap in data['access_points']:
        if not isinstance(ap, dict):
            raise ValueError('Invalid access-point record')
        try:
            bssid(ap.get('bssid', ''))
        except (argparse.ArgumentTypeError, TypeError):
            raise ValueError('Invalid BSSID in report') from None
        if ap.get('ssid') is not None and not isinstance(ap['ssid'], str):
            raise ValueError('Invalid SSID in report')
        signal = ap.get('signal_dbm')
        if signal is not None and (not isinstance(signal, (int, float)) or not math.isfinite(signal)):
            raise ValueError('Invalid signal value in report')
        security = ap.get('security', {})
        if not isinstance(security, dict):
            raise ValueError('Invalid security record')
        elements = security.get('elements', [])
        if not isinstance(elements, list) or any(not isinstance(e, dict) for e in elements):
            raise ValueError('Invalid security elements')
    return payload


def filtered_wifi(payload, args):
    data = payload['data']
    if 'access_points' not in data:
        return payload
    aps = data['access_points']
    if args.ssid is not None:
        aps = [ap for ap in aps if args.ssid.casefold() in (ap.get('ssid') or '').casefold()]
    if args.bssid:
        aps = [select_wifi_target({'data': {'access_points': aps}}, args.bssid)]
    if args.findings:
        aps = [ap for ap in aps if wifi_observations(ap)]
    identities = {ap['bssid'] for ap in aps}
    return {**payload, 'data': {**data, 'access_points': aps, 'count': len(aps)},
            'targets': [t for t in payload.get('targets', []) if t.get('identity') in identities]}


async def run(argv):
    p = parser()
    args = p.parse_args(argv)
    if args.command in (None, 'help'):
        current = p
        for part in getattr(args, 'path', ()):
            choices = next((action.choices for action in current._actions
                            if isinstance(action, argparse._SubParsersAction)), None)
            if not choices or part not in choices:
                raise ValueError('Unknown command: ' + part)
            current = choices[part]
        current.print_help()
        return 0
    if args.command == 'info':
        data = configuration()['wifi']
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            table('Interfaces', ('Purpose', 'Interface'),
                  (('Recon', data['interface']), ('Protected', data['protected_interface'])))
        return 0
    if args.command == 'auth':
        if os.geteuid() == 0:
            print('Root access available.')
            return 0
        if not shutil.which('sudo'):
            raise ValueError('sudo not found')
        if args.action == 'refresh' and not sys.stdin.isatty():
            raise ValueError('Run sudo -v in an interactive terminal')
        cmd = ('sudo', '-n', '-v') if args.action == 'status' else ('sudo', '-v')
        process = await asyncio.create_subprocess_exec(*cmd)
        code = await process.wait()
        if code == 0:
            print('Authenticated.')
        return code
    plugins = {plugin.manifest.id: plugin for plugin in discover()}
    if args.command == 'plugins':
        if args.action == 'list':
            table('Modules', ('ID', 'Description'),
                  ((p.manifest.id, p.manifest.name) for p in plugins.values()))
        else:
            plugin = plugins.get(args.id)
            if plugin is None:
                raise ValueError('Unknown module: ' + args.id)
            fields = asdict(plugin.manifest)
            fields.pop('version', None)
            print(json.dumps(fields, indent=2))
        return 0
    if args.command == 'target':
        if args.input and (args.cached or args.active or args.passive or args.interface or args.timeout != 45):
            raise ValueError('Use -I on its own; live scan options do not apply to saved results')
        if args.input:
            payload = read_report(args.input)
        else:
            observation = await execute(plugins['recon.wifi'], scan_params(args), verbose=args.verbose)
            payload = observation.to_dict()
            if observation.status in ('ERROR', 'CANCELLED'):
                if args.json:
                    print(json.dumps(payload, indent=2, ensure_ascii=True))
                else:
                    show_observation(payload)
                return 1
        ap = select_wifi_target(payload, args.bssid)
        if args.json:
            print(json.dumps(ap, indent=2, ensure_ascii=True))
        else:
            show_wifi_target(ap, details=args.details)
        return 0
    path = output_path(args.output) if args.output else None
    params = scan_params(args) if args.kind == 'wifi' else {}
    observation = await execute(plugins['recon.' + args.kind], params, verbose=args.verbose)
    payload = observation.to_dict()
    failed = observation.status in ('ERROR', 'CANCELLED')
    if args.kind == 'wifi' and not failed:
        payload = filtered_wifi(payload, args)
    ap = select_wifi_target(payload, args.bssid) if getattr(args, 'bssid', None) and not failed and payload['data'].get('access_points') else None
    if path:
        write_new(path, payload)
    if args.json:
        print(json.dumps(ap if ap is not None else payload, indent=2, ensure_ascii=True))
    elif ap is not None:
        show_wifi_target(ap, details=args.details)
    else:
        show_observation(payload, mode='details' if args.details else 'summary')
    if path:
        errors.print('Saved: ' + safe(path), markup=False)
    return 1 if failed else 0


def scan_params(args):
    return {'interface': args.interface, 'cached': args.cached, 'active': args.active, 'passive': args.passive, 'timeout': args.timeout}


def main():
    try:
        raise SystemExit(asyncio.run(run(sys.argv[1:])))
    except KeyboardInterrupt:
        raise SystemExit(130)
    except (ValueError, OSError) as error:
        errors.print('vulnfin: ' + safe(error), style='red', markup=False)
        raise SystemExit(1)
