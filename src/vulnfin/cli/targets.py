from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..core.findings import SEVERITIES
from ..core.targets import assessment_map, read_selection, select_target
from ..adapters.verification import verify_selection
from .presentation import (ASSESSMENT_TEXT, assessment_targets, assessment_warning, console,
                           safe, show_assessment, table)

TYPES = {'public': 0, 'random': 1, 'public-identity': 2, 'random-identity': 3}


def extend_parser(parser):
    from .app import output_options
    commands = next(a.choices for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    target = commands['target']
    target.description = 'Inspect, select and verify exact endpoints'
    actions = next(a for a in target._actions if isinstance(a, argparse._SubParsersAction))
    for action in ('list', 'map', 'select'):
        p = actions.add_parser(action, help={'list': 'List assessed endpoints and findings',
            'map': 'Map findings to exact endpoints', 'select': 'Select one endpoint and its findings'}[action])
        p.add_argument('-I', '--input', type=Path, action='append', required=True, help='Assessment JSON; repeat -I for more files; - reads standard input')
        p.add_argument('--context', type=Path, action='append', default=[], help='Recon report for tentative address links; repeat for more')
        p.add_argument('--protocol', choices=('wifi', 'ble', 'ip'), help='Endpoint protocol')
        if action == 'select':
            p.add_argument('address', help='Exact IP address or radio address')
            p.add_argument('-p', '--port', type=int, help='Exact TCP port')
            p.add_argument('--type', choices=TYPES, help='BLE address type')
            p.add_argument('--finding', action='append', default=[], metavar='ID', help='Select this finding; repeat for several')
        else:
            p.add_argument('--severity', choices=('info', 'low', 'medium', 'high'), help='Keep findings at this severity or above')
            p.add_argument('--name', help='Filter observed names by substring')
            p.add_argument('--findings-only', action='store_true', help='Show only endpoints with matching findings')
        output_options(p)
        p.add_argument('-o', '--output', type=Path, help='Save JSON to a new file')
    p = actions.add_parser('verify', help='Refresh a selection and recheck its conditions')
    p.add_argument('-I', '--input', type=Path, required=True, help='Selected-target JSON; use - for standard input')
    p.add_argument('-i', '--interface', help='Wi-Fi adapter for a fresh scan')
    p.add_argument('--port', default='auto', help='ESP serial port for BLE advertisement checks')
    p.add_argument('--adapter', default='hci0', help='Linux Bluetooth adapter for selected GATT reads')
    p.add_argument('--timeout', type=float, default=3, help='Service operation timeout, 0.2–10 seconds')
    p.add_argument('--scan-timeout', type=int, default=45, help='Wi-Fi scan timeout, 5–120 seconds')
    p.add_argument('--duration', type=int, default=10, help='BLE advertisement scan duration, 1–60 seconds')
    p.add_argument('--capture', type=Path, help='Explicit PCAP to recheck historical packet evidence')
    output_options(p)
    p.add_argument('-o', '--output', type=Path, help='Save verification JSON to a new file')
    p.add_argument('-v', '--verbose', action='store_true', help='Show progress on stderr')


def title(finding):
    return ASSESSMENT_TEXT.get(finding['title'], (finding['title'],))[0]


def show_mapping(mapped, details=False):
    groups = mapped['targets']
    if not groups:
        console.print('No matching endpoints in these reports.', markup=False)
    else:
        assessment_targets([g['target'] for g in groups], evidence=[
            str(len(g['findings'])) + (' finding' if len(g['findings']) == 1 else ' findings') +
            (' · ' + ('Note' if g['highest_severity'] == 'info' else g['highest_severity'].capitalize()) if g['highest_severity'] else '')
            for g in groups], evidence_label='Findings')
    if details:
        rows = [(f['id'], f['target']['address'], f['target'].get('port'), f['severity'], title(f))
                for g in groups for f in g['findings']]
        if rows:
            table('Findings', ('ID', 'Address', 'Port', 'Level', 'Finding'), rows)
        if mapped.get('address_matches'):
            table('Tentative address links', ('Wi-Fi address', 'IP', 'Basis'),
                  ((r['wifi'], r['ip'], r['basis']) for r in mapped['address_matches']))
    notes = list(mapped.get('warnings', [])) + [v for g in groups for v in g.get('warnings', [])]
    for message in dict.fromkeys(notes):
        translated = assessment_warning(message)
        if translated:
            console.print('Note: ' + safe(translated), style='yellow', markup=False)
    console.print(f"{len(groups)} endpoints · {sum(len(g['findings']) for g in groups)} findings", markup=False)


def show_selection(selection, details=False):
    console.print('Selected target', style='bold', markup=False)
    assessment_targets([selection['target']])
    if selection['findings']:
        columns = ('ID', 'Level', 'Finding') if details else ('Level', 'Finding')
        table('Selected findings', columns,
              (([f['id']] if details else []) + [f['severity'].capitalize(), title(f)] for f in selection['findings']))
    else:
        console.print('No findings selected. Verification will refresh endpoint observations.', markup=False)
    for message in dict.fromkeys(selection.get('warnings', [])):
        translated = assessment_warning(message)
        if translated:
            console.print('Note: ' + safe(translated), style='yellow', markup=False)
    if details:
        table('Sources', ('File', 'Assessed at', 'SHA256'),
              ((s.get('file'), s.get('assessed_at'), s.get('sha256')) for s in selection['observations']))


def show_verification(result, details=False):
    console.print('Verification', style='bold', markup=False)
    assessment_targets([result['target']])
    states = {'reproduced': 'Condition reproduced', 'not_observed': 'Not seen this time', 'inconclusive': 'Could not determine',
              'needs_review': 'Needs review', 'historical': 'Capture evidence only', 'unsupported': 'Not supported'}
    target_states = {'observed': 'Endpoint observed', 'not_seen': 'Endpoint not seen in this scan', 'unreachable': 'TCP connection refused',
                     'changed': 'Observed name changed', 'historical': 'Historical capture only', 'inconclusive': 'Endpoint status could not be determined'}
    console.print(target_states.get(result['target_status'], result['target_status']), markup=False)
    if not result['results']:
        console.print('No vulnerability finding was selected; this run checks endpoint observations only.', markup=False)
    if result['results']:
        columns = ('ID', 'Finding', 'Result', 'Evidence') if details else ('Finding', 'Result', 'Evidence')
        table('Conditions', columns, (([r['finding_id']] if details else []) +
              [ASSESSMENT_TEXT.get(r['title'], (r['title'],))[0], states.get(r['outcome'], r['outcome']), '; '.join(r['evidence'])]
              for r in result['results']))
    for message in dict.fromkeys(result['warnings']):
        translated = assessment_warning(message)
        if translated:
            console.print('Note: ' + safe(translated), style='yellow', markup=False)
    if details:
        show_assessment(result['fresh_assessment'], details=True)
    console.print('Condition checks complete.' if result['status'] == 'COMPLETE' else
                  'Verification interrupted.' if result['status'] == 'INTERRUPTED' else 'Some conditions still need verification or review.', markup=False)


async def dispatch(args):
    from .app import errors, output_path, write_new
    path = output_path(args.output) if args.output else None
    if args.action == 'verify':
        selection = read_selection(args.input)
        result = await verify_selection(selection, interface=args.interface, serial_port=args.port, adapter=args.adapter,
            timeout=args.timeout, scan_timeout=args.scan_timeout, duration=args.duration, capture=args.capture, verbose=args.verbose)
        code = 130 if result['status'] == 'INTERRUPTED' else 0 if result['status'] == 'COMPLETE' else 1
    else:
        result = assessment_map(args.input, context=args.context)
        if args.action == 'select':
            if args.port is not None and not 1 <= args.port <= 65535:
                raise ValueError('TCP port must be 1–65535')
            result = select_target(result, args.address, protocol=args.protocol, port=args.port,
                address_type=TYPES.get(args.type), findings=args.finding)
        else:
            filtered = []
            for group in result['targets']:
                if args.protocol and group['target']['protocol'] != args.protocol:
                    continue
                if args.name and not any(args.name.casefold() in name.casefold() for name in group['names']):
                    continue
                if args.severity:
                    group = {**group, 'findings': [f for f in group['findings'] if SEVERITIES[f['severity']] <= SEVERITIES[args.severity]]}
                    group['highest_severity'] = min((f['severity'] for f in group['findings']), key=SEVERITIES.get, default=None)
                if (args.findings_only or args.severity) and not group['findings']:
                    continue
                filtered.append(group)
            result['targets'] = filtered
        code = 0
    if path:
        write_new(path, result)
        errors.print('Saved: ' + safe(path), markup=False)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=True))
    elif args.action == 'verify':
        show_verification(result, args.details)
    elif args.action == 'select':
        show_selection(result, args.details)
    else:
        show_mapping(result, args.details)
    return code
