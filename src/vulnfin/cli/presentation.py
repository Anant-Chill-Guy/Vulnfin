from __future__ import annotations

import json
from rich.console import Console
from rich.table import Table
from rich.text import Text

from ..core.assessment import pmf_label, security_label, wifi_observations


console = Console(highlight=False)


def safe(value):
    return ''.join(c if c.isprintable() else f'\\x{ord(c):02x}'
                   for c in str(value if value is not None else '—'))


def table(title, columns, rows):
    rows = list(rows)
    t = Table(title=title, header_style='bold', expand=False, padding=(0, 1))
    for name in columns: t.add_column(name, overflow='fold')
    if not rows:
        console.print('No results.', markup=False)
        return
    for row in rows: t.add_row(*(Text(safe(x)) for x in row))
    console.print(t)


def print_json(data):
    console.print_json(json=json.dumps(data, ensure_ascii=True), highlight=False)


def structured(data):
    if isinstance(data, dict):
        return {k: structured(v) for k, v in data.items() if k not in ('raw', 'information_elements_tree')}
    if isinstance(data, list): return [structured(x) for x in data]
    return data


def review_label(findings):
    if not findings: return '—'
    if any(f['priority'] == 3 for f in findings): return 'Legacy config'
    return 'Review policy'


def wifi_table(aps):
    def order(ap):
        findings = wifi_observations(ap)
        priority = max((f['priority'] for f in findings), default=0)
        signal = ap.get('signal_dbm')
        return -priority, -(signal if signal is not None else -999)
    rows = []
    for ap in sorted(aps, key=order):
        signal = ap.get('signal_dbm')
        rows.append((ap.get('ssid') or '<hidden>', ap['bssid'], ap.get('channel'),
                     f'{signal} dBm' if signal is not None else '—',
                     security_label(ap), review_label(wifi_observations(ap))))
    table('Wi-Fi', ('SSID', 'BSSID', 'Ch', 'Signal', 'Security', 'Review'), rows)


def show_findings(findings):
    if not findings:
        console.print('No findings from this scan.', markup=False)
        return
    console.print('Findings', style='bold', markup=False)
    for finding in findings:
        console.print(safe(finding['title']), style='yellow', markup=False)
        console.print('  Evidence: ' + safe('; '.join(finding['evidence'])), markup=False)
        console.print('  Impact: ' + safe(finding['meaning']), markup=False)
        console.print('  Check: ' + safe(finding['verification']), markup=False)


def cpu_fields(data):
    found = {}
    def visit(rows):
        for row in rows or []:
            if isinstance(row, dict):
                if row.get('field'): found[row['field'].rstrip(':')] = row.get('data')
                visit(row.get('children'))
    visit((data or {}).get('lscpu'))
    return found


def memory_gib(value):
    try: return f'{int(value.split()[0]) / 1024 / 1024:.1f} GiB'
    except (ValueError, AttributeError, IndexError): return '—'


def show_observation(observation, *, mode='summary'):
    value = observation.to_dict() if hasattr(observation, 'to_dict') else observation
    if mode == 'json':
        print(json.dumps(value, indent=2, ensure_ascii=True))
        return
    if mode == 'details':
        print_json(structured(value))
        return
    data, plugin = value['data'], value['plugin']
    if value.get('status') not in ('OBSERVED', 'EMPTY'):
        console.print('Incomplete results.' if value['status'] == 'PARTIAL' else 'Scan failed.', style='yellow', markup=False)
    if plugin == 'recon.wifi' and 'access_points' in data:
        aps = data['access_points']
        if aps:
            wifi_table(aps)
            console.print(f"{len(aps)} BSS · {data['method']} · {data['interface']}", markup=False)
        else:
            message = 'No cached networks' if data['method'] == 'cached' else 'No networks found'
            hint = ' · try -A' if data['method'] == 'passive' else ''
            console.print(f"{message} · {data['method']} · {data['interface']}{hint}", markup=False)
    elif plugin == 'recon.host' and 'platform' in data:
        cpu = cpu_fields(data.get('cpu'))
        table('Host', ['Field', 'Value'], [
            ('System', f"{data['platform'].get('system')} {data['platform'].get('release')}"),
            ('CPU', cpu.get('Model name')), ('Logical CPUs', cpu.get('CPU(s)')),
            ('RAM / available', f"{memory_gib(data['memory_proc'].get('MemTotal'))} / {memory_gib(data['memory_proc'].get('MemAvailable'))}"),
            ('GPU', data.get('gpu_csv')), ('Virtualization / KVM', f"{data.get('virtualization_environment')} / {data.get('kvm_current_user_access')} access")])
        for field, status in cpu.items():
            if field.startswith('Vulnerability ') and str(status).lower().startswith('vulnerable'):
                console.print('CPU: ' + safe(field.removeprefix('Vulnerability ')) + ' · ' + safe(status),
                              style='yellow', markup=False)
    elif plugin == 'recon.hardware' and 'interfaces' in data:
        physical = [x for x in data['interfaces'] if x.get('wireless') or x.get('driver_raw')]
        table('Interfaces', ['Name', 'Wireless', 'State'], [(x['interface'], x['wireless'], x['operstate']) for x in physical])
        table('Radios', ['PHY', 'Bands', 'Modes'],
            [(x['phy'], ', '.join(x['bands']), ', '.join(x['modes'])) for x in data['wifi_phys']])
        if data['serial_ports']:
            table('Serial', ['Port', 'VID:PID'], [(x['port'],
                f"{x['properties'].get('ID_VENDOR_ID', '?')}:{x['properties'].get('ID_MODEL_ID', '?')}") for x in data['serial_ports']])
    elif plugin == 'recon.network' and 'addresses' in data:
        table('Local network', ['Interface', 'IPv4', 'IPv6 count'],
            [(x['ifname'], ', '.join(f"{a['local']}/{a['prefixlen']}" for a in x.get('addr_info', []) if a['family'] == 'inet'),
              sum(a['family'] == 'inet6' for a in x.get('addr_info', []))) for x in data['addresses'] or [] if x['ifname'] != 'lo'])
        gateways = [f"{r.get('gateway')} via {r.get('dev')}" for r in data.get('routes_v4') or [] if r.get('dst') == 'default']
        console.print('Default route: ' + safe(', '.join(gateways) or 'none'), markup=False)
        console.print(f"Neighbour-cache entries: {len(data.get('neighbours') or [])}", markup=False)
    elif value.get('status') != 'ERROR':
        print_json(structured(data))
    failures = [c for c in value.get('commands', []) if c.get('status') != 'OK' and not c.get('recovered')]
    messages = set()
    for item in failures:
        detail = item.get('error') or item['status'].lower().replace('_', ' ')
        text = safe(item['argv'][0] + ': ' + detail)
        if text not in messages:
            console.print(text, style='yellow', markup=False)
            messages.add(text)
    if value.get('status') == 'ERROR' and not failures:
        console.print(safe(data.get('error') or 'Use -j for details.'), style='red', markup=False)
    if value.get('status') in ('ERROR', 'PARTIAL'):
        for warning in value.get('warnings', []):
            message = safe(warning)
            if message not in messages:
                console.print(message, style='yellow', markup=False)
                messages.add(message)

    if any(c.get('truncated') for c in value.get('commands', [])):
        console.print('Some command output was truncated; details may be incomplete.', style='yellow', markup=False)


def show_wifi_target(ap, *, details=False):
    if details:
        print_json(structured(ap))
        return
    table('Target', ('Field', 'Value'), (
        ('SSID', ap.get('ssid') or '<hidden>'),
        ('BSSID', ap.get('bssid')),
        ('Interface', ap.get('interface')),
        ('Channel', ap.get('channel')),
        ('Signal', f"{ap.get('signal_dbm')} dBm" if ap.get('signal_dbm') is not None else '—'),
        ('Security', security_label(ap)),
        ('PMF', pmf_label(ap)),
    ))
    findings = wifi_observations(ap)
    if findings:
        show_findings(findings)
