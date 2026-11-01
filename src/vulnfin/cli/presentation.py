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
                     f'{signal:g} dBm' if signal is not None else '—',
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
    elif plugin == 'recon.hardware' and 'interfaces' in data:
        physical = [x for x in data['interfaces'] if x.get('wireless') or x.get('driver_raw')]
        table('Interfaces', ['Name', 'Wireless', 'State'], [(x['interface'], x['wireless'], x['operstate']) for x in physical])
        table('Radios', ['PHY', 'Bands', 'Modes'],
            [(x['phy'], ', '.join(x['bands']), ', '.join(x['modes'])) for x in data['wifi_phys']])
        if data['serial_ports']:
            table('Serial', ['Port', 'VID:PID'], [(x['port'],
                f"{x['properties'].get('ID_VENDOR_ID', '?')}:{x['properties'].get('ID_MODEL_ID', '?')}") for x in data['serial_ports']])
    elif plugin == 'recon.network' and 'addresses' in data:
        table('Local network', ['Interface', 'IPv4', 'IPv6'],
            [(x['ifname'], ', '.join(f"{a['local']}/{a['prefixlen']}" for a in x.get('addr_info', []) if a['family'] == 'inet'),
              ', '.join(f"{a['local']}/{a['prefixlen']}" for a in x.get('addr_info', []) if a['family'] == 'inet6'))
             for x in data['addresses'] or [] if x['ifname'] != 'lo'])
        defaults = [(family, r.get('gateway') or '—', r.get('dev') or '—')
                    for family, key in (('IPv4', 'routes_v4'), ('IPv6', 'routes_v6'))
                    for r in data.get(key) or [] if r.get('dst') == 'default']
        if defaults:
            table('Default routes', ['Family', 'Gateway', 'Interface'], defaults)
        neighbours = data.get('neighbours') or []
        if neighbours:
            table('Neighbour cache', ['IP', 'MAC', 'Interface', 'State'],
                  [(r.get('dst'), r.get('lladdr'), r.get('dev'),
                    ', '.join(r.get('state', [])) if isinstance(r.get('state'), list) else r.get('state')) for r in neighbours])
        else:
            console.print('No neighbour-cache entries.', markup=False)
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


ASSESSMENT_TEXT = {
    'No link encryption advertised': ('Open Wi-Fi',
        'These networks advertise no Wi-Fi encryption. This may be intentional for guest access.',
        'Check the network policy before treating this as a weakness.'),
    'Legacy WPA advertised': ('Legacy WPA enabled',
        'These networks advertise the older WPA security mode. This does not show which mode clients actually use.',
        'Check whether legacy WPA compatibility is still needed.'),
    'Legacy cipher advertised': ('Older Wi-Fi encryption advertised',
        'These networks advertise older encryption options.',
        'Check the AP settings and the encryption clients actually negotiate.'),
    'PMF requirement needs review': ('Management-frame protection needs review',
        'SAE or OWE is advertised without a mandatory PMF bit. Mixed security modes need a closer look.',
        'Check transition-mode settings and the protection negotiated by clients.'),
    'TLS certificate validation failed': ('Certificate could not be verified',
        'The certificate did not pass this computer’s trust and identity checks.',
        'Check the intended DNS name and trust policy. A private CA or an IP-only check may explain the result.'),
    'Basic authentication offered over HTTP': ('Password login offered over plain HTTP',
        'Basic authentication is advertised on an unencrypted HTTP connection.',
        'Confirm that clients must use HTTPS before submitting credentials.'),
    'Browser security headers need review': ('Browser protections need review',
        'Some browser security headers are missing from the checked HTML response.',
        'Review the missing headers in the context of the application; this alone does not establish an exploit.'),
    'Credentialed CORS accepts the probe origin': ('External origin accepted with credentials',
        'The response allows the external origin supplied by the check and permits credentials.',
        'Verify whether an authenticated browser could read sensitive information.'),
    'Directory listing returned': ('Directory contents are listed',
        'The server listed directory contents without supplied credentials.',
        'Check whether the directory and its files are meant to be public.'),
    'Git HEAD metadata is publicly readable': ('Git metadata is exposed',
        'The checked .git/HEAD path returned a response that looks like Git repository metadata.',
        'Confirm the response and block web access to repository files if unintended.'),
    'Diagnostic output needs review': ('Possible debug information',
        'The response contains a debug or error-page marker.',
        'Check the response context; documentation or ordinary page content can contain the same text.'),
    'SSH 1 compatibility advertised': ('SSH 1 compatibility advertised',
        'The server banner advertises support for the older SSH 1 protocol.',
        'Verify the SSH configuration and remove SSH 1 compatibility if present.'),
    'TLS upgrade not advertised': ('Encrypted connection upgrade not advertised',
        'The service did not advertise a TLS upgrade in its capability response.',
        'Check the intended secure endpoint and whether clients send sensitive data here.'),
    'Password authentication advertised before TLS': ('Password authentication offered before TLS',
        'SMTP advertises password authentication before an encrypted connection is established.',
        'Verify whether the server actually requires TLS before accepting a test account’s credentials.'),
    'Redis PING accepted without supplied credentials': ('Redis answers without login',
        'Redis accepted PING without supplied credentials. This does not establish access to stored data.',
        'Check the intended network exposure and Redis permissions.'),
    'MQTT connection accepted without supplied credentials': ('MQTT accepts a connection without login',
        'The broker accepted a clean-session connection without supplied credentials.',
        'Check the anonymous-access policy. Topic read and publish permissions were not tested.'),
    'ONVIF device information returned without supplied credentials': ('Camera information available without login',
        'The ONVIF endpoint returned device information without supplied credentials.',
        'Check whether this metadata should be public. Stream and administrator access were not tested.'),
    'Unprotected Wi-Fi data frames observed': ('Wi-Fi data frames without link protection',
        'The capture includes data frames without the Wi-Fi Protected bit.',
        'Inspect the relevant frames and determine whether they expose sensitive information.'),
    'Selected characteristic read succeeded': ('Selected BLE value could be read',
        'The selected characteristic returned data without requested pairing or supplied credentials. The value is omitted.',
        'Check the data’s purpose and intended read permissions. Link encryption and application authorization remain unverified.'),
    'SMB signing is not required': ('SMB signing is optional',
        'The reported SMB configuration does not require message signing.',
        'Review signing policy and authentication paths; relay feasibility needs additional verification.'),
    'Legacy RDP encryption accepted': ('Older RDP encryption accepted',
        'The service accepted the listed legacy RDP encryption options.',
        'Review RDP security settings, NLA requirements and client compatibility.'),
    'VNC advertises None authentication': ('VNC offers access without authentication',
        'VNC advertises the None authentication type. Desktop access has not been exercised.',
        'Verify whether this option grants a session and whether that access is intended.'),
    'Legacy SSH algorithms advertised': ('Older SSH algorithms advertised',
        'The server advertises the listed legacy SSH algorithms.',
        'Review the SSH policy and the algorithms clients actually negotiate.'),
}


def assessment_identity(target):
    return tuple(target.get(k) for k in ('protocol', 'address', 'port', 'address_type', 'scheme', 'path'))


def assessment_name(target):
    if target.get('name'):
        return str(target['name'])
    if target.get('observed_names'):
        return ', '.join(target['observed_names'])
    return '<hidden>' if target.get('name_state') == 'hidden' else '—'


def assessment_targets(rows, *, evidence=None, metadata=False, sources=None, evidence_label='Evidence'):
    from rich import box
    targets = list(rows)
    if not targets:
        return
    protocols = list(dict.fromkeys(t.get('protocol') for t in targets))
    if len(protocols) > 1:
        for protocol in protocols:
            indices = [i for i, t in enumerate(targets) if t.get('protocol') == protocol]
            console.print({'wifi': 'Wi-Fi', 'ble': 'BLE', 'ip': 'Network services'}.get(protocol, str(protocol)), style='bold', markup=False)
            assessment_targets([targets[i] for i in indices],
                evidence=[evidence[i] for i in indices] if evidence is not None else None, metadata=metadata,
                sources=[sources[i] for i in indices] if sources is not None else None, evidence_label=evidence_label)
        return
    radio = all(t.get('protocol') in ('wifi', 'ble') for t in targets)
    wifi_only = all(t.get('protocol') == 'wifi' for t in targets)
    ble_only = all(t.get('protocol') == 'ble' for t in targets)
    view = Table(box=box.SIMPLE_HEAD, show_edge=False, padding=(0, 1), header_style='bold')
    columns = ['Network' if wifi_only else 'Name', 'BSSID' if wifi_only else 'Address']
    if wifi_only:
        columns += ['Ch', 'Signal']
    elif ble_only:
        columns += ['Type', 'Signal']
    else:
        columns += ['Port', 'Service']
        if any(t.get('path') for t in targets):
            columns.append('Path')
    if evidence is not None:
        columns.append(evidence_label)
    if metadata:
        columns += ['Status', 'Confidence']
    if sources is not None:
        columns.append('Source')
    for column in columns:
        view.add_column(column, overflow='fold', no_wrap=radio and column in ('Address', 'BSSID'),
                        min_width=17 if radio and column in ('Address', 'BSSID') else None)
    types = {0: 'Public', 1: 'Random', 2: 'Public identity', 3: 'Random identity'}
    for index, target in enumerate(targets):
        values = [assessment_name(target), target.get('address')]
        signal = target.get('signal_dbm')
        if wifi_only:
            values += [target.get('channel'), f'{signal:g} dBm' if isinstance(signal, (int, float)) else '—']
        elif ble_only:
            values += [types.get(target.get('address_type'), 'Unknown'), f'{signal:g} dBm' if isinstance(signal, (int, float)) else '—']
        else:
            service = target.get('service') or '—'
            if service.lower() in ('http', 'https', 'tls', 'ssh', 'ftp', 'smtp', 'rtsp', 'mqtt', 'onvif', 'rdp', 'vnc', 'smb'):
                service = service.upper()
            if target.get('product'):
                service += ' · ' + target['product'] + (' ' + str(target['product_version']) if target.get('product_version') else '')
            values += [target.get('port'), service]
            if 'Path' in columns:
                values.append(target.get('path'))
        if evidence is not None:
            values.append(evidence[index])
        if metadata:
            values += [target.get('_state'), target.get('_confidence')]
        if sources is not None:
            values.append(sources[index])
        view.add_row(*(Text(safe(value)) for value in values))
    console.print(view)


def assessment_warning(message):
    if 'Cached results can be stale' in message:
        return 'Cached Wi-Fi results may be old.'
    if message.startswith('Source was incomplete or failed:'):
        return None
    if message.startswith('Observation time unavailable:'):
        return 'The source has no usable observation time: ' + message.split(': ', 1)[-1].replace('live:', '')
    if message.startswith('Evidence is older than 24 hours'):
        return 'Saved evidence is over 24 hours old, or its clock is ahead: ' + message.split(': ', 1)[-1]
    if message.startswith('live:recon.'):
        return message.split(': ', 1)[-1]
    return message


def show_assessment(payload, details=False):
    data = payload['data']
    findings, checks = data['findings'], data['checks']
    targets = data.get('targets') or []
    groups = {}
    for finding in findings:
        key = tuple(finding[k] for k in ('check', 'title', 'severity', 'meaning', 'next_check'))
        groups.setdefault(key, []).append(finding)
    for key, group in groups.items():
        first = group[0]
        title, meaning, next_check = ASSESSMENT_TEXT.get(first['title'],
            (first['title'], first['meaning'], first['next_check']))
        level = 'Note' if first['severity'] == 'info' else first['severity'].capitalize()
        if all(f['state'] == 'candidate' for f in group):
            title = 'Possible advisory match: ' + title
        console.print(safe(title + ' · ' + level), style='bold', markup=False)
        same_evidence = all(f['evidence'] == first['evidence'] for f in group)
        evidence = ['; '.join(f['evidence']) for f in group] if not same_evidence else None
        duplicate = len({assessment_identity(f['target']) for f in group}) != len(group)
        rows = [{**f['target'], '_state': {'observed': 'Observed setting', 'potential': 'Needs verification', 'candidate': 'Advisory match'}.get(f['state'], f['state']),
                 '_confidence': f['confidence'].capitalize()} for f in group]
        assessment_targets(rows, evidence=evidence, metadata=details,
                           sources=[f.get('source') or '—' for f in group] if details or duplicate else None)
        if same_evidence and (details or first['severity'] != 'info'):
            console.print('Evidence: ' + safe('; '.join(first['evidence'])), markup=False)
        console.print(safe(meaning), markup=False)
        console.print(safe(next_check), markup=False)
        console.print()
    empty = bool(checks) and all(c['outcome'] == 'empty' for c in checks)
    if not findings:
        if targets:
            assessment_targets(sorted(targets, key=lambda t: (assessment_name(t), t['address'], t.get('port', 0))))
        if empty:
            for check in checks:
                console.print(safe(check['evidence']), markup=False)
        elif checks and all(c['outcome'] == 'closed' for c in checks):
            console.print('None of the requested ports accepted a TCP connection.', markup=False)
        elif any(c['outcome'] in ('completed', 'observed') for c in checks):
            advertising_only = all(c['check'] in ('ble.advertisement', 'ble.gatt') for c in checks) and all(c['outcome'] == 'not_run' for c in checks if c['check'] == 'ble.gatt')
            console.print('No issues found in the advertising data.' if advertising_only else 'No issues found by the completed checks.', markup=False)
        else:
            console.print('No assessment completed.', markup=False)
    labels = {'source': 'Source scan', 'coverage': 'Available evidence', 'wifi.security': 'Wi-Fi security',
              'ble.advertisement': 'BLE advertising data', 'ble.gatt': 'BLE services',
              'ble.gatt.read': 'BLE read access', 'ble.gatt.characteristic': 'BLE characteristic',
              'service.follow_up': 'Live service checks', 'service.identification': 'Service identification',
              'service.connection': 'TCP connection', 'onvif.information': 'Camera information',
              'packet.exposure': 'Packet exposure', 'http.git': 'Git metadata', 'http.body': 'HTTP content',
              'http.response': 'HTTP response', 'tls.certificate': 'Certificate', 'tls.negotiation': 'TLS connection',
              'tls.legacy': 'Older TLS support'}
    outcomes = {'completed': 'Checked', 'observed': 'Response received', 'inconclusive': 'Could not determine',
                'failed': 'Failed', 'unsupported': 'Not supported', 'not_run': 'Not checked', 'empty': 'No results', 'closed': 'Refused'}
    if details:
        table('Check details', ('Name', 'Address', 'Check', 'Result', 'Evidence'),
              ((assessment_name(c['target']) if c['target'] else '—',
                c['target']['address'] + (':' + str(c['target']['port']) if 'port' in c['target'] else '') if c['target'] else '—',
                labels.get(c['check'], c['check'].replace('nmap.', 'Nmap: ').replace('.', ' ').capitalize()),
                outcomes.get(c['outcome'], c['outcome']), c['evidence']) for c in checks))
    else:
        pending = {}
        for check in checks:
            if check['outcome'] in ('failed', 'inconclusive', 'unsupported', 'not_run'):
                pending.setdefault((check['check'], check['outcome'], check['evidence']), []).append(check['target'])
        for (check, outcome, evidence), affected in pending.items():
            label = labels.get(check, check.replace('nmap.', 'Nmap: ').replace('.', ' ').capitalize())
            if check == 'ble.gatt' and outcome == 'not_run' and evidence.startswith('Connection required;'):
                console.print('BLE access permissions were not checked. Connect to a specific address to inspect its services.', markup=False)
                continue
            if check == 'service.follow_up' and outcome == 'not_run':
                console.print('Live service checks were not run. Use assess services with the IP or saved service report.', markup=False)
                continue
            console.print(safe(label + ' · ' + outcomes.get(outcome, outcome)), style='yellow', markup=False)
            visible = [t for t in affected if t]
            if visible:
                assessment_targets(visible)
            console.print(safe(evidence), markup=False)
    shown = set()
    for warning in payload.get('warnings', []):
        message = assessment_warning(warning)
        if message and message not in shown:
            console.print('Note: ' + safe(message), style='yellow', markup=False)
            shown.add(message)
    if empty and not details:
        return
    count = len({tuple(t.get(k) for k in ('protocol', 'address', 'port', 'address_type')) for t in targets})
    ending = ' · incomplete' if payload['status'] in ('ERROR', 'PARTIAL', 'UNAVAILABLE') else ''
    console.print(f"{len(findings)} {'finding' if len(findings) == 1 else 'findings'} · {count} {'endpoint' if count == 1 else 'endpoints'}{ending}", markup=False)
