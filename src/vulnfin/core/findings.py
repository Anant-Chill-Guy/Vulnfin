from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
import sys

from .assessment import wifi_observations
from .models import utcnow

MAC = re.compile(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}')
SEVERITIES = {'high': 0, 'medium': 1, 'low': 2, 'info': 3}
CATALOGUE = (
    ('wifi.security', 'Wi-Fi', 'Legacy WPA/ciphers, open links and PMF context', 'saved or fresh scan'),
    ('ble.advertisement', 'BLE', 'Malformed advertisements and advertised identifiers', 'saved or fresh scan'),
    ('ble.gatt', 'BLE', 'Services, characteristic properties and selected reads', 'Linux Bluetooth; optional Bleak'),
    ('http.configuration', 'HTTP', 'Basic authentication, cookies, CORS and browser protections', 'HTTP response'),
    ('http.exposure', 'HTTP', 'Directory listings, diagnostic pages and Git HEAD exposure', 'bounded GET requests'),
    ('tls.configuration', 'TLS', 'Certificate validation and deprecated TLS negotiation', 'TLS handshakes'),
    ('ssh.protocol', 'SSH', 'Protocol banner and SSH 1 support', 'server banner'),
    ('ftp.transport', 'FTP', 'FTP greeting and advertised TLS upgrade', 'FEAT; no login'),
    ('smtp.transport', 'SMTP', 'SMTP greeting, STARTTLS and plaintext AUTH advertisement', 'EHLO; no login'),
    ('rtsp.methods', 'RTSP', 'Protocol response and advertised methods', 'OPTIONS; no stream'),
    ('redis.access', 'Redis', 'PING response and authentication requirement', 'PING; no data reads'),
    ('mqtt.access', 'MQTT', 'Connection acceptance without supplied credentials', 'clean CONNECT; no subscriptions'),
    ('onvif.information', 'ONVIF', 'Device information returned without supplied credentials', 'GetDeviceInformation; no streams'),
    ('packet.exposure', 'Wi-Fi packets', 'Unprotected data frames and decoded cleartext protocols', 'offline TShark'),
    ('nmap.protocols', 'SSH/SMB/RDP/VNC', 'Legacy algorithms, signing, encryption and authentication types', 'optional Nmap; --nmap'),
    ('advisory.match', 'Services', 'Exact product/version matches in a supplied advisory file', 'offline; candidates only'),
)


def catalogue():
    offline = {'wifi.security', 'ble.advertisement', 'packet.exposure', 'advisory.match'}
    return [{'id': identity, 'surface': surface, 'description': description, 'requirements': requirements,
             'traffic': 'evidence only' if identity in offline else 'active protocol requests',
             'persistent_remote_writes': False}
            for identity, surface, description, requirements in CATALOGUE]


def text(value, limit=512):
    value = str(value if value is not None else '')
    return ''.join(c if c.isprintable() else ' ' for c in value)[:limit]


def ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError('Expected a literal IP address') from None
    if address.is_multicast or address.is_unspecified:
        raise ValueError('Choose a unicast IP address')
    return str(address)


def endpoint(address, port=None, protocol='ip', address_type=None):
    if protocol in ('wifi', 'ble'):
        if not isinstance(address, str) or not MAC.fullmatch(address):
            raise ValueError('Invalid radio address in evidence')
        address = address.lower()
    else:
        address = ip(address)
    value = {'protocol': protocol, 'address': address}
    if port is not None:
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError('Invalid TCP port in evidence')
        value['port'] = port
        value['transport'] = 'tcp'
    if address_type is not None:
        value['address_type'] = address_type
    return value


class Assessment:
    def __init__(self):
        self.findings = []
        self.checks = []
        self.sources = []
        self.warnings = []
        self._keys = set()
        self._targets = {}

    def remember(self, target):
        if target is None:
            return
        key = tuple(target.get(k) for k in ('protocol', 'address', 'port', 'address_type', 'scheme', 'path'))
        previous = self._targets.get(key, {})
        self._targets[key] = {**previous, **{k: v for k, v in target.items() if v is not None}}

    def check(self, check, target, outcome, evidence, source=None):
        if len(self.checks) >= 50000:
            raise ValueError('Assessment exceeds 50000 checks; narrow the input')
        self.remember(target)
        self.checks.append({'check': check, 'target': dict(target) if target else None, 'outcome': outcome,
                            'evidence': text(evidence, 2048), 'source': source})

    def add(self, check, target, title, severity, confidence, evidence, meaning, next_check,
            state='observed', source=None):
        evidence = [text(v, 1024) for v in evidence]
        key = (check, json.dumps(target, sort_keys=True), title, source, json.dumps(evidence))
        if key in self._keys:
            return
        self._keys.add(key)
        identity = hashlib.sha256(json.dumps(key).encode()).hexdigest()[:12]
        self.remember(target)
        self.findings.append({'id': identity, 'check': check, 'target': dict(target),
            'title': title, 'severity': severity, 'confidence': confidence, 'state': state,
            'evidence': evidence, 'meaning': meaning, 'next_check': next_check, 'source': source,
            'confirmed_vulnerability': False})

    def result(self):
        failures = [c for c in self.checks if c['outcome'] in ('failed', 'inconclusive')]
        empty = bool(self.checks) and all(c['outcome'] == 'empty' for c in self.checks)
        unavailable = bool(self.checks) and all(c['outcome'] in ('unsupported', 'not_run') for c in self.checks)
        failed = bool(self.checks) and all(c['outcome'] == 'failed' for c in self.checks)
        return {'plugin': 'assess', 'schema': 'vulnfin.assessment.v1', 'assessed_at': utcnow(),
            'status': 'ERROR' if failed else 'UNAVAILABLE' if unavailable else 'PARTIAL' if failures or self.warnings else 'EMPTY' if empty else 'OBSERVED',
            'data': {'findings': sorted(self.findings, key=lambda f: (SEVERITIES[f['severity']], f['target']['address'], f['check'])),
                     'checks': self.checks, 'sources': self.sources, 'targets': list(self._targets.values()),
                     'scope': 'Supported evidence and bounded probes only; target selection and exploit applicability remain separate.'},
            'warnings': self.warnings}


def load_json(path, limit=32*1024*1024):
    path = Path(path).expanduser()
    try:
        if str(path) == '-':
            raw = sys.stdin.buffer.read(limit + 1)
        else:
            with path.open('rb') as stream:
                raw = stream.read(limit + 1)
    except FileNotFoundError:
        raise ValueError('File not found: ' + str(path)) from None
    if len(raw) > limit:
        raise ValueError('JSON file exceeds 32 MiB: ' + str(path))
    try:
        def invalid_constant(value):
            raise ValueError('Non-finite JSON number: ' + value)
        value = json.loads(raw, parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('Invalid JSON: ' + str(path)) from None
    return value, hashlib.sha256(raw).hexdigest()


def load_reports(paths):
    if not 1 <= len(paths) <= 8:
        raise ValueError('Choose 1–8 reports')
    results = []
    fields = {'recon.wifi': 'access_points', 'recon.espwifi': 'records', 'recon.ble': 'records',
              'recon.nrf': 'records', 'recon.services': 'services', 'recon.cameras': 'devices',
              'recon.network': 'neighbours', 'recon.hardware': 'interfaces', 'inspect.wifi': 'packets'}
    total = 0
    for path in paths:
        payload, digest = load_json(path)
        if not isinstance(payload, dict) or payload.get('plugin') not in fields or not isinstance(payload.get('data'), dict):
            raise ValueError('Unsupported discovery report: ' + str(path))
        rows = payload['data'].get(fields[payload['plugin']])
        if rows is None and (payload['plugin'] == 'recon.network' or payload.get('status') in ('ERROR', 'CANCELLED')):
            rows = []
        if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
            raise ValueError('Invalid evidence records: ' + str(path))
        total += len(rows)
        if total > 100000:
            raise ValueError('Reports exceed 100000 records; narrow the input')
        results.append((str(Path(path).expanduser()), payload, digest))
    return results


def provenance(report, source, payload, digest=None):
    stamp = payload.get('observed_at')
    capture_start = None
    if payload.get('plugin') == 'inspect.wifi':
        times = []
        for row in payload.get('data', {}).get('packets', []):
            try:
                value = float(row.get('timestamp'))
                if math.isfinite(value):
                    times.append(datetime.fromtimestamp(value, timezone.utc))
            except (TypeError, ValueError, OverflowError, OSError):
                continue
        if times:
            capture_start = min(times).isoformat()
            stamp = max(times).isoformat()
    age = None
    try:
        observed = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
        if observed.tzinfo is None:
            raise ValueError()
        age = round((datetime.now(timezone.utc) - observed).total_seconds(), 1)
    except (AttributeError, TypeError, ValueError):
        report.warnings.append('Observation time unavailable: ' + source)
    if age is not None and (age < -60 or age > 86400):
        report.warnings.append('Evidence is older than 24 hours or its clock is ahead: ' + source)
    if payload.get('status') not in (None, 'OBSERVED', 'EMPTY'):
        report.warnings.append('Source was incomplete or failed: ' + source)
    warnings = payload.get('warnings') or []
    if not isinstance(warnings, list):
        raise ValueError('Invalid source warnings')
    for warning in warnings:
        if isinstance(warning, str):
            report.warnings.append(source + ': ' + text(warning))
    report.sources.append({'source': source, 'plugin': payload.get('plugin'),
                           'observed_at': stamp, 'capture_start': capture_start, 'analyzed_at': payload.get('analyzed_at'),
                           'age_seconds': age, 'sha256': digest})


def wifi(report, ap, source):
    target = {**endpoint(ap.get('bssid'), protocol='wifi'), 'name': ap.get('ssid'),
              'name_source': 'SSID advertisement', 'name_state': 'known' if ap.get('ssid') else 'hidden', 'channel': ap.get('channel'),
              'signal_dbm': ap.get('signal_dbm'), 'interface': ap.get('interface'), 'service': 'Wi-Fi'}
    sec = ap.get('security')
    if not isinstance(sec, dict) or not isinstance(sec.get('elements', []), list) or any(not isinstance(e, dict) for e in sec.get('elements', [])):
        raise ValueError('Invalid Wi-Fi security evidence')
    findings = wifi_observations(ap)
    for finding in findings:
        report.add('wifi.security', target, finding['title'],
            'medium' if finding['priority'] == 3 else 'info', 'high', finding['evidence'],
            finding['meaning'], finding['verification'], source=source)
    rsn = [e for e in sec.get('elements', []) if e.get('element') == 'RSN']
    for entry in rsn:
        suites = str(entry.get('authentication_suites_raw') or '')
        if re.search(r'\b(?:SAE|OWE)\b', suites) and entry.get('pmf_required') is False:
            report.add('wifi.security', target, 'PMF requirement needs review', 'medium', 'medium',
                ['AKM: ' + suites, 'PMF required bit is clear'],
                'The advertisement includes SAE or OWE without a mandatory PMF bit; transition modes need context.',
                'Check transition mode and negotiated protection on the selected AP.', state='potential', source=source)
    report.check('wifi.security', target, 'observed' if findings else 'completed',
                 'Advertisement analysis only; client negotiation was not tested.', source)


def identify(value):
    value = str(value)
    patterns = ((r'OpenSSH[_/](\d[^\s;]*)', 'openssh'), (r'Apache/(\d[\w.+-]*)', 'apache_http_server'),
                (r'nginx/(\d[\w.+-]*)', 'nginx'), (r'Microsoft-IIS/(\d[\w.+-]*)', 'iis'),
                (r'Python/(\d[\w.+-]*)', 'python'), (r'vsFTPd\s+(\d[\w.+-]*)', 'vsftpd'),
                (r'ProFTPD\s+(\d[\w.+-]*)', 'proftpd'))
    return [{'product': product, 'version': match.group(1)} for pattern, product in patterns
            if (match := re.search(pattern, value, re.I))]


def advisories(path, report=None):
    if path is None:
        return []
    payload, digest = load_json(path)
    if report is not None:
        report.sources.append({'source': str(Path(path).expanduser()), 'kind': 'advisories', 'sha256': digest})
    rows = payload.get('advisories') if isinstance(payload, dict) else None
    if not isinstance(rows, list) or len(rows) > 10000:
        raise ValueError('Advisory file needs an advisories list, at most 10000 entries')
    for row in rows:
        if not isinstance(row, dict) or any(not isinstance(row.get(k), str) or not row[k].strip() for k in ('id', 'product', 'title', 'reference', 'conditions')):
            raise ValueError('Advisory needs id, product, title, reference, conditions and exact versions')
        versions = row.get('versions')
        if not isinstance(versions, list) or not versions or any(not isinstance(v, str) or not v for v in versions):
            raise ValueError('Advisory versions must be a nonempty list of exact strings')
        if row.get('severity', 'medium') not in SEVERITIES:
            raise ValueError('Invalid advisory severity')
        if not re.match(r'https?://[^\s]+$', row['reference']):
            raise ValueError('Advisory reference must be an HTTP or HTTPS URL')
    return rows


def match_advisories(report, target, products, rows, source):
    for product in products:
        for row in rows:
            if row['product'].casefold() == product['product'].casefold() and product['version'] in row['versions']:
                report.add('advisory.match', target, text(row['id']) + ': ' + text(row['title']),
                    row.get('severity', 'medium'), 'low',
                    [product['product'] + ' ' + product['version'], row['reference']],
                    'Exact advertised version match; vendor backports and prerequisites have not been established.',
                    text(row['conditions'], 2048), state='candidate', source=source)


def packets(report, rows, source):
    groups, names = {}, {}
    for row in rows:
        address = str(row.get('bssid') or '').lower()
        if MAC.fullmatch(address) and isinstance(row.get('ssid'), str) and row['ssid']:
            names.setdefault(address, set()).add(row['ssid'])
    for row in rows:
        address = row.get('bssid') or row.get('transmitter')
        if not isinstance(address, str) or not MAC.fullmatch(address):
            continue
        known = sorted(names.get(address.lower(), ()))
        target = {**endpoint(address, protocol='wifi'), 'name': known[0] if len(known) == 1 else None,
                  'observed_names': known, 'name_source': 'Captured SSID', 'service': 'Wi-Fi'}
        protocols = row.get('protocols', [])
        if not isinstance(protocols, list):
            raise ValueError('Invalid decoded protocol list')
        if row.get('protected') is False and row.get('type') in ('Data', 'QoS data') and 'eapol' not in protocols:
            group = groups.setdefault(address.lower(), {'target': target, 'count': 0, 'frames': [], 'protocols': set()})
            group['count'] += 1
            if len(group['frames']) < 8:
                group['frames'].append(row.get('number'))
            group['protocols'].update(p for p in protocols if p in ('http', 'ftp', 'telnet', 'smtp', 'rtsp'))
    for group in groups.values():
        report.add('packet.exposure', group['target'], 'Unprotected Wi-Fi data frames observed', 'info', 'high',
            [str(group['count']) + ' frames; example frame numbers: ' + ', '.join(map(str, group['frames'])),
             'Decoded cleartext protocols: ' + (', '.join(sorted(group['protocols'])) or 'none identified')],
            'These frames have no Wi-Fi Protected bit. Payload sensitivity and network policy remain unverified.',
            'Inspect the relevant frames and determine whether sensitive application data is exposed.', source=source)
    report.check('packet.exposure', None, 'completed', str(len(rows)) + ' decoded frames examined; payloads were not decrypted.', source)


def analyse(report, payload, source, advisory_rows=(), digest=None):
    provenance(report, source, payload, digest)
    plugin, data = payload['plugin'], payload['data']
    if payload.get('status') in ('ERROR', 'CANCELLED'):
        failures = [text(c.get('error') or c.get('status')) for c in payload.get('commands', [])
                    if isinstance(c, dict) and c.get('status') != 'OK' and not c.get('recovered')]
        report.check('source', None, 'failed', 'Source scan failed; no assessment performed. ' + '; '.join(failures), source)
        return
    if payload.get('status') == 'PARTIAL':
        report.check('source', None, 'inconclusive', 'Source scan was incomplete; available evidence is assessed below.', source)
    field = {'recon.wifi': 'access_points', 'recon.espwifi': 'records',
             'recon.ble': 'records', 'inspect.wifi': 'packets'}.get(plugin)
    if field and not data.get(field):
        if plugin == 'recon.ble':
            evidence = 'No BLE advertisements received'
            context = [str(data['duration_seconds']) + 's' if 'duration_seconds' in data else None,
                       data.get('method'), data.get('port')]
        elif plugin == 'inspect.wifi':
            evidence = 'No matching Wi-Fi frames decoded'
            context = [data.get('file')]
        else:
            evidence = 'No matching networks in the Wi-Fi cache' if data.get('method') == 'cached' else 'No matching Wi-Fi networks'
            context = [data.get('method'), data.get('interface') or data.get('port')]
        report.check('coverage', None, 'empty', evidence + ''.join(' · ' + text(v) for v in context if v), source)
        return
    if plugin == 'recon.wifi':
        for ap in data.get('access_points', []):
            wifi(report, ap, source)
    elif plugin == 'recon.espwifi':
        for row in data.get('records', []):
            target = {**endpoint(row.get('address'), protocol='wifi'), 'name': row.get('ssid'),
                      'name_source': 'ESP SSID observation', 'name_state': 'known' if row.get('ssid') else 'hidden', 'channel': row.get('channel'),
                      'signal_dbm': row.get('rssi'), 'service': 'Wi-Fi'}
            label = row.get('security')
            if label in ('Open', 'WEP', 'WPA-PSK', 'WPA/WPA2-PSK'):
                report.add('wifi.security', target, 'ESP reports ' + label + ' security',
                    'info' if label == 'Open' else 'medium', 'medium', ['ESP authentication classification: ' + label],
                    'This is an SDK security classification; detailed security elements were not collected.',
                    'Use the Wi-Fi adapter to inspect the same BSSID and its security elements.', state='potential', source=source)
            report.check('wifi.security', target, 'completed', 'ESP classification only; cipher and PMF details unavailable.', source)
    elif plugin == 'recon.ble':
        for row in data.get('records', []):
            kind = row.get('address_type')
            if kind not in (0, 1, 2, 3):
                raise ValueError('BLE address type missing or invalid')
            target = endpoint(row.get('address'), protocol='ble', address_type=kind)
            adv = row.get('advertisement') or {}
            if not isinstance(adv, dict):
                raise ValueError('Invalid BLE advertisement')
            target.update(name=adv.get('name'), name_source='BLE advertisement',
                          signal_dbm=row.get('rssi'), service='BLE', services=adv.get('service_uuids') or [])
            if adv.get('malformed'):
                report.check('ble.advertisement', target, 'inconclusive', 'Malformed advertising fields; vulnerability inference is unavailable.', source)
            else:
                report.check('ble.advertisement', target, 'completed',
                    'Name: ' + text(adv.get('name') or 'not supplied') + '; services: ' + text(adv.get('service_uuids') or []) + '; manufacturer IDs: ' + text([m.get('company_id') for m in adv.get('manufacturers', []) if isinstance(m, dict)]) + '; identifiers alone do not establish sensitive exposure.', source)
            report.check('ble.gatt', target, 'not_run', 'Connection required; use assess ble with the exact address and type.', source)
    elif plugin == 'recon.services':
        for row in data.get('services', []):
            target = endpoint(row.get('address'), row.get('port'))
            service = row.get('service') or 'unknown'
            target['service'] = service
            products = identify(row.get('evidence') or '')
            report.check('service.identification', target, 'observed',
                'Recorded service: ' + text(service) + '; open-port evidence is not a vulnerability.', source)
            match_advisories(report, target, products, advisory_rows, source)
            evidence = row.get('evidence')
            if service == 'http' and isinstance(evidence, str) and evidence.startswith('HTTP/'):
                from ..adapters.probes import http_analysis
                lines = evidence.splitlines()
                match = re.match(r'HTTP/1\.[01] ([0-9]{3})', lines[0])
                if match:
                    headers = {}
                    for line in lines[1:]:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            headers.setdefault(key.lower(), []).append(value.strip())
                    http_analysis(report, target, {'status': int(match.group(1)), 'headers': headers, 'body': b'', 'body_complete': True, 'body_encoded': False}, False, source)
            report.check('service.follow_up', target, 'not_run', 'Use assess services for live protocol checks; report analysis sends no traffic.', source)
    elif plugin == 'recon.cameras':
        for row in data.get('devices', []):
            target = {**endpoint(row.get('address')), 'service': 'ONVIF', 'urls': row.get('urls') or []}
            report.check('onvif.information', target, 'not_run',
                'Discovery advertisement only; use assess cameras on the responding IP and explicit endpoint path.', source)
    elif plugin == 'inspect.wifi':
        packets(report, data.get('packets', []), source)
    elif plugin in ('recon.nrf', 'recon.hardware', 'recon.network'):
        report.check('coverage', None, 'unsupported',
            {'recon.nrf': 'Power-detector activity has no packet or device identity for vulnerability checks.',
             'recon.hardware': 'Driver capabilities alone cannot establish a device vulnerability.',
             'recon.network': 'Cached neighbours and routes are context only; supply an IP to assess services.'}[plugin], source)
    else:
        raise ValueError('Unsupported report type')
