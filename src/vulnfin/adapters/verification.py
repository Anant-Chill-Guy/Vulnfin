from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
import re
import uuid

from .probes import PROTOCOLS, assess_endpoint, http_request, onvif_probe, request_path, server_name
from ..core.findings import Assessment, analyse, text
from ..core.models import utcnow
from ..core.runtime import execute
from ..core.targets import identity, observation_age


NMAP_CHECKS = {'smb.signing', 'rdp.encryption', 'vnc.authentication', 'ssh.algorithms'}
REVIEW_TITLES = {'Diagnostic output needs review', 'PMF requirement needs review'}
KNOWN_TITLES = {
    'wifi.security': {'Legacy WPA advertised', 'Legacy cipher advertised', 'No link encryption advertised',
        'PMF requirement needs review', 'ESP reports Open security', 'ESP reports WEP security',
        'ESP reports WPA-PSK security', 'ESP reports WPA/WPA2-PSK security'},
    'http.configuration': {'Basic authentication offered over HTTP', 'Credentialed CORS accepts the probe origin',
        'Browser security headers need review'},
    'http.exposure': {'Directory listing returned', 'Git HEAD metadata is publicly readable', 'Diagnostic output needs review'},
    'tls.configuration': {'TLS certificate validation failed', 'TLS 1.0 accepted', 'TLS 1.1 accepted'},
    'ssh.protocol': {'SSH 1 compatibility advertised'},
    'ftp.transport': {'TLS upgrade not advertised'},
    'smtp.transport': {'TLS upgrade not advertised', 'Password authentication advertised before TLS'},
    'redis.access': {'Redis PING accepted without supplied credentials'},
    'mqtt.access': {'MQTT connection accepted without supplied credentials'},
    'onvif.information': {'ONVIF device information returned without supplied credentials'},
    'ble.gatt': {'Selected characteristic read succeeded'},
    'packet.exposure': {'Unprotected Wi-Fi data frames observed'},
    'smb.signing': {'SMB signing is not required'},
    'rdp.encryption': {'Legacy RDP encryption accepted'},
    'vnc.authentication': {'VNC advertises None authentication'},
    'ssh.algorithms': {'Legacy SSH algorithms advertised'},
}


def supported(finding):
    return finding['title'] in KNOWN_TITLES.get(finding['check'], ()) or (
        finding['check'] == 'http.configuration' and finding['title'].startswith('Cookie protection needs review: '))


def resource(target):
    scheme = target.get('scheme')
    if scheme not in (None, 'http', 'https'):
        raise ValueError('Unsupported scheme in selected resource')
    return scheme, server_name(target.get('server_name')), request_path(target.get('path') or '/')


def same_resource(check, expected, actual, *, git_base=False):
    if identity(expected) != identity(actual):
        return False
    if check == 'tls.configuration' or check.startswith('http.') or check == 'onvif.information':
        expected_name = (expected.get('server_name') or '').rstrip('.').casefold()
        actual_name = (actual.get('server_name') or '').rstrip('.').casefold()
        if expected_name != actual_name:
            return False
    if check.startswith('http.') or check == 'onvif.information':
        path = expected.get('path') or '/'
        if git_base and path.endswith('/.git/HEAD'):
            path = path[:-len('.git/HEAD')]
        if path != (actual.get('path') or '/') or (expected.get('scheme') or 'http') != (actual.get('scheme') or 'http'):
            return False
    return True


def related_checks(finding, fresh):
    check, title = finding['check'], finding['title']
    target = finding['target']
    rows = [c for c in fresh.checks if c.get('target') and same_resource(check, target, c['target'], git_base='Git HEAD' in title)]
    if check.startswith('http.'):
        return [c for c in rows if c['check'] == ('http.git' if 'Git HEAD' in title else 'http.response')]
    if check == 'tls.configuration':
        return [c for c in rows if c['check'] == ('tls.certificate' if 'certificate' in title else 'tls.legacy')
                and (not title.startswith(('TLS 1.0', 'TLS 1.1')) or c['evidence'].startswith(title.split(' accepted')[0]))]
    aliases = {'wifi.security': 'wifi.security', 'ssh.protocol': 'ssh.protocol', 'ftp.transport': 'ftp.transport',
               'smtp.transport': 'smtp.transport', 'redis.access': 'redis.access', 'mqtt.access': 'mqtt.access',
               'onvif.information': 'onvif.information', 'ble.gatt': 'ble.gatt.read', 'packet.exposure': 'packet.exposure'}
    if check in NMAP_CHECKS:
        name = {'smb.signing': 'smb2-security-mode', 'rdp.encryption': 'rdp-enum-encryption',
                'vnc.authentication': 'vnc-info', 'ssh.algorithms': 'ssh2-enum-algos'}[check]
        return [c for c in rows if c['check'] == 'nmap.' + name]
    matched = [c for c in rows if c['check'] == aliases.get(check, check)]
    if check == 'ble.gatt':
        uuids = [v[6:] for v in finding['evidence'] if v.startswith('UUID: ')]
        matched = [c for c in matched if any(c['evidence'].startswith(value + ':') for value in uuids)]
    return matched or ([c for c in rows if c['check'] == 'ble.gatt'] if check == 'ble.gatt' else [])


def same_condition(original, candidate):
    aliases = {'ESP reports Open security': 'No link encryption advertised',
               'ESP reports WPA-PSK security': 'Legacy WPA advertised',
               'ESP reports WPA/WPA2-PSK security': 'Legacy WPA advertised'}
    if original['check'] != candidate['check'] or aliases.get(original['title'], original['title']) != candidate['title']:
        return False
    if not same_resource(original['check'], original['target'], candidate['target']):
        return False
    if original['check'] == 'ble.gatt':
        return any(v.startswith('UUID: ') and v in candidate['evidence'] for v in original['evidence'])
    return True


async def web_control(finding, timeout):
    target = finding['target']
    scheme, name, path = resource(target)
    host, port = target['address'], target['port']
    kwargs = {'secure': scheme == 'https', 'name': name}
    async def get(value, **options):
        return await asyncio.wait_for(http_request(host, port, timeout, path=value, **kwargs, **options), timeout * 2)
    if finding['title'] == 'Git HEAD metadata is publicly readable':
        if not path.endswith('/.git/HEAD'):
            return 'needs_review', ['The original finding has no exact Git HEAD path; reassess this endpoint first.']
        actual = await get(path)
        parent = path.rsplit('/', 1)[0]
        control = await get(parent + '/vf-' + uuid.uuid4().hex)
        pattern = rb'(?:ref: refs/[A-Za-z0-9_./-]+|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})'
        signature = actual['status'] == 200 and actual['body_complete'] and re.fullmatch(pattern, actual['body'].strip())
        if not signature:
            return ('not_observed' if actual['body_complete'] and not actual['body_encoded'] else 'inconclusive'), ['The selected path did not return a complete Git HEAD signature.']
        if not control['body_complete'] or control['body_encoded']:
            return 'inconclusive', ['The control response was incomplete or encoded; wildcard behaviour could not be ruled out.']
        if control['status'] == 200 and control['body'].strip() == actual['body'].strip():
            return 'inconclusive', ['The random control path returned the same content; a wildcard response may explain the result.']
        return 'reproduced', ['Selected path returned a Git HEAD signature.', 'Random control path did not return the same successful response.']
    if finding['title'] == 'Credentialed CORS accepts the probe origin':
        evidence = []
        accepted = 0
        for _ in range(2):
            origin = 'https://vf-' + uuid.uuid4().hex + '.invalid'
            response = await get(path, origin=origin)
            headers = response['headers']
            allowed = headers.get('access-control-allow-origin') == [origin] and [v.lower() for v in headers.get('access-control-allow-credentials', [])] == ['true']
            accepted += int(allowed)
            evidence.append('Distinct probe origin ' + ('accepted with credentials' if allowed else 'not accepted with credentials') + '; HTTP ' + str(response['status']))
        return ('reproduced' if accepted == 2 else 'inconclusive' if accepted else 'not_observed'), evidence
    return None


async def verify_selection(selection, *, interface=None, serial_port='auto', adapter='hci0', timeout=3,
                           scan_timeout=45, duration=10, capture=None, verbose=False):
    if not 0.2 <= timeout <= 10 or not 5 <= scan_timeout <= 120 or not 1 <= duration <= 60:
        raise ValueError('Timeout must be 0.2–10s; scan timeout 5–120s; BLE duration 1–60s')
    target = selection['target']
    findings = selection['findings']
    if len(findings) > 64:
        raise ValueError('Choose at most 64 findings for one verification; narrow with --finding')
    if target['protocol'] == 'ip' and target.get('port') is None:
        raise ValueError('Select an assessed endpoint with an exact TCP port first')
    for candidate in [*selection.get('resources', []), *(f['target'] for f in findings)]:
        resource(candidate)
    fresh = Assessment()
    results, controls, warnings = [], {}, list(selection.get('warnings', []))
    age = observation_age(selection)
    if age is None:
        warnings.append('The original observation time is unavailable; verification collects fresh evidence where supported.')
    elif age > 900 or age < -60:
        warnings.append('The selection includes old or clock-skewed evidence; only the new checks establish current conditions.')
    target_status, interrupted, historical = 'inconclusive', False, False
    def progress(message):
        if verbose:
            from ..cli.presentation import safe
            from rich.console import Console
            Console(stderr=True, highlight=False).print(safe(message), markup=False)
    try:
        if target['protocol'] == 'wifi':
            packet_findings = [f for f in findings if f['check'] == 'packet.exposure']
            packet_only = bool(findings) and len(packet_findings) == len(findings)
            if not packet_only:
                from ..plugins import discover
                plugin = next(p for p in discover() if p.manifest.id == 'recon.wifi')
                chosen = interface or target.get('interface')
                progress('Refreshing Wi-Fi observations for ' + target['address'])
                payload = (await execute(plugin, {'interface': chosen, 'cached': False, 'active': True,
                    'passive': False, 'timeout': scan_timeout}, verbose=verbose)).to_dict()
                rows = [r for r in payload['data'].get('access_points', []) if r.get('bssid', '').lower() == target['address']]
                payload['data']['access_points'] = rows
                analyse(fresh, payload, 'verification:wifi')
                target_status = 'observed' if rows and payload['status'] == 'OBSERVED' else 'not_seen' if payload['status'] in ('OBSERVED', 'EMPTY') else 'inconclusive'
                expected = selection.get('names') or []
                if rows and expected and rows[0].get('ssid') and rows[0]['ssid'] not in expected:
                    target_status = 'changed'
                    warnings.append('The selected BSSID now advertises a different name; review its identity before proceeding.')
            if packet_findings:
                if capture is None:
                    warnings.append('Supply --capture to recheck packet evidence; a capture cannot establish current radio reachability.')
                else:
                    try:
                        from .packets import inspect_wifi
                        path = Path(capture).expanduser()
                        with path.open('rb') as stream:
                            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                        payload = await inspect_wifi(path)
                        with path.open('rb') as stream:
                            if hashlib.file_digest(stream, 'sha256').hexdigest() != digest:
                                raise ValueError('Capture changed during verification; stop the writer and retry')
                        payload['data']['packets'] = [r for r in payload['data']['packets'] if str(r.get('bssid') or '').lower() == target['address']]
                        analyse(fresh, payload, str(path), digest=digest)
                        historical = True
                        if packet_only:
                            target_status = 'historical'
                    except (ValueError, OSError) as error:
                        evidence = [text(error) or 'Capture verification failed']
                        for finding in packet_findings:
                            controls[finding['id']] = ('inconclusive', evidence)
                        fresh.check('packet.exposure', target, 'inconclusive', evidence[0])
        elif target['protocol'] == 'ble':
            gatt_findings = [f for f in findings if f['check'] == 'ble.gatt']
            if gatt_findings:
                if target.get('address_type') not in (0, 1):
                    warnings.append('Linux GATT checks require a public or random address, rather than an unresolved identity-address type.')
                else:
                    from .gatt import assess_gatt, characteristic_uuid
                    reads = []
                    for finding in gatt_findings:
                        values = [v[6:] for v in finding['evidence'] if v.startswith('UUID: ')]
                        if len(values) != 1:
                            raise ValueError('Selected BLE read finding has no unique characteristic UUID')
                        reads.append(characteristic_uuid(values[0]))
                    progress('Rechecking selected BLE reads on ' + target['address'])
                    await assess_gatt(fresh, target['address'], 'public' if target['address_type'] == 0 else 'random', adapter, max(10, duration + 10), reads)
                    target_status = 'observed' if any(c['outcome'] in ('observed', 'completed') for c in fresh.checks) else 'inconclusive'
            else:
                from ..plugins import discover
                plugin = next(p for p in discover() if p.manifest.id == 'recon.ble')
                progress('Refreshing BLE advertisements for ' + target['address'])
                payload = (await execute(plugin, {'port': serial_port, 'duration': duration, 'active': True}, verbose=verbose)).to_dict()
                rows = [r for r in payload['data'].get('records', []) if r.get('address', '').lower() == target['address'] and r.get('address_type') == target.get('address_type')]
                payload['data']['records'] = rows
                analyse(fresh, payload, 'verification:ble')
                target_status = 'observed' if rows and payload['status'] == 'OBSERVED' else 'not_seen' if payload['status'] in ('OBSERVED', 'EMPTY') else 'inconclusive'
        else:
            jobs = set()
            for finding in findings:
                check, title = finding['check'], finding['title']
                if check == 'advisory.match' or not supported(finding):
                    continue
                scheme, name, path = resource(finding['target'])
                if check in NMAP_CHECKS:
                    jobs.add(('nmap', None, '/'))
                elif check == 'onvif.information':
                    jobs.add(('onvif-https' if scheme == 'https' else 'onvif', name, path))
                elif check.startswith('http.'):
                    if title == 'Git HEAD metadata is publicly readable' and path.endswith('/.git/HEAD'):
                        path = path[:-len('.git/HEAD')]
                    jobs.add(('https' if scheme == 'https' else 'http', name, path))
                elif check == 'tls.configuration':
                    jobs.add(('tls', name, '/'))
                elif check.split('.')[0] in PROTOCOLS:
                    jobs.add((check.split('.')[0], name, '/'))
            if not findings:
                for row in selection.get('resources') or [target]:
                    service = str(row.get('service') or '').lower()
                    _, name, path = resource(row)
                    if service in PROTOCOLS[1:]:
                        jobs.add((service, name, path))
                if not jobs:
                    jobs.add(('auto', None, '/'))
            if len(jobs) > 16:
                raise ValueError('More than 16 resource checks; narrow the selected findings')
            for protocol, name, path in sorted(jobs, key=lambda v: (v[0], v[1] or '', v[2])):
                progress('Checking ' + target['address'] + ':' + str(target['port']) + ' · ' + protocol)
                if protocol == 'nmap':
                    from .service_checks import nmap_probe
                    await nmap_probe(fresh, target['address'], target['port'])
                elif protocol.startswith('onvif'):
                    await onvif_probe(fresh, target['address'], target['port'], timeout,
                        secure=protocol == 'onvif-https', name=name, path=path)
                else:
                    await assess_endpoint(fresh, target['address'], target['port'], timeout, protocol=protocol, name=name, path=path)
            for finding in findings:
                if not supported(finding) or finding['title'] not in ('Git HEAD metadata is publicly readable', 'Credentialed CORS accepts the probe origin'):
                    continue
                try:
                    controls[finding['id']] = await web_control(finding, timeout)
                except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError) as error:
                    controls[finding['id']] = ('inconclusive', [text(error) or 'Control request timed out'])
            if any(c['outcome'] in ('observed', 'completed') for c in fresh.checks):
                target_status = 'observed'
            elif fresh.checks and all(c['outcome'] == 'closed' for c in fresh.checks):
                target_status = 'unreachable'
    except asyncio.CancelledError:
        interrupted = True
        warnings.append('Verification interrupted; completed evidence is retained.')
    except (ValueError, OSError) as error:
        fresh.check('verification', target, 'failed', text(error) or 'Verification failed')
    for finding in findings:
        outcome, evidence = 'inconclusive', []
        matching = [f for f in fresh.findings if same_condition(finding, f)]
        relevant = related_checks(finding, fresh)
        if interrupted:
            evidence = ['Verification was interrupted; rerun this finding.']
        elif finding['check'] == 'advisory.match':
            outcome, evidence = 'needs_review', ['A version match cannot establish advisory applicability.', finding['next_check']]
        elif not supported(finding):
            outcome, evidence = 'unsupported', ['No automatic verifier is registered for this finding.']
        elif historical and finding['check'] == 'packet.exposure':
            outcome, evidence = 'historical', ['Condition found in the supplied capture.' if matching else 'Condition not found in the supplied capture.', 'This is historical packet evidence, not current target reachability.']
        elif finding['id'] in controls:
            outcome, evidence = controls[finding['id']]
        elif target_status in ('changed', 'not_seen', 'unreachable'):
            evidence = ['The target identity changed or the selected endpoint was not observed; absence of the weakness is not established.']
        elif any(c['check'] == 'source' and c['outcome'] in ('failed', 'inconclusive') for c in fresh.checks):
            evidence = ['The source scan was incomplete or failed; this condition could not be verified reliably.']
        elif finding['title'] in REVIEW_TITLES or finding['title'] == 'ESP reports WEP security' or finding['check'] == 'packet.exposure':
            outcome, evidence = 'needs_review', ['This finding needs contextual or packet-level review.', finding['next_check']]
        elif matching:
            outcome = 'reproduced'
            evidence = list(dict.fromkeys(v for f in matching for v in f['evidence']))
            if finding['check'] in ('ssh.algorithms', 'rdp.encryption') and not set(finding['evidence']).issubset(set(evidence)):
                outcome = 'needs_review'
                evidence.append('The advertised options changed; review the fresh evidence against the original finding.')
            if finding['title'] == 'Legacy cipher advertised' and finding['evidence'] != matching[0]['evidence']:
                outcome = 'needs_review'
                evidence.append('Cipher advertisement changed; review the fresh evidence.')
        elif relevant and all(c['outcome'] in ('completed', 'observed') for c in relevant):
            body_problem = finding['check'].startswith('http.') and any(c['check'] == 'http.body' and c['outcome'] == 'inconclusive' and c.get('target') and same_resource(finding['check'], finding['target'], c['target'], git_base='Git HEAD' in finding['title']) for c in fresh.checks)
            outcome = 'inconclusive' if body_problem else 'not_observed'
            evidence = ['The condition was not seen in the completed checks; this does not prove the endpoint is free of other vulnerabilities.']
        else:
            evidence = [c['evidence'] for c in relevant if c['outcome'] in ('failed', 'inconclusive', 'unsupported', 'not_run')]
            if not evidence:
                evidence = ['No supported check established this finding’s current condition.']
        results.append({'finding_id': finding['id'], 'check': finding['check'], 'title': finding['title'],
            'target': finding['target'], 'outcome': outcome, 'evidence': evidence,
            'condition_verified': outcome == 'reproduced', 'confirmed_vulnerability': False,
            'remaining_requirement': finding['next_check']})
    complete = not interrupted and target_status == 'observed' and all(r['outcome'] in ('reproduced', 'not_observed') for r in results)
    if not findings and any(c['outcome'] in ('failed', 'inconclusive', 'unsupported') for c in fresh.checks):
        complete = False
    return {'schema': 'vulnfin.verification.v1', 'verified_at': utcnow(),
        'status': 'INTERRUPTED' if interrupted else 'COMPLETE' if complete else 'PARTIAL',
        'target': target, 'target_status': target_status, 'original_age_seconds': age,
        'selection_sha256': selection.get('selection_sha256'), 'results': results,
        'fresh_assessment': fresh.result(), 'warnings': list(dict.fromkeys(warnings)),
        'verified_device_identity': False,
        'preparation': {'target': target, 'verified_conditions': [r for r in results if r['condition_verified']],
                        'remaining_requirements': [r['remaining_requirement'] for r in results if r['outcome'] != 'not_observed']}}
