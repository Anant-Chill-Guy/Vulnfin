from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re

from .findings import MAC, SEVERITIES, endpoint, load_json
from .models import utcnow


IDENTITY_FIELDS = ('protocol', 'address', 'port', 'address_type')


def identity(target):
    return tuple(target.get(k) for k in IDENTITY_FIELDS)


def validated_target(value):
    if not isinstance(value, dict) or value.get('protocol') not in ('wifi', 'ble', 'ip'):
        raise ValueError('Invalid target protocol in report')
    protocol = value['protocol']
    kind = value.get('address_type')
    if protocol == 'ble' and (isinstance(kind, bool) or kind not in (0, 1, 2, 3)):
        raise ValueError('BLE targets need an explicit address type')
    if protocol != 'ble' and kind is not None:
        raise ValueError('Address type is only valid for BLE')
    if protocol != 'ip' and value.get('port') is not None:
        raise ValueError('Radio targets cannot have a TCP port')
    if value.get('transport', 'tcp') != 'tcp':
        raise ValueError('Only TCP service targets are supported')
    canonical = endpoint(value.get('address'), value.get('port'), protocol, kind)
    result = {**value, **canonical}
    for key in ('name', 'service', 'product', 'product_version', 'interface', 'server_name', 'scheme', 'path', 'name_source'):
        if result.get(key) is not None and (not isinstance(result[key], str) or len(result[key]) > 4096):
            raise ValueError('Invalid target field: ' + key)
    for key in ('observed_names', 'services', 'urls'):
        if key in result and (not isinstance(result[key], list) or any(not isinstance(v, str) for v in result[key])):
            raise ValueError('Invalid target field: ' + key)
    return result


def validated_finding(value):
    if not isinstance(value, dict):
        raise ValueError('Invalid finding in report')
    if not isinstance(value.get('id'), str) or not re.fullmatch(r'[a-f0-9]{12}', value['id']):
        raise ValueError('Invalid finding identifier')
    for key in ('check', 'title', 'meaning', 'next_check'):
        if not isinstance(value.get(key), str) or not value[key] or len(value[key]) > 8192:
            raise ValueError('Invalid finding field: ' + key)
    if value.get('severity') not in SEVERITIES or value.get('confidence') not in ('low', 'medium', 'high'):
        raise ValueError('Invalid finding severity or confidence')
    if value.get('state') not in ('observed', 'potential', 'candidate'):
        raise ValueError('Invalid finding state')
    evidence = value.get('evidence')
    if not isinstance(evidence, list) or len(evidence) > 256 or any(not isinstance(v, str) or len(v) > 8192 for v in evidence):
        raise ValueError('Invalid finding evidence')
    return {**value, 'target': validated_target(value.get('target')), 'confirmed_vulnerability': False}


def assessment_map(paths, *, context=()):
    if not 1 <= len(paths) <= 8 or sum(str(p) == '-' for p in paths) > 1:
        raise ValueError('Choose 1–8 assessment reports; standard input can be used once')
    groups, sources, warnings = {}, [], []
    total = 0
    for path in paths:
        payload, digest = load_json(path)
        if not isinstance(payload, dict) or payload.get('schema') != 'vulnfin.assessment.v1' or not isinstance(payload.get('data'), dict):
            raise ValueError('Use an assessment report from assess -o or assess -j: ' + str(path))
        data = payload['data']
        findings, checks, targets = data.get('findings'), data.get('checks'), data.get('targets', [])
        if any(not isinstance(rows, list) for rows in (findings, checks, targets)):
            raise ValueError('Invalid assessment records')
        total += len(findings) + len(checks) + len(targets)
        if total > 100000:
            raise ValueError('Assessment reports exceed 100000 records')
        provenance = data.get('sources') or []
        if not isinstance(provenance, list) or any(not isinstance(v, dict) for v in provenance):
            raise ValueError('Invalid assessment sources')
        source = {'file': str(Path(path).expanduser()), 'sha256': digest, 'assessed_at': payload.get('assessed_at'),
                  'status': payload.get('status'), 'observations': provenance}
        sources.append(source)
        file_groups = set()
        def collect(raw):
            target = validated_target(raw)
            key = identity(target)
            if len(groups) >= 10000 and key not in groups:
                raise ValueError('More than 10000 endpoints; narrow the reports')
            group = groups.setdefault(key, {'target': {k: target[k] for k in IDENTITY_FIELDS if k in target},
                'names': [], 'resources': [], 'findings': [], 'observations': [], 'warnings': []})
            names = [target.get('name'), *(target.get('observed_names') or [])]
            for name in names:
                if name and name not in group['names']:
                    group['names'].append(name)
            resource = {k: v for k, v in target.items() if not k.startswith('_')}
            if resource not in group['resources']:
                group['resources'].append(resource)
            if key not in file_groups:
                group['observations'].append(source)
                file_groups.add(key)
            return group
        for target in targets:
            collect(target)
        for check in checks:
            if not isinstance(check, dict):
                raise ValueError('Invalid check record')
            if check.get('target'):
                collect(check['target'])
        seen = set()
        for raw in findings:
            finding = validated_finding(raw)
            group = collect(finding['target'])
            stamp = json.dumps(finding, sort_keys=True, ensure_ascii=True)
            if stamp not in seen:
                existing = next((f for f in group['findings'] if f['id'] == finding['id']), None)
                if existing is not None and existing != finding:
                    raise ValueError('Conflicting finding ID across reports: ' + finding['id'])
                if existing is None:
                    group['findings'].append(finding)
                seen.add(stamp)
        if payload.get('status') in ('PARTIAL', 'ERROR', 'UNAVAILABLE'):
            warnings.append('Assessment was incomplete or unavailable: ' + str(path))
        messages = payload.get('warnings') or []
        if not isinstance(messages, list) or any(not isinstance(v, str) for v in messages):
            raise ValueError('Invalid assessment warnings')
        warnings.extend(messages)
    for group in groups.values():
        target = group['target']
        if len(group['names']) == 1:
            target['name'] = group['names'][0]
        elif len(group['names']) > 1:
            target['observed_names'] = group['names']
            group['warnings'].append('This address has multiple observed names; physical identity is not established.')
        for key in ('service', 'product', 'product_version', 'name_source', 'name_state', 'signal_dbm', 'channel', 'interface'):
            values = [r[key] for r in group['resources'] if r.get(key) is not None]
            if values:
                target[key] = values[-1]
        group['findings'].sort(key=lambda f: (SEVERITIES[f['severity']], f['title'], f['id']))
        group['highest_severity'] = min((f['severity'] for f in group['findings']), key=SEVERITIES.get, default=None)
        group['verified_device_identity'] = False
    links = []
    if context:
        if any(str(p) == '-' for p in context):
            raise ValueError('Context reports must be files, not standard input')
        from ..adapters.correlation import correlate
        links = correlate(context)['address_matches']
        known = {g['target']['address'] for g in groups.values()}
        links = [link for link in links if link['wifi'] in known or link['ip'] in known]
    rows = sorted(groups.values(), key=lambda g: (g['target']['protocol'], g['target']['address'], g['target'].get('port', 0), g['target'].get('address_type', -1)))
    return {'schema': 'vulnfin.targets.v1', 'mapped_at': utcnow(), 'targets': rows, 'sources': sources,
            'address_matches': links, 'warnings': list(dict.fromkeys(warnings)),
            'scope': 'Endpoints and their evidence; shared names and address matches do not prove physical device identity.'}


def select_target(mapped, address, *, protocol=None, port=None, address_type=None, findings=()):
    if MAC.fullmatch(address):
        address = address.lower()
    else:
        address = endpoint(address)['address']
    matches = [g for g in mapped['targets'] if g['target']['address'] == address
               and (protocol is None or g['target']['protocol'] == protocol)
               and (port is None or g['target'].get('port') == port)
               and (address_type is None or g['target'].get('address_type') == address_type)]
    if not matches:
        raise ValueError('No matching endpoint in the supplied assessment')
    if len(matches) != 1:
        raise ValueError('Address matches several endpoints; specify --protocol, -p or --type')
    group = matches[0]
    selected = group['findings']
    if findings:
        unknown = set(findings) - {f['id'] for f in selected}
        if unknown:
            raise ValueError('Finding does not belong to this endpoint: ' + ', '.join(sorted(unknown)))
        selected = [f for f in selected if f['id'] in findings]
    return {'schema': 'vulnfin.target.v1', 'selected_at': utcnow(), 'target': group['target'],
            'names': group['names'], 'resources': group['resources'], 'findings': selected,
            'observations': group['observations'], 'warnings': [*mapped['warnings'], *group['warnings']],
            'address_matches': [link for link in mapped['address_matches'] if address in (link['ip'], link['wifi'])],
            'verified_device_identity': False}


def read_selection(path):
    payload, digest = load_json(path)
    if not isinstance(payload, dict) or payload.get('schema') != 'vulnfin.target.v1':
        raise ValueError('Use a target selection from target select -o or target select -j')
    target = validated_target(payload.get('target'))
    rows = payload.get('findings')
    resources = payload.get('resources', [])
    if not isinstance(rows, list) or len(rows) > 256 or not isinstance(resources, list) or len(resources) > 2048:
        raise ValueError('Selection exceeds 256 findings or 2048 resource records; narrow the selection')
    findings = [validated_finding(f) for f in rows]
    resources = [validated_target(r) for r in resources]
    if any(identity(f['target']) != identity(target) for f in findings) or any(identity(r) != identity(target) for r in resources):
        raise ValueError('Selection contains evidence for another endpoint')
    if len({f['id'] for f in findings}) != len(findings):
        raise ValueError('Selection contains duplicate finding IDs')
    for key in ('observations', 'warnings', 'names', 'address_matches'):
        if not isinstance(payload.get(key, []), list):
            raise ValueError('Invalid selection field: ' + key)
    if any(not isinstance(v, dict) for v in payload.get('observations', []) + payload.get('address_matches', [])):
        raise ValueError('Invalid selection observations or address links')
    if any(not isinstance(v, str) for v in payload.get('warnings', []) + payload.get('names', [])):
        raise ValueError('Invalid selection names or warnings')
    return {**payload, 'target': target, 'findings': findings, 'resources': resources, 'selection_sha256': digest,
            'verified_device_identity': False}


def observation_age(selection):
    times = []
    for observation in selection.get('observations', []):
        if not isinstance(observation, dict):
            continue
        sources = observation.get('observations') or []
        if not isinstance(sources, list):
            continue
        for source in sources:
            if not isinstance(source, dict):
                continue
            try:
                value = datetime.fromisoformat(source['observed_at'].replace('Z', '+00:00'))
                if value.tzinfo:
                    times.append(value)
            except (KeyError, TypeError, ValueError, AttributeError):
                continue
    return round((datetime.now(timezone.utc) - min(times)).total_seconds(), 1) if times else None
