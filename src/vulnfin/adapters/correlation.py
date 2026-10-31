from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import re


MAC = re.compile(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}')


def correlate(paths):
    if not 1 <= len(paths) <= 8:
        raise ValueError('Choose 1–8 JSON reports')
    groups, neighbours = {}, []
    for value in paths:
        path = Path(value).expanduser()
        if path.stat().st_size > 32 * 1024 * 1024:
            raise ValueError('Report exceeds 32 MiB: ' + str(path))
        payload = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(payload, dict) or not isinstance(payload.get('data'), dict):
            raise ValueError('Not a discovery report: ' + str(path))
        data, plugin = payload['data'], payload.get('plugin')
        field = {'recon.wifi': 'access_points', 'recon.espwifi': 'records', 'recon.ble': 'records',
                 'recon.network': 'neighbours', 'recon.services': 'services', 'recon.cameras': 'devices'}.get(plugin)
        if field is None or data.get(field) is not None and not isinstance(data[field], list):
            raise ValueError('Unsupported report: ' + str(path))
        for record in data.get(field) or []:
            if not isinstance(record, dict):
                raise ValueError('Invalid report record: ' + str(path))
            address = record.get('bssid') if plugin == 'recon.wifi' else record.get('dst') if plugin == 'recon.network' else record.get('address')
            if not isinstance(address, str):
                continue
            if plugin in ('recon.wifi', 'recon.espwifi', 'recon.ble'):
                if not MAC.fullmatch(address):
                    continue
                protocol = 'ble' if plugin == 'recon.ble' else 'wifi'
                identity = address.lower()
                if protocol == 'ble':
                    identity += ':' + str(record.get('address_type', 'unknown'))
            else:
                try:
                    identity = str(ipaddress.ip_address(address))
                except ValueError:
                    continue
                protocol = 'ip'
                mac = str(record.get('lladdr', '')).lower()
                if MAC.fullmatch(mac):
                    neighbours.append((identity, mac))
            group = groups.setdefault((protocol, identity), {'protocol': protocol, 'identity': identity, 'sources': [], 'observations': []})
            if plugin not in group['sources']:
                group['sources'].append(plugin)
            group['observations'].append({'file': str(path), 'observed_at': record.get('observed_at', payload.get('observed_at')),
                                           'interface': record.get('interface') or record.get('dev'),
                                           'signal_dbm': record.get('signal_dbm', record.get('rssi')),
                                           'port': record.get('port')})
    links = [{'wifi': mac, 'ip': address, 'basis': 'same MAC in Wi-Fi and neighbour-cache reports', 'verified_device_identity': False}
             for address, mac in sorted(set(neighbours)) if ('wifi', mac) in groups]
    return {'records': list(groups.values()), 'address_matches': links,
            'note': 'Address matches across saved observations; shared SSIDs and randomized BLE addresses do not establish physical identity.'}
