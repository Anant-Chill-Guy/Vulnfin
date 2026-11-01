from __future__ import annotations

import asyncio
from importlib.metadata import version
import re
import uuid

from .resources import Resource
from ..core.findings import endpoint, text


def characteristic_uuid(value):
    try:
        if re.fullmatch(r'[0-9a-fA-F]{4}', value):
            value = '0000' + value + '-0000-1000-8000-00805f9b34fb'
        return str(uuid.UUID(value))
    except ValueError:
        raise ValueError('Use a 16-bit or full characteristic UUID') from None


async def assess_gatt(report, address, address_type, adapter, timeout, reads):
    target = endpoint(address, protocol='ble', address_type=0 if address_type == 'public' else 1)
    target['service'] = 'BLE'
    if not re.fullmatch(r'hci[0-9]+', adapter):
        raise ValueError('Use a Bluetooth adapter such as hci0')
    reads = list(dict.fromkeys(characteristic_uuid(v) for v in reads))
    if len(reads) > 16:
        raise ValueError('Choose at most 16 characteristic UUIDs')
    try:
        from bleak import BleakClient, BleakScanner
        if int(version('bleak').split('.')[0]) != 3:
            raise ValueError('BLE GATT checks need Bleak 3.x from the system package manager')
    except ImportError:
        raise ValueError('BLE GATT support missing. Install python-bleak with the system package manager') from None
    source = 'live:ble:' + adapter + ':' + address.lower()
    with Resource('bluetooth:' + adapter):
        try:
            async with asyncio.timeout(timeout):
                device = await BleakScanner.find_device_by_address(address, timeout=min(timeout, 10), bluez={'adapter': adapter})
                if device is None:
                    report.check('ble.gatt', target, 'inconclusive', 'Target was not observed during the Bluetooth scan.', source)
                    return
                props = device.details.get('props', {}) if isinstance(device.details, dict) else {}
                target.update(name=props.get('Name'), name_source='BlueZ name; may be cached', signal_dbm=props.get('RSSI'))
                if props.get('AddressType') != address_type:
                    report.check('ble.gatt', target, 'inconclusive', 'Observed address type is missing or differs from the requested type.', source)
                    return
                if props.get('Connected'):
                    report.check('ble.gatt', target, 'not_run', 'Target already has an OS connection; disconnect it explicitly before assessing.', source)
                    return
                paired = props.get('Paired')
                if paired is not False:
                    report.check('ble.gatt', target, 'not_run', 'An unpaired baseline is unavailable; existing bonds are left unchanged.', source)
                    return
                async with BleakClient(device, pair=False, timeout=timeout) as client:
                    matches = {}
                    count = 0
                    for service in client.services:
                        for char in service.characteristics:
                            count += 1
                            if count > 2048:
                                raise ValueError('GATT characteristic count exceeds 2048')
                            properties = sorted(char.properties)
                            matches.setdefault(char.uuid.lower(), []).append(char)
                            report.check('ble.gatt.characteristic', target, 'observed',
                                'Service ' + service.uuid + '; characteristic ' + char.uuid + '; handle ' + str(char.handle) + '; properties ' + ', '.join(properties), source)
                    report.check('ble.gatt', target, 'completed', str(count) + ' characteristics enumerated; advertised properties do not establish effective permissions.', source)
                    for identity in reads:
                        found = matches.get(identity, [])
                        if len(found) != 1:
                            report.check('ble.gatt.read', target, 'not_run', identity + ': absent or ambiguous UUID; no read attempted.', source)
                            continue
                        char = found[0]
                        if 'read' not in char.properties:
                            report.check('ble.gatt.read', target, 'not_run', identity + ': read property not advertised.', source)
                            continue
                        try:
                            async with asyncio.timeout(min(10, timeout)):
                                value = await client.read_gatt_char(char)
                            report.add('ble.gatt', target, 'Selected characteristic read succeeded', 'info', 'high',
                                ['UUID: ' + identity, str(len(value)) + ' bytes returned; value omitted', 'OS reported no existing pairing before connection'],
                                'This read succeeded without supplied credentials or requested pairing. Link encryption, application authorization and data sensitivity are not established.',
                                'Check the characteristic purpose and intended read policy; use protocol-specific verification for sensitive data.', state='potential', source=source)
                            report.check('ble.gatt.read', target, 'observed', identity + ': read succeeded; value omitted.', source)
                        except Exception as error:
                            report.check('ble.gatt.read', target, 'inconclusive', identity + ': ' + text(error), source)
        except Exception as error:
            report.check('ble.gatt', target, 'inconclusive', text(error) or 'Bluetooth operation timed out', source)
