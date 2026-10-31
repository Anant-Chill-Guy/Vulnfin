from __future__ import annotations

from ..adapters.agent import Agent, advertisement
from ..core.models import Manifest


class EmbeddedDiscovery:
    def prepare(self, params, config):
        params['port'] = params.get('port') or 'auto'
        if self.manifest.id == 'recon.nrf':
            params['samples'] = int(params.get('samples', 64))
            if not 1 <= params['samples'] <= 512:
                raise ValueError('Samples must be 1–512')
        else:
            params['duration'] = int(params.get('duration', 10))
            if not 1 <= params['duration'] <= 300:
                raise ValueError('Duration must be 1–300 seconds')
        return params

    async def run(self, ctx, params):
        kind = self.manifest.protocol
        records, stats = {}, {}
        async with Agent(params['port']) as device:
            if not device.hello.get('capabilities', {}).get(kind):
                raise ValueError(kind.upper() + ' unavailable on this device')
            args = (params['samples'],) if kind == 'nrf' else (params['duration'], int(bool(params.get('active'))))
            async for event in device.command(kind.upper(), *args, timeout=(params['samples'] * 0.5 + 15 if kind == 'nrf' else params['duration'] + 15)):
                if event['type'] == 'done':
                    stats = {k: v for k, v in event.items() if k not in ('id', 'type')}
                elif event['type'] == kind:
                    key = event['channel'] if kind == 'nrf' else (event['address'], event.get('address_type')) if kind == 'ble' else event['address']
                    if len(records) >= 2048 and key not in records:
                        raise ValueError('Too many device records; use a shorter scan')
                    record = {k: v for k, v in event.items() if k not in ('id', 'type')}
                    if kind == 'ble':
                        record['advertisement'] = advertisement(record.get('payload_hex', ''))
                    if kind == 'wifi' and record.get('ssid_hex'):
                        record['ssid'] = bytes.fromhex(record['ssid_hex']).decode('utf-8', 'replace')
                    records[key] = record
            data = {'port': device.port, 'records': list(records.values()), 'stats': stats,
                    'method': 'passive' if kind == 'nrf' or not params.get('active') else 'active',
                    **({'samples': params['samples']} if kind == 'nrf' else {'duration_seconds': params['duration']})}
        lost = int(stats.get('dropped', 0))
        return ctx.observation(self.manifest.id, data,
                               status='PARTIAL' if lost else 'OBSERVED' if records else 'EMPTY',
                               warnings=[f'{lost} records dropped; shorten the scan'] if lost else [])


class BleDiscovery(EmbeddedDiscovery):
    manifest = Manifest('recon.ble', 'BLE advertisements', 'ble', 'Read BLE advertising data through the ESP32.',
                        hardware=('esp32',), parameters=('port', 'duration', 'active'))


class NrfDiscovery(EmbeddedDiscovery):
    manifest = Manifest('recon.nrf', 'nRF channel activity', 'nrf', 'Measure received-power detector hits across 126 channels.',
                        hardware=('esp32', 'nrf24'), parameters=('port', 'samples'))


class EspWifiDiscovery(EmbeddedDiscovery):
    manifest = Manifest('recon.espwifi', 'ESP32 Wi-Fi discovery', 'wifi', 'Scan 2.4 GHz Wi-Fi through the ESP32.',
                        hardware=('esp32',), parameters=('port', 'active', 'duration'))


PLUGINS = (BleDiscovery, NrfDiscovery, EspWifiDiscovery)
