from __future__ import annotations

import csv
from datetime import datetime, timezone
import io
from pathlib import Path
import shutil

from .linux import Runner


FIELDS = {
    'number': 'frame.number', 'timestamp': 'frame.time_epoch', 'bytes': 'frame.len',
    'protocols': 'frame.protocols', 'type_subtype': 'wlan.fc.type_subtype',
    'transmitter': 'wlan.ta', 'receiver': 'wlan.ra', 'source': 'wlan.sa',
    'destination': 'wlan.da', 'bssid': 'wlan.bssid', 'ssid_hex': 'wlan.ssid',
    'frequency_mhz': 'radiotap.channel.freq', 'signal_dbm': 'radiotap.dbm_antsignal',
    'protected': 'wlan.fc.protected', 'retry': 'wlan.fc.retry',
    'ip_source': 'ip.src', 'ip_destination': 'ip.dst',
    'ipv6_source': 'ipv6.src', 'ipv6_destination': 'ipv6.dst',
    'tcp_source_port': 'tcp.srcport', 'tcp_destination_port': 'tcp.dstport',
    'udp_source_port': 'udp.srcport', 'udp_destination_port': 'udp.dstport',
    'summary': '_ws.col.Info',
}

TYPES = {0x00: 'Association request', 0x01: 'Association response', 0x02: 'Reassociation request',
         0x03: 'Reassociation response', 0x04: 'Probe request', 0x05: 'Probe response',
         0x08: 'Beacon', 0x0a: 'Disassociation', 0x0b: 'Authentication', 0x0c: 'Deauthentication',
         0x0d: 'Action', 0x18: 'Block ACK request', 0x19: 'Block ACK', 0x1b: 'RTS',
         0x1c: 'CTS', 0x1d: 'ACK', 0x20: 'Data', 0x24: 'Null data',
         0x28: 'QoS data', 0x2c: 'QoS null'}


def decode_rows(text):
    rows = []
    for values in csv.reader(io.StringIO(text), delimiter='\t', quotechar='"'):
        if len(values) != len(FIELDS):
            raise ValueError('Unexpected TShark output; check the installed Wireshark version')
        row = {key: value or None for key, value in zip(FIELDS, values)}
        for key in ('number', 'bytes', 'frequency_mhz', 'signal_dbm', 'tcp_source_port',
                    'tcp_destination_port', 'udp_source_port', 'udp_destination_port'):
            try:
                row[key] = int(row[key]) if row[key] is not None else None
            except ValueError:
                row[key] = None
        for key in ('protected', 'retry'):
            row[key] = None if row[key] is None else row[key] in ('1', 'True', 'true')
        try:
            subtype = int(row['type_subtype'], 0) if row['type_subtype'] else None
        except ValueError:
            subtype = None
        row['type'] = TYPES.get(subtype, '802.11 frame')
        row['ssid'] = None
        if row['ssid_hex'] is not None:
            try:
                row['ssid'] = bytes.fromhex(row['ssid_hex'].replace(':', '')).decode('utf-8', 'replace')
            except ValueError:
                row['ssid_encoding_error'] = True
        row['protocols'] = (row['protocols'] or '').split(':')
        rows.append(row)
    return rows


async def inspect_wifi(path, *, limit=None, expression=None):
    path = Path(path).expanduser().resolve()
    if not path.is_file():
        raise ValueError('Capture file not found: ' + str(path))
    if limit is not None and not 1 <= limit <= 1000000:
        raise ValueError('Packet read limit must be 1–1000000')
    if not shutil.which('tshark'):
        raise ValueError('tshark not found. Install wireshark-cli')
    argv = ['tshark', '-n', '-r', str(path), '-Y',
            'wlan' + (' && (' + expression + ')' if expression else ''),
            '-T', 'fields', '-E', 'separator=/t', '-E', 'quote=d', '-E', 'occurrence=f']
    if limit is not None:
        argv += ['-c', str(limit)]
    for field in FIELDS.values():
        argv += ['-e', field]
    runner = Runner(limit=32*1024*1024)
    result = await runner.command(argv, timeout=120)
    if result.status != 'OK' or result.truncated:
        if result.truncated:
            raise ValueError('Decoded output exceeded 32 MiB; narrow --filter or set --limit')
        raise ValueError(result.stderr.strip() or 'Packet decoding failed')
    rows = decode_rows(result.stdout)
    return {'plugin': 'inspect.wifi', 'analyzed_at': datetime.now(timezone.utc).isoformat(),
            'data': {'file': str(path), 'packet_read_limit': limit, 'display_filter': expression,
                     'packets': rows, 'count': len(rows), 'decoder': 'tshark',
                     'scope': 'Offline decoding of at most the requested input frames; encrypted payloads are not decrypted.'}}
