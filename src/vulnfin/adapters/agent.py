from __future__ import annotations

import asyncio
import json
import os
import time
import uuid

from .resources import Resource


def ports():
    try:
        from serial.tools import list_ports
    except ImportError:
        raise ValueError('Serial support missing. Run bash bootstrap.sh') from None
    return [{'port': p.device, 'description': p.description, 'vid': p.vid, 'pid': p.pid}
            for p in list_ports.comports() if p.device.startswith(('/dev/ttyACM', '/dev/ttyUSB'))]


def choose_port(value='auto'):
    if value != 'auto':
        if not value.startswith(('/dev/ttyACM', '/dev/ttyUSB', '/dev/serial/')):
            raise ValueError('Choose a USB serial port under /dev')
        return value
    found = ports()
    if len(found) != 1:
        raise ValueError('No serial device found' if not found else 'Several serial devices found; use --port')
    return found[0]['port']


def board_configuration(port):
    from pathlib import Path
    found = next((p for p in ports() if Path(p['port']).resolve() == Path(port).resolve()), None)
    if not found:
        raise ValueError('USB port disappeared; reconnect the board and run device ports')
    base = 'esp32:esp32:esp32s3:FlashSize=16M,PSRAM=opi,PartitionScheme=huge_app'
    if (found['vid'], found['pid']) == (0x303a, 0x1001):
        return base + ',USBMode=hwcdc,CDCOnBoot=cdc', 'native USB'
    if found['vid'] in (0x1a86, 0x10c4, 0x0403, 0x067b):
        return base + ',CDCOnBoot=default', 'USB-UART'
    raise ValueError('USB connection type is unknown; supply --fqbn with matching USB settings')


class Agent:
    def __init__(self, port='auto'):
        self.port = choose_port(port)
        self.serial = None
        self.resource = Resource('serial:' + os.path.realpath(self.port))
        self.pending = bytearray()
        self.active = None
        self.hello = None

    async def __aenter__(self):
        try:
            import serial
        except ImportError:
            raise ValueError('Serial support missing. Run bash bootstrap.sh') from None
        self.resource.__enter__()
        try:
            self.serial = serial.Serial(port=None, baudrate=115200, timeout=0, write_timeout=2, exclusive=True)
            self.serial.dtr = False
            self.serial.rts = False
            self.serial.port = self.port
            self.serial.open()
            await asyncio.sleep(0.2)
            for attempt in range(2):
                try:
                    events = [event async for event in self.command('HELLO', timeout=4)]
                    self.hello = next((e for e in events if e.get('type') == 'hello'), None)
                    if not self.hello or self.hello.get('agent') != 'Vulnfin' or self.hello.get('protocol') != 1:
                        raise ValueError('Unsupported firmware; flash the Vulnfin agent')
                    caps = self.hello.get('capabilities')
                    if not isinstance(caps, dict) or any(not isinstance(caps.get(k), bool) for k in ('wifi', 'ble', 'nrf')):
                        raise ValueError('Invalid firmware capability response')
                    return self
                except ValueError:
                    if attempt:
                        raise
                    self.pending.clear()
                    await asyncio.sleep(0.3)
        except BaseException:
            await self.__aexit__(None, None, None)
            raise

    def send(self, command):
        try:
            data = (command + '\n').encode('ascii')
            if self.serial.write(data) != len(data):
                raise ValueError('Serial write incomplete')
        except OSError as error:
            raise ValueError('Serial connection failed: ' + str(error)) from None

    async def command(self, name, *arguments, timeout=30):
        identity = uuid.uuid4().hex[:8]
        self.active = identity
        self.send(' '.join((name, identity, *(str(v) for v in arguments))))
        deadline = time.monotonic() + timeout
        heartbeat = time.monotonic()
        finished = False
        try:
            while time.monotonic() < deadline:
                if time.monotonic() - heartbeat >= 1:
                    self.send('PING ' + identity)
                    heartbeat = time.monotonic()
                try:
                    self.pending.extend(self.serial.read(min(self.serial.in_waiting or 1, 4096)))
                except OSError as error:
                    raise ValueError('Serial connection lost: ' + str(error)) from None
                while b'\n' in self.pending:
                    line, _, remainder = self.pending.partition(b'\n')
                    self.pending = bytearray(remainder)
                    if len(line) > 4096:
                        raise ValueError('Firmware response too long')
                    try:
                        event = json.loads(line)
                    except (ValueError, UnicodeError):
                        continue
                    if not isinstance(event, dict) or event.get('id') != identity:
                        continue
                    if not isinstance(event.get('type'), str):
                        raise ValueError('Invalid firmware response')
                    if event.get('type') == 'error':
                        raise ValueError(str(event.get('message', 'Device operation failed')))
                    if event.get('type') == 'done':
                        finished = True
                        if event.get('cancelled'):
                            raise ValueError('Device operation interrupted')
                        yield event
                        return
                    yield event
                if len(self.pending) > 4096:
                    raise ValueError('Firmware response too long')
                await asyncio.sleep(0.02)
            raise ValueError('Device timed out; check firmware and USB connection')
        finally:
            if not finished and self.serial and self.serial.is_open:
                try:
                    self.send('STOP ' + identity)
                except (OSError, ValueError):
                    pass
            self.active = None

    async def __aexit__(self, *args):
        try:
            if self.serial:
                try:
                    if self.active and self.serial.is_open:
                        try:
                            self.send('STOP ' + self.active)
                        except (OSError, ValueError):
                            pass
                    await asyncio.sleep(0.1)
                finally:
                    self.serial.close()
        finally:
            self.resource.__exit__(*args)


def advertisement(data):
    result = {'name': None, 'service_uuids': [], 'manufacturer': None, 'manufacturers': [],
              'service_data': [], 'fields': [], 'raw_hex': data}
    try:
        raw = bytes.fromhex(data)
    except (ValueError, TypeError):
        return {**result, 'malformed': True}
    position, complete_name = 0, False
    uuid_lengths = {2: 2, 3: 2, 4: 4, 5: 4, 6: 16, 7: 16}
    service_lengths = {0x16: 2, 0x20: 4, 0x21: 16}
    def service_uuid(value):
        return str(uuid.UUID(bytes=bytes(reversed(value)))) if len(value) == 16 else f'{int.from_bytes(value, "little"):0{len(value)*2}x}'
    while position < len(raw):
        length = raw[position]
        if not length:
            break
        end = position + length + 1
        if end > len(raw):
            result['malformed'] = True
            break
        kind, value = raw[position + 1], raw[position + 2:end]
        result['fields'].append({'type': kind, 'hex': value.hex()})
        if kind in (8, 9) and (kind == 9 or not complete_name):
            result['name'] = value.decode('utf-8', errors='replace')
            complete_name = kind == 9
        elif kind in uuid_lengths:
            size = uuid_lengths[kind]
            if len(value) % size:
                result['malformed'] = True
            else:
                result['service_uuids'].extend(service_uuid(value[i:i+size]) for i in range(0, len(value), size))
        elif kind in service_lengths:
            size = service_lengths[kind]
            if len(value) < size:
                result['malformed'] = True
            else:
                identity = service_uuid(value[:size])
                result['service_uuids'].append(identity)
                result['service_data'].append({'uuid': identity, 'data_hex': value[size:].hex()})
        elif kind == 255:
            if len(value) < 2:
                result['malformed'] = True
            else:
                item = {'company_id': int.from_bytes(value[:2], 'little'), 'data_hex': value[2:].hex()}
                result['manufacturers'].append(item)
                result['manufacturer'] = item
        elif kind in (1, 0x0a, 0x19):
            size = 2 if kind == 0x19 else 1
            if len(value) != size:
                result['malformed'] = True
            else:
                key = {1: 'flags', 0x0a: 'tx_power_dbm', 0x19: 'appearance'}[kind]
                result[key] = int.from_bytes(value, 'little', signed=kind == 0x0a)
        position = end
    result['service_uuids'] = list(dict.fromkeys(result['service_uuids']))
    return result
