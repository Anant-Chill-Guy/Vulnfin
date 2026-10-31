from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import time

from .linux import Runner, interface_name
from .resources import Resource
from ..core.runtime import configuration


def pcap_info(path):
    with path.open('rb') as stream:
        header = stream.read(24)
        byteorders = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>', b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>'}
        order = byteorders.get(header[:4])
        if len(header) != 24 or order is None:
            raise ValueError('No valid PCAP header received')
        linktype = struct.unpack(order + 'I', header[20:24])[0]
        packets, truncated = 0, False
        while True:
            raw = stream.read(16)
            if not raw:
                break
            if len(raw) != 16:
                truncated = True
                break
            length = struct.unpack(order + 'I', raw[8:12])[0]
            if length > 16 * 1024 * 1024 or len(stream.read(length)) != length:
                truncated = True
                break
            packets += 1
    return {'packets': packets, 'linktype': linktype, 'truncated': truncated}


async def capture_wifi(interface, path, *, channel=None, duration=30, bssid=None, expression=None, max_mb=64):
    iface = interface_name(interface)
    if iface == configuration()['wifi']['protected_interface']:
        raise ValueError('Choose a dedicated adapter; the protected interface cannot be used for capture')
    if not 1 <= duration <= 3600 or not 1 <= max_mb <= 1024:
        raise ValueError('Duration must be 1–3600 seconds; max size must be 1–1024 MiB')
    if channel is not None and not 1 <= channel <= 233:
        raise ValueError('Invalid Wi-Fi channel')
    if not shutil.which('tcpdump'):
        raise ValueError('tcpdump not found')
    path = Path(path).expanduser()
    if path.exists() or path.is_symlink() or not path.parent.is_dir():
        raise ValueError('Choose a new output file in an existing directory')
    runner = Runner()
    cleanup = []
    restore_attempt_errors = []
    async def command(argv, privileged=False):
        result = await runner.command(argv, privileged=privileged)
        if result.status != 'OK':
            raise ValueError(result.stderr.strip() or 'Command failed: ' + ' '.join(argv))
        return result.stdout
    with Resource('wifi:' + iface):
        info = await command(['iw', 'dev', iface, 'info'])
        match = re.search(r'^\s*type\s+(\S+)', info, re.M)
        mode = match[1] if match else None
        if mode not in ('managed', 'monitor'):
            raise ValueError('Capture requires a managed or monitor interface')
        if mode == 'managed':
            link = await command(['iw', 'dev', iface, 'link'])
            if link.lstrip().startswith('Connected to'):
                raise ValueError('Adapter is connected; disconnect it before capture')
        links = json.loads(await command(['ip', '-j', 'link', 'show', 'dev', iface]))
        was_up = 'UP' in links[0].get('flags', [])
        frequency = re.search(r'channel\s+\d+\s+\((\d+) MHz\)', info)
        managed = None
        if shutil.which('nmcli'):
            state = await command(['nmcli', '-g', 'GENERAL.NM-MANAGED', 'device', 'show', iface])
            if state.strip() not in ('yes', 'no'):
                raise ValueError('Could not read NetworkManager ownership')
            managed = state.strip() == 'yes'
        original_state = {'mode': mode, 'admin_up': was_up, 'nm_managed': managed}
        restored_state = None
        restoration_verified = False
        async def verify_state():
            current_info = await runner.command(['iw', 'dev', iface, 'info'])
            current_link = await runner.command(['ip', '-j', 'link', 'show', 'dev', iface])
            if current_info.status != 'OK' or current_link.status != 'OK':
                raise ValueError('Could not verify restored interface state')
            current_mode = re.search(r'^\s*type\s+(\S+)', current_info.stdout, re.M)
            try:
                values = json.loads(current_link.stdout)
                admin_up = 'UP' in values[0]['flags']
            except (ValueError, KeyError, IndexError, TypeError):
                raise ValueError('Invalid interface state during restoration check') from None
            nm_managed = None
            if managed is not None:
                current_nm = await runner.command(['nmcli', '-g', 'GENERAL.NM-MANAGED', 'device', 'show', iface])
                if current_nm.status != 'OK' or current_nm.stdout.strip() not in ('yes', 'no'):
                    raise ValueError('Could not verify NetworkManager ownership')
                nm_managed = current_nm.stdout.strip() == 'yes'
            if not current_mode:
                raise ValueError('Could not verify restored Wi-Fi mode')
            state = {'mode': current_mode[1], 'admin_up': admin_up, 'nm_managed': nm_managed}
            if mode == 'monitor' and channel is not None and frequency:
                current_frequency = re.search(r'channel\s+\d+\s+\((\d+) MHz\)', current_info.stdout)
                state['frequency_mhz'] = int(current_frequency[1]) if current_frequency else None
            return state
        async def check_restoration():
            nonlocal restored_state
            for delay in (0, 0.2, 0.5):
                if delay:
                    await asyncio.sleep(delay)
                restored_state = await verify_state()
                matches = all(restored_state.get(key) == value for key, value in original_state.items())
                if mode == 'monitor' and channel is not None and frequency:
                    matches = matches and restored_state.get('frequency_mhz') == int(frequency[1])
                if matches:
                    return True
            return False
        changed_mode = nm_changed = started = False
        proc = None
        reader = None
        stderr = bytearray()
        stopped = False
        limit_reached = False
        valid = False
        stream = None
        async def drain():
            while chunk := await proc.stderr.read(4096):
                if len(stderr) < 65536:
                    stderr.extend(chunk[:65536-len(stderr)])
        async def stop():
            if proc is None or proc.returncode is not None:
                return
            try:
                proc.send_signal(signal.SIGINT)
            except ProcessLookupError:
                return
            try:
                await asyncio.wait_for(proc.wait(), 3)
            except asyncio.TimeoutError:
                try:
                    proc.terminate()
                    await asyncio.wait_for(proc.wait(), 2)
                except (ProcessLookupError, asyncio.TimeoutError):
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass
                    await proc.wait()
        await runner.require_privileges()
        failure = None
        try:
            if managed:
                nm_changed = True
                await command(['nmcli', 'device', 'set', iface, 'managed', 'no'], True)
            if mode != 'monitor':
                await command(['ip', 'link', 'set', iface, 'down'], True)
                changed_mode = True
                await command(['iw', 'dev', iface, 'set', 'type', 'monitor'], True)
            await command(['ip', 'link', 'set', iface, 'up'], True)
            if channel is not None:
                await command(['iw', 'dev', iface, 'set', 'channel', str(channel)], True)
            filters = []
            if bssid:
                filters.append('wlan host ' + bssid)
            if expression:
                filters.append('(' + expression + ')')
            argv = ['tcpdump', '-i', iface, '-U', '-s', '0', '-w', '-']
            if filters:
                argv += [' and '.join(filters)]
            if os.geteuid() != 0:
                await runner.require_privileges()
                argv = ['sudo', '-n', '--', *argv]
            stream = path.open('xb')
            started = True
            proc = await asyncio.create_subprocess_exec(*argv, stdout=stream, stderr=asyncio.subprocess.PIPE,
                                                        stdin=asyncio.subprocess.DEVNULL, process_group=0,
                                                        env={**os.environ, 'LC_ALL': 'C'})
            reader = asyncio.create_task(drain())
            deadline = time.monotonic() + duration
            while proc.returncode is None and time.monotonic() < deadline:
                if path.stat().st_size >= max_mb * 1024 * 1024:
                    limit_reached = True
                    break
                await asyncio.sleep(0.05)
            await stop()
        except asyncio.CancelledError:
            stopped = True
        except (ValueError, OSError) as error:
            failure = str(error)
        finally:
            await asyncio.shield(stop())
            if reader:
                await reader
            if stream:
                stream.close()
            async def restore_command(argv):
                result = await runner.command(argv, privileged=True)
                if result.status != 'OK':
                    restore_attempt_errors.append(result.stderr.strip() or 'Could not restore ' + iface)
            for argv, enabled in (
                (['ip', 'link', 'set', iface, 'down'], changed_mode or not was_up),
                (['iw', 'dev', iface, 'set', 'type', mode], changed_mode),
                (['iw', 'dev', iface, 'set', 'freq', frequency[1] if frequency else '0'], channel is not None and mode == 'monitor' and frequency is not None),
                (['ip', 'link', 'set', iface, 'up' if was_up else 'down'], True),
                (['nmcli', 'device', 'set', iface, 'managed', 'yes'], nm_changed),
            ):
                if enabled:
                    await asyncio.shield(restore_command(argv))
            try:
                restoration_verified = await asyncio.shield(check_restoration())
                if not restoration_verified:
                    if managed is not None:
                        await asyncio.shield(restore_command(['nmcli', 'device', 'set', iface, 'managed', 'no']))
                    for argv in (
                        ['ip', 'link', 'set', iface, 'down'],
                        ['iw', 'dev', iface, 'set', 'type', mode],
                    ):
                        await asyncio.shield(restore_command(argv))
                    if mode == 'monitor' and channel is not None and frequency:
                        await asyncio.shield(restore_command(['iw', 'dev', iface, 'set', 'freq', frequency[1]]))
                    await asyncio.shield(restore_command(['ip', 'link', 'set', iface, 'up' if was_up else 'down']))
                    if managed is not None:
                        await asyncio.shield(restore_command(['nmcli', 'device', 'set', iface, 'managed', 'yes' if managed else 'no']))
                    restoration_verified = await asyncio.shield(check_restoration())
                if not restoration_verified:
                    cleanup.append('Interface restoration failed: expected ' + json.dumps(original_state, sort_keys=True) +
                                   '; observed ' + json.dumps(restored_state, sort_keys=True))
            except (ValueError, OSError) as error:
                cleanup.append('Restoration verification failed: ' + str(error))
            if not restoration_verified:
                cleanup.extend(restore_attempt_errors)
        if started and path.is_file():
            try:
                stats = pcap_info(path)
                valid = True
                if stats['linktype'] not in (105, 119, 127, 192):
                    failure = failure or 'Capture does not contain an 802.11 link type'
                if stats['truncated']:
                    failure = failure or 'Capture ends with an incomplete packet'
            except ValueError as error:
                failure = failure or str(error)
                path.unlink()
        if not valid:
            if stopped and not cleanup:
                raise asyncio.CancelledError()
            raise ValueError('; '.join(filter(None, [failure or stderr.decode(errors='replace').strip() or 'Capture did not start', *cleanup])))
        if proc.returncode not in (0, 130, -signal.SIGINT):
            failure = failure or stderr.decode(errors='replace').strip() or 'Capture process failed'
        return {'file': str(path), 'interface': iface, 'channel': channel, **stats,
                'bytes': path.stat().st_size, 'size_limit_reached': limit_reached, 'interrupted': stopped,
                'original_state': original_state, 'restored_state': restored_state,
                'restoration_verified': restoration_verified, 'restore_attempt_errors': restore_attempt_errors,
                'cleanup_errors': cleanup, 'error': failure, 'tcpdump': stderr.decode(errors='replace').strip()}
