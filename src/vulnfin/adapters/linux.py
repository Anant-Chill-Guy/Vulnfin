from __future__ import annotations

import asyncio
import os
import re
import shutil
import signal
import time

from ..core.models import CommandResult


def interface_name(value):
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', value):
        raise ValueError('Invalid Linux interface name')
    return value


class Runner:
    def __init__(self, limit=2 * 1024 * 1024):
        self.limit = limit
        self.results = []

    async def command(self, argv, timeout=15, privileged=False, accepted=(0,)):
        argv = list(argv)
        result = CommandResult(argv=argv, status='UNAVAILABLE')
        start = time.monotonic()
        program = shutil.which(argv[0])
        actual = argv
        buffers = [bytearray(), bytearray()]
        truncated = [False, False]
        proc = None

        async def drain(stream, index):
            while chunk := await stream.read(65536):
                remaining = self.limit - len(buffers[index])
                buffers[index].extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated[index] = True

        async def terminate():
            if proc is None or proc.returncode is not None:
                return
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                try: proc.terminate()
                except (ProcessLookupError, PermissionError): pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=2)
            except asyncio.TimeoutError:
                try: os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError): pass
                try: await asyncio.wait_for(proc.wait(), timeout=2)
                except asyncio.TimeoutError: pass

        readers = []
        try:
            if not program:
                result.stderr = f'Missing executable: {argv[0]}'
                return result
            if privileged and os.geteuid() != 0:
                if not shutil.which('sudo'):
                    result.status = 'PERMISSION_REQUIRED'
                    result.stderr = 'sudo is unavailable; the operation requires CAP_NET_ADMIN/root.'
                    return result
                actual = ['sudo', '-n', '--'] + argv
            proc = await asyncio.create_subprocess_exec(*actual, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, stdin=asyncio.subprocess.DEVNULL,
                process_group=0, env={**os.environ, 'LC_ALL': 'C'})
            readers = [asyncio.create_task(drain(proc.stdout, 0)), asyncio.create_task(drain(proc.stderr, 1))]
            await asyncio.wait_for(asyncio.gather(proc.wait(), *readers), timeout=timeout)
            result.returncode = proc.returncode
            result.status = 'OK' if proc.returncode in accepted else 'ERROR'
            if privileged and proc.returncode and b'password is required' in buffers[1]:
                result.status = 'PERMISSION_REQUIRED'
        except asyncio.TimeoutError:
            result.status = 'TIMEOUT'
            await terminate()
        except asyncio.CancelledError:
            result.status = 'CANCELLED'
            await terminate()
            raise
        except OSError as error:
            result.status = 'ERROR'
            result.stderr = str(error)
        finally:
            for task in readers:
                if not task.done(): task.cancel()
            if readers:
                await asyncio.gather(*readers, return_exceptions=True)
            result.stdout = buffers[0].decode(errors='replace')
            result.stderr += buffers[1].decode(errors='replace')
            result.truncated = any(truncated)
            result.elapsed_ms = round((time.monotonic() - start) * 1000, 2)
            self.results.append(result)
        return result
