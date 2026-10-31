from __future__ import annotations

import os
from pathlib import Path
import tomllib

from ..adapters.linux import Runner
from .models import Observation


def configuration():
    config = {'wifi': {'interface': 'wlan1', 'protected_interface': 'wlan0'}}
    path = Path(os.environ.get('XDG_CONFIG_HOME', Path.home() / '.config')) / 'vulnfin' / 'config.toml'
    if path.is_file():
        with path.open('rb') as stream:
            custom = tomllib.load(stream)
        config['wifi'].update(custom.get('wifi', {}))
    return config


class Context:
    def __init__(self, runner, config, verbose=False):
        self.runner = runner
        self.config = config
        self.verbose = verbose

    def progress(self, message):
        if self.verbose:
            from rich.console import Console
            Console(stderr=True, highlight=False).print(str(message), markup=False)

    def observation(self, plugin, data, targets=None, warnings=None, status=None):
        failures = any((r.status != 'OK' and not getattr(r, 'recovered', False)) or r.truncated for r in self.runner.results)
        commands = []
        for result in self.runner.results:
            command = result.summary()
            if result.status != 'OK':
                command['error'] = result.stderr.strip() or result.status.lower().replace('_', ' ')
                if result.status == 'PERMISSION_REQUIRED':
                    command['error'] += ' · run sudo -v, then retry'
            if getattr(result, 'recovered', False):
                command['recovered'] = True
            commands.append(command)
        return Observation(plugin=plugin, status=status or ('PARTIAL' if failures else 'OBSERVED'),
                           data=data, warnings=list(warnings or []), commands=commands,
                           targets=targets or [])



async def execute(plugin, params, *, verbose=False):
    config = configuration()
    params = plugin.prepare(dict(params), config)
    runner = Runner(limit=32 * 1024 * 1024)
    context = Context(runner, config, verbose)
    return await plugin.run(context, params)
