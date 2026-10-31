from importlib import import_module
from pkgutil import iter_modules


def discover():
    for item in sorted(iter_modules(__path__), key=lambda x: x.name):
        if item.name.startswith('_'): continue
        module = import_module(f'{__name__}.{item.name}')
        for plugin_type in getattr(module, 'PLUGINS', ()):
            yield plugin_type()
