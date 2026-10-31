#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

if (( EUID != 0 )); then
    exec sudo -- bash "$PWD/bootstrap.sh"
fi

VULNFIN_PREFIX="${VULNFIN_PREFIX:-/usr/local}"
VULNFIN_PYTHON="${VULNFIN_PYTHON:-/usr/bin/python3}"

if ! "$VULNFIN_PYTHON" -I -c 'import sys; from importlib.metadata import version; assert sys.version_info >= (3, 11); assert int(version("rich").split(".")[0]) in (14, 15); assert (3, 5) <= tuple(map(int, version("pyserial").split(".")[:2])) < (4, 0); import serial' >/dev/null 2>&1; then
    if command -v pacman >/dev/null 2>&1; then
        pacman -S --needed python python-rich python-pyserial
    else
        printf '%s\n' 'Install Python 3.11+, Rich 14 or 15 and pyserial 3.5+ with your package manager.' >&2
        exit 1
    fi
fi

"$VULNFIN_PYTHON" -I - "$PWD" "$VULNFIN_PREFIX" "$VULNFIN_PYTHON" <<'PY'
import ast
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

source = Path(sys.argv[1]).resolve()
prefix = Path(sys.argv[2]).expanduser().resolve()
python = Path(sys.argv[3]).absolute()
if sys.version_info < (3, 11):
    raise SystemExit('Python 3.11 or newer is required')
if any(c.isspace() for c in str(python)):
    raise SystemExit('Python executable path cannot contain whitespace')
runtime = prefix / 'lib' / 'vulnfin'
package = runtime / 'vulnfin'
launcher = prefix / 'bin' / 'vulnfin'
for path in (runtime, package):
    if path.is_symlink() or path.exists() and path.stat().st_uid != 0:
        raise SystemExit('Installation directory must be owned by root: ' + str(path))
files = {}
for path in sorted((source / 'src' / 'vulnfin').rglob('*')):
    if '__pycache__' in path.parts or path.suffix not in ('.py', '.ino'):
        continue
    if path.is_symlink() or not path.is_file():
        raise SystemExit('Invalid source file: ' + str(path))
    data = path.read_bytes()
    if path.suffix == '.py':
        ast.parse(data, filename=str(path))
    files[path.relative_to(source / 'src' / 'vulnfin')] = data
if Path('cli/app.py') not in files or Path('firmware/agent/agent.ino') not in files:
    raise SystemExit('Vulnfin source is incomplete')

def write(path, data, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            os.fchmod(stream.fileno(), mode)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)

for relative, data in files.items():
    write(package / relative, data, 0o644)
for path in sorted(package.rglob('*'), reverse=True):
    if path.is_symlink() or path.is_file() and path.relative_to(package) not in files:
        path.unlink()
    elif path.is_dir():
        path.chmod(0o755)
        try:
            path.rmdir()
        except OSError:
            pass
runtime.chmod(0o755)
package.chmod(0o755)
entry = (f'#!{python} -I\nimport sys\nsys.dont_write_bytecode = True\n'
         f'sys.path.insert(0, {str(runtime)!r})\nfrom vulnfin.cli.app import main\nmain()\n')
write(launcher, entry.encode(), 0o755)
subprocess.run([str(launcher), '-h'], check=True, stdout=subprocess.DEVNULL)
generated = [source / '.venv-vulnfin', source / 'src' / 'vulnfin.egg-info',
             *(source / 'src' / 'vulnfin').rglob('__pycache__')]
for path in generated:
    if path.is_symlink():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)
print('Installed: ' + str(launcher))
PY
