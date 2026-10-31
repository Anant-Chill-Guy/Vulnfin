#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

if [[ ! -x .venv-vulnfin/bin/python ]]; then
    python3 -m venv .venv-vulnfin
fi

.venv-vulnfin/bin/python -m pip install \
    --quiet --disable-pip-version-check --no-compile -e .

printf '\nInstalled.\n  source .venv-vulnfin/bin/activate\n  vulnfin -h\n'
