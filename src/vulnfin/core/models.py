from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class Manifest:
    id: str
    name: str
    protocol: str
    description: str
    hardware: tuple[str, ...] = ()
    parameters: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    target_types: tuple[str, ...] = ()
    tools: tuple[str, ...] = ()
    version: str = "0.1.0"
    operation: str = "discovery"
    output: str = "vulnfin.observation.v1"

    def validate(self):
        if not self.id or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789._-' for c in self.id):
            raise ValueError(f'Invalid plugin identifier: {self.id}')
        if self.operation != 'discovery' or not self.protocol or not self.name:
            raise ValueError('Invalid discovery manifest')
        return self


@dataclass
class CommandResult:
    argv: list[str]
    status: str
    returncode: int | None = None
    stdout: str = ''
    stderr: str = ''
    elapsed_ms: float = 0
    truncated: bool = False
    started_at: str = field(default_factory=utcnow)

    def summary(self):
        return {k: v for k, v in asdict(self).items() if k not in ('stdout', 'stderr')}


@dataclass
class Observation:
    plugin: str
    status: str
    data: dict[str, Any]
    warnings: list[str] = field(default_factory=list)
    commands: list[dict] = field(default_factory=list)
    targets: list[dict] = field(default_factory=list)
    schema: str = 'vulnfin.observation.v1'
    observed_at: str = field(default_factory=utcnow)

    def to_dict(self):
        return asdict(self)
