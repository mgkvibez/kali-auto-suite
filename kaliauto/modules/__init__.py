"""The module registry. Each module is plan()+run(), and run() is injectable."""

from __future__ import annotations

from typing import Dict

from . import dns as dns_mod
from . import headers as headers_mod
from . import ports as ports_mod
from . import tls as tls_mod

REGISTRY: Dict[str, object] = {"dns": dns_mod, "tls": tls_mod, "headers": headers_mod, "ports": ports_mod}


def plan_module(name: str, target: str, timeout: float = 5.0) -> str:
    return REGISTRY[name].plan(target, timeout)


def run_module(name: str, target: str, timeout: float = 5.0, **kwargs):
    return REGISTRY[name].run(target, timeout, **kwargs)


def available() -> Dict[str, bool]:
    return {name: mod.available() for name, mod in REGISTRY.items()}
