"""The authorization gate: a target is in scope only if a human said so."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import List, Optional, Tuple

REQUIRED_FIELDS = ("authorized_by", "authorized_on", "contact", "authorization_reference")
# Hostnames, IPv4/IPv6 and CIDR only. Anything else is refused before it can be
# turned into an argv entry, which is what keeps shell metacharacters out.
TARGET_RE = re.compile(r"^(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$|^[0-9a-fA-F:.]+(?:/[0-9]{1,3})?$")
HOSTNAME_RE = re.compile(r"^(?:\*\.)?(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")


class ScopeError(Exception):
    """Refusal. Every subclass carries the reason a human needs to see."""


class MissingAuthorization(ScopeError):
    pass


class OutOfScope(ScopeError):
    pass


class UnsafeTarget(ScopeError):
    pass


@dataclass(frozen=True)
class Scope:
    path: str
    digest: str
    authorized_by: str
    authorized_on: str
    contact: str
    authorization_reference: str
    allow_private: bool
    targets: Tuple[str, ...] = field(default_factory=tuple)

    def fingerprint(self) -> str:
        return self.digest[:12]


def _is_private(target: str) -> bool:
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False
    return network.is_private or network.is_loopback or network.is_link_local


def _validate_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise UnsafeTarget("empty target")
    if not (TARGET_RE.match(target) or HOSTNAME_RE.match(target)):
        raise UnsafeTarget("target {!r} is not a hostname, IP or CIDR range".format(target))
    if any(bad in target for bad in (";", "&", "|", "$", "`", "\n", " ", ">", "<", "*.")):
        if not target.startswith("*."):
            raise UnsafeTarget("target {!r} contains characters that do not belong in a host".format(target))
    return target


def load_scope(path: str) -> Scope:
    p = Path(path)
    if not p.is_file():
        raise MissingAuthorization("scope file {!r} does not exist".format(path))
    raw = p.read_text()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MissingAuthorization("scope file is not valid JSON: {}".format(exc)) from exc
    if not isinstance(data, dict):
        raise MissingAuthorization("scope file must be a JSON object")

    missing = [f for f in REQUIRED_FIELDS if not str(data.get(f, "")).strip()]
    if missing:
        raise MissingAuthorization(
            "scope file is missing the authorization fields: {}. A recon run without "
            "a named authorizer is not something this tool will start.".format(", ".join(missing)))

    targets = data.get("targets")
    if not isinstance(targets, list) or not targets:
        raise MissingAuthorization("scope file lists no targets")
    checked = tuple(_validate_target(str(t)) for t in targets)

    allow_private = bool(data.get("allow_private", False))
    digest = hashlib.sha256(raw.encode()).hexdigest()
    return Scope(path=str(p), digest=digest,
                 authorized_by=str(data["authorized_by"]),
                 authorized_on=str(data["authorized_on"]),
                 contact=str(data["contact"]),
                 authorization_reference=str(data["authorization_reference"]),
                 allow_private=allow_private, targets=checked)


def _matches(target: str, entry: str) -> bool:
    if entry.startswith("*."):
        suffix = entry[2:].lower()
        return target.lower() == suffix or target.lower().endswith("." + suffix)
    if target == entry:
        return True
    try:
        if "/" in entry:
            return ipaddress.ip_address(target) in ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return False
    return False


def authorize(scope: Scope, target: str) -> str:
    """Return the target if it is in scope, else raise. This is the only door in."""
    target = _validate_target(target)
    if not any(_matches(target, e) for e in scope.targets):
        raise OutOfScope(
            "{!r} is not listed in {} (scope {}). Add it to the scope file only if "
            "you are authorized for it.".format(target, scope.path, scope.fingerprint()))
    if _is_private(target) and not scope.allow_private:
        raise OutOfScope(
            "{!r} is a private or loopback address and the scope file does not set "
            "allow_private: true".format(target))
    return target


def targets_for_run(scope: Scope, requested: Optional[List[str]]) -> List[str]:
    chosen = requested if requested else list(scope.targets)
    out, seen = [], set()
    for t in chosen:
        authorised = authorize(scope, t)
        if authorised not in seen:
            seen.add(authorised)
            out.append(authorised)
    return out


def days_since_authorization(scope: Scope) -> Optional[int]:
    try:
        then = date.fromisoformat(scope.authorized_on)
    except ValueError:
        return None
    return (date.today() - then).days
