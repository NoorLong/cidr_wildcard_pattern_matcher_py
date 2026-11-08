"""Core matching logic for CIDR wildcard patterns.

A pattern is a dotted string of four octets separated by dots. Each octet is
either a decimal number 0-255 or the wildcard ``*``. The wildcard ``*``
matches any single octet, not a range of octets. This matches the behaviour of
legacy systems such as Cisco ACL wildcard masks when written in dotted form.

The pattern is compiled into a tuple of four elements, each being either an
int or ``None`` for a wildcard. Matching is a simple positional comparison.
"""

from __future__ import annotations

import ipaddress

__all__ = ["compile_pattern", "match", "match_any"]


def compile_pattern(pattern: str) -> tuple[int | None, ...]:
    """Compile a dotted wildcard pattern into a tuple of four octets.

    Each element is an ``int`` in 0-255 or ``None`` for a wildcard ``*``.
    Raises ``ValueError`` if the pattern is not exactly four dot-separated
    octets, or if any octet is neither ``*`` nor a decimal 0-255.

    The compiled form is deliberately a plain tuple so it is hashable and
    cheap to compare; callers that match many addresses against one pattern
    should compile once and reuse.
    """
    if not isinstance(pattern, str):
        raise TypeError("pattern must be a string")

    parts = pattern.split(".")
    if len(parts) != 4:
        raise ValueError(
            f"pattern must have exactly 4 octets, got {len(parts)}: {pattern!r}"
        )

    compiled: list[int | None] = []
    for part in parts:
        if part == "*":
            compiled.append(None)
            continue
        # Reject empty strings, leading '+', whitespace, etc. int() would
        # accept "+1" and " 1"; we want strict decimal digits only.
        if not part.isdigit():
            raise ValueError(
                f"octet must be '*' or a decimal 0-255, got {part!r}"
            )
        value = int(part)
        if value < 0 or value > 255:
            raise ValueError(f"octet out of range 0-255: {part!r}")
        compiled.append(value)

    return tuple(compiled)


def _parse_ip(ip: str) -> tuple[int, int, int, int]:
    """Parse an IPv4 address string into a 4-tuple of ints.

    We use the standard library ``ipaddress`` module rather than splitting on
    dots ourselves so that IPv6 addresses, leading zeros, and other malformed
    inputs are rejected consistently. ``ipaddress`` accepts IPv6, so we
    explicitly require version 4.
    """
    if not isinstance(ip, str):
        raise TypeError("ip must be a string")
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {ip!r}") from exc
    if addr.version != 4:
        raise ValueError(f"only IPv4 addresses are supported, got {ip!r}")
    # ``packed`` is four bytes in network order.
    return tuple(addr.packed)  # type: ignore[return-value]


def match(ip: str, pattern: str) -> bool:
    """Return True if *ip* matches the dotted wildcard *pattern*.

    *ip* must be a valid IPv4 address string. *pattern* is compiled on every
    call; use :func:`compile_pattern` plus a manual comparison if you are
    matching a large number of addresses against the same pattern.
    """
    compiled = compile_pattern(pattern)
    return _match_compiled(ip, compiled)


def _match_compiled(ip: str, compiled: tuple[int | None, ...]) -> bool:
    octets = _parse_ip(ip)
    for expected, actual in zip(compiled, octets):
        if expected is None:
            continue
        if expected != actual:
            return False
    return True


def match_any(ip: str, patterns: list[str] | tuple[str, ...]) -> bool:
    """Return True if *ip* matches at least one pattern in *patterns*.

    Patterns are compiled once up front, so this is the efficient entry point
    when an address must be checked against a rule set. An empty sequence
    returns False.
    """
    if not isinstance(patterns, (list, tuple)):
        raise TypeError("patterns must be a list or tuple")
    compiled = [compile_pattern(p) for p in patterns]
    return any(_match_compiled(ip, c) for c in compiled)
