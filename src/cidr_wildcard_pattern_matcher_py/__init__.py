"""CIDR Wildcard Pattern Matcher.

Matches IP addresses against glob-style wildcard patterns used in legacy
firewall and access control configurations.
"""

from .core import compile_pattern, match, match_any

__all__ = ["compile_pattern", "match", "match_any"]
