# cidr_wildcard_pattern_matcher_py

Match IPv4 addresses against glob-style wildcard patterns such as
`192.168.*.*`, the dotted form used by legacy firewall and access control
configurations.

```python
from cidr_wildcard_pattern_matcher_py import match, match_any, compile_pattern

match("192.168.1.42", "192.168.1.*")       # True
match("192.168.2.42", "192.168.1.*")       # False
match_any("10.0.0.5", ["10.0.0.1", "10.*.*.*"])  # True

# Compile once when matching many addresses against the same pattern.
pattern = compile_pattern("172.16.*.*")
# pattern is (172, 16, None, None)
```

## Why this exists

Legacy firewall rule sets are frequently written with a dotted wildcard mask
rather than CIDR notation, and the two are not the same thing. A CIDR block
like `192.168.0.0/16` covers a contiguous range, while `192.168.*.*` is a
positional pattern: it matches any value in the third and fourth octets but
demands exactly `192` and `168` in the first two. The trade-off made here is
deliberately narrow: this library implements the dotted-wildcard reading only,
with `*` matching exactly one octet. It does not attempt to interpret the
pattern as a CIDR block, and it does not support partial-octet wildcards such
as `192.168.1.4*`.

## Edge cases you will hit

Every octet must be either `*` or a decimal value from 0 to 255. A pattern
with the wrong number of octets, a non-numeric octet, or an out-of-range
value raises `ValueError` at compile time. Addresses are parsed with the
standard library `ipaddress` module, so IPv6 addresses and ambiguous forms
such as `010.0.0.1` are rejected rather than silently reinterpreted.

`match_any` compiles every pattern in the sequence before testing any of them,
so a single malformed pattern raises `ValueError` even if an earlier pattern
would have matched.

## Design notes

The window stores values eagerly rather than keeping running aggregates. Running
sums drift with floating point over long streams, and recomputing from a small
buffer is cheap enough that the drift is not worth the speed.

## Limitations

Values are coerced to floats, so very large integers lose precision. If you need
exact integer aggregates over a window, this is the wrong tool.

