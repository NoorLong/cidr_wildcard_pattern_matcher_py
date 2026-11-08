"""Tests for the CIDR wildcard pattern matcher."""

import unittest

from cidr_wildcard_pattern_matcher_py import compile_pattern, match, match_any


class CompilePatternTests(unittest.TestCase):
    def test_compiles_literal_octets(self):
        self.assertEqual(compile_pattern("192.168.1.1"), (192, 168, 1, 1))

    def test_compiles_wildcards(self):
        self.assertEqual(compile_pattern("*.*.*.*"), (None, None, None, None))

    def test_compiles_mixed(self):
        self.assertEqual(compile_pattern("10.0.*.*"), (10, 0, None, None))

    def test_rejects_wrong_octet_count(self):
        with self.assertRaises(ValueError):
            compile_pattern("192.168.1")
        with self.assertRaises(ValueError):
            compile_pattern("192.168.1.1.1")

    def test_rejects_non_numeric_octet(self):
        with self.assertRaises(ValueError):
            compile_pattern("192.168.one.1")

    def test_rejects_out_of_range_octet(self):
        with self.assertRaises(ValueError):
            compile_pattern("192.168.1.256")
        with self.assertRaises(ValueError):
            compile_pattern("300.0.0.1")

    def test_rejects_empty_octet(self):
        with self.assertRaises(ValueError):
            compile_pattern("192..1.1")

    def test_rejects_plus_sign(self):
        # int("+1") is 1, but legacy configs use plain decimal digits.
        with self.assertRaises(ValueError):
            compile_pattern("+1.0.0.1")

    def test_rejects_non_string(self):
        with self.assertRaises(TypeError):
            compile_pattern(192)  # type: ignore[arg-type]


class MatchTests(unittest.TestCase):
    def test_exact_match(self):
        self.assertTrue(match("192.168.1.1", "192.168.1.1"))

    def test_exact_mismatch(self):
        self.assertFalse(match("192.168.1.2", "192.168.1.1"))

    def test_wildcard_in_last_octet(self):
        self.assertTrue(match("192.168.1.42", "192.168.1.*"))
        self.assertFalse(match("192.168.2.42", "192.168.1.*"))

    def test_wildcard_in_multiple_octets(self):
        self.assertTrue(match("10.20.30.40", "10.*.*.40"))
        self.assertFalse(match("10.20.30.41", "10.*.*.40"))

    def test_all_wildcards(self):
        self.assertTrue(match("0.0.0.0", "*.*.*.*"))
        self.assertTrue(match("255.255.255.255", "*.*.*.*"))

    def test_wildcard_does_not_span_octets(self):
        # ``*`` matches exactly one octet, so a 3-octet pattern is invalid
        # and a 4-octet pattern cannot match a 5-octet string.
        with self.assertRaises(ValueError):
            match("10.0.0.1", "10.*.*")

    def test_invalid_ip_raises(self):
        with self.assertRaises(ValueError):
            match("not-an-ip", "*.*.*.*")

    def test_ipv6_rejected(self):
        with self.assertRaises(ValueError):
            match("::1", "*.*.*.*")

    def test_leading_zero_ip_rejected(self):
        # ipaddress rejects "010.0.0.1" because of the ambiguous octal form.
        with self.assertRaises(ValueError):
            match("010.0.0.1", "10.0.0.1")


class MatchAnyTests(unittest.TestCase):
    def test_matches_first(self):
        self.assertTrue(match_any("10.0.0.1", ["10.0.0.1", "192.168.1.1"]))

    def test_matches_second(self):
        self.assertTrue(match_any("192.168.1.1", ["10.0.0.1", "192.168.1.1"]))

    def test_matches_none(self):
        self.assertFalse(match_any("172.16.0.1", ["10.0.0.1", "192.168.1.1"]))

    def test_empty_list(self):
        self.assertFalse(match_any("10.0.0.1", []))

    def test_invalid_pattern_propagates(self):
        with self.assertRaises(ValueError):
            match_any("10.0.0.1", ["10.0.0.1", "bad.pattern"])

    def test_accepts_tuple(self):
        self.assertTrue(match_any("10.0.0.1", ("10.0.0.1",)))

    def test_rejects_non_sequence(self):
        with self.assertRaises(TypeError):
            match_any("10.0.0.1", "10.0.0.1")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
