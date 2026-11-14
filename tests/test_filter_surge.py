import importlib.util
from pathlib import Path
import re
import unittest

spec = importlib.util.spec_from_file_location("filter_surge", Path(__file__).resolve().parents[1] / "custom/filter_surge.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def evaluates(line, host):
    """Independent evaluator for emitted Surge syntax (domain + AND/NOT)."""
    kind, rest = line.split(",", 1)
    if kind in {"AND", "NOT"}:
        if not (rest.startswith("(") and rest.endswith(")")):
            raise AssertionError("Missing logical operand list")
        children, depth, start = [], 0, None
        for index, char in enumerate(rest[1:-1]):
            if char == "(":
                if depth == 0:
                    start = index + 1
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    children.append(rest[1:-1][start:index])
                if depth < 0:
                    raise AssertionError("Unbalanced rule")
            elif depth == 0 and char != ",":
                raise AssertionError("Unexpected text between operands")
        if depth or not children:
            raise AssertionError("Unbalanced or empty rule")
        if kind == "NOT":
            if len(children) != 1:
                raise AssertionError("NOT requires exactly one child")
            return not evaluates(children[0], host)
        return all(evaluates(child, host) for child in children)
    host, rest = host.lower(), rest.lower()
    if kind == "DOMAIN":
        return host == rest
    if kind == "DOMAIN-SUFFIX":
        return host == rest or host.endswith("." + rest)
    if kind == "DOMAIN-KEYWORD":
        return rest in host
    if kind == "DOMAIN-WILDCARD":
        pattern = re.escape(rest).replace(r"\*", ".*").replace(r"\?", ".")
        return re.fullmatch(pattern, host) is not None
    raise AssertionError(f"Unexpected rule: {line}")


class FilterTests(unittest.TestCase):
    def filtered(self, source, hosts):
        result, manifest = module.filter_rules(source, hosts, min_rules=1)
        return [line for line in result.splitlines() if not line.startswith("#")], manifest

    def test_remove_only_exact_domain_rule(self):
        rows, manifest = self.filtered("DOMAIN,ad.example.com\nDOMAIN,other.example.com", ["ad.example.com"])
        self.assertEqual(rows, ["DOMAIN,other.example.com"])
        self.assertEqual(manifest["output_rule_count"], 1)

    def test_suffix_keeps_children_and_siblings_blocked(self):
        rows, _ = self.filtered("DOMAIN-SUFFIX,example.com", ["ad.example.com"])
        self.assertFalse(evaluates(rows[0], "ad.example.com"))
        for host in ("example.com", "child.ad.example.com", "other.example.com"):
            self.assertTrue(evaluates(rows[0], host))
        self.assertFalse(evaluates(rows[0], "notexample.com"))

    def test_actual_suffix_is_not_removed(self):
        rows, _ = self.filtered("DOMAIN-SUFFIX,ad.zijieapi.com", ["ad.zijieapi.com"])
        self.assertEqual(rows, ["AND,((DOMAIN-SUFFIX,ad.zijieapi.com),(NOT,((DOMAIN,ad.zijieapi.com))))"])
        self.assertTrue(evaluates(rows[0], "child.ad.zijieapi.com"))
        self.assertFalse(evaluates(rows[0], "ad.zijieapi.com"))

    def test_actual_wildcard_remains_for_siblings(self):
        rows, _ = self.filtered("DOMAIN-WILDCARD,polaris*-normal-*.zijieapi.com", ["polaris5-normal-hl.zijieapi.com"])
        self.assertFalse(evaluates(rows[0], "polaris5-normal-hl.zijieapi.com"))
        for host in ("polaris3-normal-hl.zijieapi.com", "polaris5-normal-lf.zijieapi.com"):
            self.assertTrue(evaluates(rows[0], host))

    def test_all_overlapping_rules_are_filtered(self):
        source = "\n".join(("DOMAIN-SUFFIX,example.com", "DOMAIN-KEYWORD,ad.", "DOMAIN-WILDCARD,ad.*", "DOMAIN,ad.example.com"))
        rows, manifest = self.filtered(source, ["ad.example.com"])
        self.assertFalse(any(evaluates(row, "ad.example.com") for row in rows))
        self.assertEqual(manifest["matching_rules_per_host"]["ad.example.com"], 4)

    def test_multiple_exceptions_in_one_rule(self):
        rows, _ = self.filtered("DOMAIN-SUFFIX,example.com", ["a.example.com", "b.example.com"])
        for host in ("a.example.com", "b.example.com"):
            self.assertFalse(evaluates(rows[0], host))
        self.assertTrue(evaluates(rows[0], "c.example.com"))

    def test_unrelated_rules_and_notices_are_preserved(self):
        rows, manifest = self.filtered("# License: example\nDOMAIN-SUFFIX,tracker.test\n", ["ad.example.com"])
        self.assertEqual(rows, ["DOMAIN-SUFFIX,tracker.test"])
        self.assertEqual(manifest["changes"], [])
        text, _ = module.filter_rules("# License: example\nDOMAIN-SUFFIX,tracker.test\n", ["ad.example.com"], 1)
        self.assertIn("# Upstream: License: example", text)

    def test_reject_invalid_allowlist_and_upstream(self):
        for invalid in ("", "*.example.com", "DOMAIN,example.com", "https://example.com", "a.example\na.example"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                module.read_allowlist(invalid)
        for invalid in ("<html>error</html>", "FINAL", "DOMAIN,example.com,DIRECT", "DOMAIN,*.example.com", "DOMAIN-WILDCARD,[ab].example.com"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.filtered(invalid, ["ad.example.com"])

    def test_small_download_fails_closed(self):
        with self.assertRaises(ValueError):
            module.filter_rules("DOMAIN-SUFFIX,example.com", ["ad.example.com"])

    def test_normalize_allowlist(self):
        self.assertEqual(module.read_allowlist("# Note\n AD.Example.COM \n"), ["ad.example.com"])

    def test_unchanged_hosts_match_identically(self):
        source = "\n".join(("DOMAIN-SUFFIX,example.com", "DOMAIN-WILDCARD,ads?-*.test", "DOMAIN-KEYWORD,tracker"))
        allowed = ["ad.example.com", "ads1-video.test"]
        rows, _ = self.filtered(source, allowed)
        hosts = [f"{prefix}.{suffix}" for prefix in ("ad", "ads1-video", "child.ad", "tracker", "other") for suffix in ("example.com", "test", "other.net")]
        for host in hosts:
            with self.subTest(host=host):
                expected = host not in allowed and any(evaluates(row, host) for row in source.splitlines())
                self.assertEqual(any(evaluates(row, host) for row in rows), expected)


if __name__ == "__main__":
    unittest.main()
