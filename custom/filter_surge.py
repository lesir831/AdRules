#!/usr/bin/env python3
"""Filter an upstream Surge rule-set without broadening exact-host exceptions."""

import argparse
import fnmatch
import hashlib
import json
from pathlib import Path
import re

TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD"}
HOST = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
PATTERN = re.compile(r"[a-z0-9.*?-]+\Z")


def read_allowlist(text):
    hosts = []
    for number, raw in enumerate(text.splitlines(), 1):
        host = raw.strip().lower()
        if not host or host.startswith("#"):
            continue
        if not HOST.fullmatch(host):
            raise ValueError(f"Invalid exact hostname on allowlist line {number}")
        if host in hosts:
            raise ValueError(f"Duplicate allowlist hostname: {host}")
        hosts.append(host)
    if not hosts:
        raise ValueError("Allowlist must not be empty")
    return hosts


def parse_rule(line):
    parts = [p.strip() for p in line.split(",")]
    if len(parts) != 2 or parts[0] not in TYPES:
        raise ValueError(f"Unsupported upstream rule: {line[:160]}")
    kind, pattern = parts[0], parts[1].lower()
    if not PATTERN.fullmatch(pattern):
        raise ValueError(f"Invalid domain pattern: {line[:160]}")
    if kind != "DOMAIN-WILDCARD" and any(c in pattern for c in "*?"):
        raise ValueError(f"Unexpected wildcard: {line[:160]}")
    if kind in {"DOMAIN", "DOMAIN-SUFFIX"} and not HOST.fullmatch(pattern):
        raise ValueError(f"Invalid domain: {line[:160]}")
    return kind, pattern


def matches(rule, hostname):
    kind, pattern = rule
    hostname = hostname.lower()
    if kind == "DOMAIN":
        return hostname == pattern
    if kind == "DOMAIN-SUFFIX":
        return hostname == pattern or hostname.endswith("." + pattern)
    if kind == "DOMAIN-KEYWORD":
        return pattern in hostname
    if kind == "DOMAIN-WILDCARD":
        return fnmatch.fnmatchcase(hostname, pattern)
    raise ValueError(f"Unknown rule type: {kind}")


def filter_rules(text, hosts, min_rules=10000):
    output = [
        "# AdRules: exact-host exceptions for Surge",
        "# Upstream: https://github.com/Cats-Team/AdRules (main)",
        "# See manifest.json for the pinned upstream revision and every change.",
        "# Requires Surge logical-rule support; keep REJECT and pre-matching on the reference.",
    ]
    changes = []
    count = 0
    hits = {host: 0 for host in hosts}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "!")):
            # Preserve upstream notices and counts, marked as upstream metadata.
            if line:
                output.append("# Upstream: " + line.lstrip("#! "))
            continue
        rule = parse_rule(line)
        count += 1
        excluded = [host for host in hosts if matches(rule, host)]
        if not excluded:
            output.append(raw)
            continue
        for host in excluded:
            hits[host] += 1
        if rule[0] == "DOMAIN":
            replacement = None
        else:
            # A deleted suffix/wildcard would also unblock subdomains/siblings.
            # Instead, keep the original match AND NOT each exact allowed host.
            operands = [f"({line})"]
            operands.extend(f"(NOT,((DOMAIN,{host})))" for host in excluded)
            replacement = "AND,(" + ",".join(operands) + ")"
            output.append(replacement)
        changes.append({"original": line, "replacement": replacement, "excluded_hosts": excluded})
    if count < min_rules:
        raise ValueError(f"Upstream is unexpectedly small: {count} rules; expected >= {min_rules}")
    return "\n".join(output) + "\n", {
        "input_rule_count": count,
        "output_rule_count": count - sum(c["replacement"] is None for c in changes),
        "allowlist": hosts,
        "matching_rules_per_host": hits,
        "changes": changes,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--allowlist", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--upstream-sha", required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    for value in (args.upstream_sha, args.source_sha):
        if not re.fullmatch(r"[0-9a-f]{40}", value):
            parser.error("Revisions must be full 40-character commit hashes")
    source = args.input.read_bytes()
    hosts = read_allowlist(args.allowlist.read_text(encoding="utf-8"))
    result, manifest = filter_rules(source.decode("utf-8"), hosts)
    manifest.update({
        "upstream_repository": "Cats-Team/AdRules",
        "upstream_sha": args.upstream_sha,
        "source_sha": args.source_sha,
        "upstream_sha256": hashlib.sha256(source).hexdigest(),
        "output_sha256": hashlib.sha256(result.encode()).hexdigest(),
    })
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(result, encoding="utf-8")
    args.manifest.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
