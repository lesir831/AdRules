# Filtered AdRules for Surge

Automatically derived from [Cats-Team/AdRules](https://github.com/Cats-Team/AdRules), with a small exact-host allowlist. This is an independent fork, not an official upstream release.

## Subscribe

```text
https://raw.githubusercontent.com/lesir831/AdRules/filtered/adrules-surge.conf
```

Use this as a Surge **RULE-SET**, not a DOMAIN-SET. `REJECT`, `extended-matching`, and `pre-matching` may remain enabled on the reference. Requires a Surge version with AND/NOT logical-rule support.

## Exceptions and updates

- [Editable allowlist](https://github.com/lesir831/AdRules/blob/script/custom/surge-allowlist.txt)
- [Filter code](https://github.com/lesir831/AdRules/blob/script/custom/filter_surge.py)
- [Actions](https://github.com/lesir831/AdRules/actions/workflows/filter-surge.yml)
- [Build manifest](manifest.json): exact upstream commit, source commit, SHA-256 hashes, counts, and every changed rule.

The Action runs every six hours, on filter/allowlist changes, and on manual dispatch. It reads the latest generated upstream rules without executing upstream scripts. Failed downloads, unexpected rule syntax, and unexpectedly small inputs stop publication, preserving the last successful output. Scheduled Actions in inactive public forks may be disabled by GitHub after 60 days; check the workflow if updates stop.

Exceptions apply only to full hostnames in the allowlist. A matching `DOMAIN` entry is removed. A matching suffix, keyword, or wildcard rule is retained inside `AND(original, NOT(exact hostname))` so sibling hosts and subdomains stay blocked. This also handles DNS pre-matching, which ordinary top-of-list DIRECT rules cannot override. Other rule sets, modules, or DNS services can still block an allowed hostname independently.

To add an exception, edit `custom/surge-allowlist.txt` on `script` and run **Filter Surge Rules**. Do not edit this generated branch by hand.

## Attribution and licensing

Upstream is **Cats-Team/AdRules**. Original rule notices are retained as upstream comments. The merged rule data retains the licenses of its upstream authors; it is not relicensed under the filter code's 0BSD license. See [Source.md](Source.md), [upstream source attribution](https://github.com/Cats-Team/AdRules/blob/script/Source.md), and upstream's README for source licenses. The copied source list reflects this fork's source revision; consult upstream for later additions. Exact input/output revisions and hashes are recorded in `manifest.json`.
