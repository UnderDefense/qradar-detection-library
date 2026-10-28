#!/usr/bin/env python3
"""Refresh the generated parts of the README files from the rules under rules/.

Usage: python3 scripts/update_readme.py

- README.md: the rule count badges between <!-- badges:start --> and <!-- badges:end -->.
- rules/<pack>/README.md: the pack overview between <!-- pack:start --> and <!-- pack:end -->
  (rules, log source types, custom properties, reference sets, what the console needs).
  Text outside the markers is kept; a missing README is created.
"""
import re
import sys
import urllib.parse
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
RULES = ROOT / "rules"
IDS = ROOT / "static" / "qradar-ids.yml"
EXTENSION_RULES = ROOT / "static" / "qradar-extension-rules.yml"
BADGES = ("<!-- badges:start -->", "<!-- badges:end -->")
PACK = ("<!-- pack:start -->", "<!-- pack:end -->")
CUSTOM_SUFFIX = " (custom)"

# Log source of each pack folder: badge label and colour. Unknown folders use the folder name.
PACKS = {
    "cloud/o365": ("Microsoft Office 365", "0078D4"),
    "cloud/entraid": ("Microsoft Entra ID", "0078D4"),
    "endpoints/ad": ("Active Directory", "00A4EF"),
    "endpoints/sysmon": ("Sysmon", "00A4EF"),
    "endpoints/windows": ("Windows Security Event Log", "00A4EF"),
    "network/firewall": ("Fortinet FortiGate", "EE3124"),
}


def badge(label, message, color):
    def part(text):
        # shields.io static badges: "-" is written "--", "_" is written "__".
        return urllib.parse.quote(text.replace("-", "--").replace("_", "__"))
    return f"![{label}: {message}](https://img.shields.io/badge/{part(label)}-{part(message)}-{color})"


def plural(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


def load_packs():
    packs = {}
    for path in sorted(RULES.rglob("*.y*ml")):
        if path.name == "reference-data.yml":
            continue
        pack = "/".join(path.relative_to(RULES).parts[:-1])
        packs.setdefault(pack, []).append(yaml.safe_load(path.read_text(encoding="utf-8")))
    return packs


def replace_block(text, markers, body, where):
    start, end = markers
    new, n = re.subn(re.escape(start) + r".*?" + re.escape(end), f"{start}\n{body}\n{end}", text, flags=re.S)
    if n != 1:
        sys.exit(f"{where} needs exactly one {start} ... {end} block")
    return new


def update_main(packs):
    count = {p: (sum(not r.get("building_block") for r in rs), sum(bool(r.get("building_block")) for r in rs))
             for p, rs in packs.items()}
    total_rules = sum(r for r, _ in count.values())
    total_bbs = sum(b for _, b in count.values())
    lines = [" ".join([
        badge("rules", str(total_rules), "2E7D32"),
        badge("building blocks", str(total_bbs), "2E7D32"),
        badge("log sources", str(len(packs)), "2E7D32"),
    ]), ""]
    pills = []
    for pack in sorted(count, key=lambda p: PACKS.get(p, (p,))[0]):
        rules, bbs = count[pack]
        label, color = PACKS.get(pack, (pack, "555555"))
        message = plural(rules, "rule") + (f", {plural(bbs, 'BB')}" if bbs else "")
        pills.append(f"[{badge(label, message, color)}](rules/{pack})")
    lines.append(" ".join(pills))
    README.write_text(replace_block(README.read_text(encoding="utf-8"), BADGES, "\n".join(lines), "README.md"),
                      encoding="utf-8")
    print(f"README.md: {total_rules} rules, {total_bbs} building blocks, {len(packs)} log sources")


def walk_tests(rule):
    for t in rule.get("tests", []):
        yield t


def properties_of(rule):
    """Custom properties the structured tests, actions and limiter use; names that AQL tests quote."""
    custom, aql = set(), set()
    def add(name):
        if isinstance(name, str) and name.endswith(CUSTOM_SUFFIX):
            custom.add(name)
    for t in walk_tests(rule):
        for f in t.get("filters", []):
            add(f["property"])
        for name in t.get("properties", []) + t.get("distinct_properties", []):
            add(name)
        if t["type"] == "aql":
            aql.update(re.findall(r'"([^"]+)"', re.sub(r"'(?:[^']|'')*'", "''", t["filter"])))
    for section in (rule.get("action", {}).get("offense"), rule.get("response", {}).get("new_event", {}).get("offense")):
        add((section or {}).get("index_on"))
    add(rule.get("limiter", {}).get("per_property"))
    return custom, aql


def rule_row(rule):
    kind = "BB" if rule.get("building_block") else "Rule"
    severity = (rule.get("action", {}).get("severity") or {}).get("set") \
        or rule.get("response", {}).get("new_event", {}).get("severity")
    mitre = ", ".join(rule.get("mitre") or []) or "-"
    name = rule["name"].replace("|", "\\|")
    return f"| {name} | {kind} | {severity if severity is not None else '-'} | {mitre} |"


def pack_body(pack, rules, ids, extension_rules):
    names = {r["name"] for r in rules}
    log_sources, custom, aql, sets, needs = set(), set(), set(), set(), {}
    for rule in rules:
        c, a = properties_of(rule)
        custom |= c
        aql |= a
        for t in walk_tests(rule):
            if t["type"] == "log_source_type" and not t.get("negate"):
                log_sources.update(t["log_source_types"])
            sets.update(t.get("reference_sets", []))
            for ref in t.get("rules", []) if t["type"] in ("rule", "rule_threshold") else []:
                if ref in names or ref in (ids.get("system_rules") or {}):
                    continue
                for extension, ext_rules in extension_rules.items():
                    if ref in ext_rules:
                        needs.setdefault(extension, set()).add(ref)
        for key in ("add_to_reference_set", "remove_from_reference_set"):
            if key in rule.get("response", {}):
                sets.add(rule["response"][key]["reference_set"])
    aql -= {p[: -len(CUSTOM_SUFFIX)] for p in custom}

    out = [f"{plural(sum(not r.get('building_block') for r in rules), 'rule')}, "
           f"{plural(sum(bool(r.get('building_block')) for r in rules), 'Building Block')}.", ""]
    out += ["**Log source types:** " + (", ".join(sorted(log_sources)) or "none; the rules select events by name"), ""]
    out += ["| Rule | Type | Severity | MITRE ATT&CK |", "|---|---|---|---|"]
    out += [rule_row(r) for r in sorted(rules, key=lambda r: (bool(r.get("building_block")), r["name"]))]
    if custom:
        out += ["", "**Custom properties** the console must have:", ""]
        out += [f"- {p}" for p in sorted(custom)]
    if aql:
        out += ["", "**Properties in AQL filters** (custom or built-in): " + ", ".join(sorted(aql))]
    if sets:
        out += ["", "**Reference sets** (created empty by the extension unless `reference-data.yml` fills them):", ""]
        out += [f"- {s}" for s in sorted(sets)]
    if needs:
        out += ["", "**IBM content extensions** the console must have:", ""]
        out += [f"- {e}: {', '.join(sorted(rs))}" for e, rs in sorted(needs.items())]
    return "\n".join(out)


def update_packs(packs):
    ids = yaml.safe_load(IDS.read_text(encoding="utf-8")) or {}
    extension_rules = (yaml.safe_load(EXTENSION_RULES.read_text(encoding="utf-8")) or {}).get("extension_rules", {})
    for pack, rules in sorted(packs.items()):
        path = RULES / pack / "README.md"
        if not path.exists():
            title = PACKS.get(pack, (pack,))[0]
            path.write_text(f"# {title}\n\n{PACK[0]}\n{PACK[1]}\n", encoding="utf-8")
        text = replace_block(path.read_text(encoding="utf-8"), PACK, pack_body(pack, rules, ids, extension_rules),
                             str(path.relative_to(ROOT)))
        path.write_text(text, encoding="utf-8")
        print(f"{path.relative_to(ROOT)}: {len(rules)} rules and BBs")


def main():
    packs = load_packs()
    update_main(packs)
    update_packs(packs)


if __name__ == "__main__":
    main()
