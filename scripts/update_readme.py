#!/usr/bin/env python3
"""Refresh the rule count badges in README.md from the files under rules/.

Usage: python3 scripts/update_readme.py
Rewrites the part of README.md between <!-- badges:start --> and <!-- badges:end -->.
"""
import re
import sys
import urllib.parse
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
START, END = "<!-- badges:start -->", "<!-- badges:end -->"

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


def counts():
    packs = {}
    for path in sorted((ROOT / "rules").rglob("*.y*ml")):
        if path.name == "reference-data.yml":
            continue
        pack = "/".join(path.relative_to(ROOT / "rules").parts[:-1])
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        rules, bbs = packs.setdefault(pack, [0, 0])
        packs[pack] = [rules, bbs + 1] if rule.get("building_block") else [rules + 1, bbs]
    return packs


def main():
    packs = counts()
    total_rules = sum(r for r, _ in packs.values())
    total_bbs = sum(b for _, b in packs.values())
    lines = [
        " ".join([
            badge("rules", str(total_rules), "2E7D32"),
            badge("building blocks", str(total_bbs), "2E7D32"),
            badge("log sources", str(len(packs)), "2E7D32"),
        ]),
        "",
    ]
    pills = []
    for pack, (rules, bbs) in sorted(packs.items(), key=lambda p: PACKS.get(p[0], (p[0],))[0]):
        label, color = PACKS.get(pack, (pack, "555555"))
        message = plural(rules, "rule") + (f", {plural(bbs, 'BB')}" if bbs else "")
        pills.append(badge(label, message, color))
    lines.append(" ".join(pills))

    text = README.read_text(encoding="utf-8")
    block = f"{START}\n" + "\n".join(lines) + f"\n{END}"
    new, n = re.subn(re.escape(START) + r".*?" + re.escape(END), block, text, flags=re.S)
    if n != 1:
        sys.exit(f"README.md needs exactly one {START} ... {END} block")
    README.write_text(new, encoding="utf-8")
    print(f"{total_rules} rules, {total_bbs} building blocks, {len(packs)} log sources")


if __name__ == "__main__":
    main()
