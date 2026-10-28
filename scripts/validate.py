#!/usr/bin/env python3
"""Validate QRadar rule YAML files against static/rule-schema.json,
and reference-data.yml files against static/reference-data-schema.json.

Usage: python3 scripts/validate.py [PATH ...]   (default: rules examples)
Exits with 1 if any file is invalid.
"""
import json
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "static" / "rule-schema.json"
REFERENCE_DATA_SCHEMA = ROOT / "static" / "reference-data-schema.json"
# A log source folder may hold one file of reference data next to its rules.
REFERENCE_DATA_FILE = "reference-data.yml"


class RuleLoader(yaml.SafeLoader):
    """SafeLoader that keeps dates as strings, so `created: 2026-10-26` validates as format: date."""


RuleLoader.yaml_implicit_resolvers = {
    ch: [(tag, rx) for tag, rx in resolvers if tag != "tag:yaml.org,2002:timestamp"]
    for ch, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def rule_files(paths):
    for p in paths:
        p = Path(p)
        if p.is_file():
            yield p
        else:
            yield from sorted(f for f in p.rglob("*") if f.suffix in (".yml", ".yaml"))


def location(error):
    loc = ""
    for part in error.absolute_path:
        loc += f"[{part}]" if isinstance(part, int) else f".{part}"
    return loc.lstrip(".") or "<root>"


def message(error):
    # `errorMessage` is a yaml-language-server keyword; reuse it so CLI and editor say the same thing.
    return error.schema.get("errorMessage", error.message)


def main(argv):
    validator, reference_data_validator = (
        Draft202012Validator(json.loads(s.read_text()), format_checker=Draft202012Validator.FORMAT_CHECKER)
        for s in (SCHEMA, REFERENCE_DATA_SCHEMA)
    )
    seen = {"name": {}, "id": {}}
    failed = 0
    files = list(rule_files(argv or [ROOT / "rules", ROOT / "examples"]))

    for path in files:
        rel = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
        try:
            rule = yaml.load(path.read_text(encoding="utf-8"), Loader=RuleLoader)
        except yaml.YAMLError as e:
            print(f"FAIL {rel}\n  YAML: {e}")
            failed += 1
            continue

        if path.name == REFERENCE_DATA_FILE:
            errors = sorted(reference_data_validator.iter_errors(rule), key=lambda e: list(e.absolute_path))
            names = [s.get("name") for s in (rule or {}).get("reference_sets", []) if isinstance(s, dict)]
            errors += [f"reference_sets: duplicate name '{n}'" for n in sorted({n for n in names if names.count(n) > 1})]
        else:
            errors = sorted(validator.iter_errors(rule), key=lambda e: list(e.absolute_path))
        if isinstance(rule, dict) and path.name != REFERENCE_DATA_FILE:
            for key in seen:
                value = rule.get(key)
                if value in seen[key]:
                    errors.append(f"{key}: duplicate '{value}', also in {seen[key][value]}")
                elif value is not None:
                    seen[key][value] = rel

        if errors:
            failed += 1
            print(f"FAIL {rel}")
            for e in errors:
                print(f"  {e}" if isinstance(e, str) else f"  {location(e)}: {message(e)}")
        else:
            print(f"ok   {rel}")

    print(f"\n{len(files) - failed}/{len(files)} valid")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
