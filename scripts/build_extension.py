#!/usr/bin/env python3
"""Build a QRadar content extension from a log source folder of rule YAML files.

Usage: python3 scripts/build_extension.py FOLDER [FOLDER ...] --qids QID_RECORDS.json [--out dist] [--ids FILE]
       e.g. python3 scripts/build_extension.py rules/endpoints/sysmon

Each folder becomes one extension: dist/<folder path joined by '-'>.zip
(rules/endpoints/sysmon -> dist/endpoints-sysmon.zip). A reference-data.yml in the
folder adds reference sets, with or without elements, to the extension.

Rules name events (QID tests, Event Name filters) as the Rule Wizard shows them. QIDs can be
custom and differ per console, so the builder looks them up in the target console's QID records:
  curl -sk -H "SEC: $TOKEN" -H "Range: items=0-499999" \
    "https://$QRADAR/api/data_classification/qid_records?fields=qid,name,log_source_type_id" > qids.json

XML pieces live in static/extension/ and follow a Use Case Manager export of a
QRadar 7.5 rule and the IBM QRadar Endpoint Content Extension. Numeric IDs in the
extension are local to the file: import maps them to the console's own objects by
their identifiers. A rule part with no known XML form, or a name with no entry in
static/qradar-ids.yml, stops the build and is listed, so nothing is guessed.
"""
import argparse
import base64
import json
import re
import sys
import urllib.parse
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

import yaml
from jsonschema import Draft202012Validator

from validate import (REFERENCE_DATA_FILE, REFERENCE_DATA_SCHEMA, ROOT, SCHEMA, RuleLoader, location,
                      message)

TEMPLATES = ROOT / "static" / "extension"
IDS = ROOT / "static" / "qradar-ids.yml"
EXTENSION_RULES = ROOT / "static" / "qradar-extension-rules.yml"
# qradarversion of the latest Use Case Manager export the templates were checked against.
DEFAULT_QRADAR_VERSION = "2021.6.16.20260817115410"
RULE_ID_BASE = 200000
FGROUP_ID_BASE = 88000
REFERENCE_SET_ID_BASE = 1000
# Reference sets get a UUID derived from their name, so every build of a set carries the same one.
REFERENCE_SET_UUID_NAMESPACE = uuid.UUID("5b1e8f0c-3d2a-4c6e-9f7b-2a8d4e6c1b90")
# reference_data_key.domain_info of every key in IBM extensions.
ALL_DOMAINS = 2147483647
# QIDs for dispatched events: QID_BASE + rule UUID mod QID_SPAN, so a rebuild keeps the same QID.
# IBM extensions ship their dispatched events in the same 675xxxxx range.
# TODO: confirm on the test console how import treats a QID that already exists.
QID_BASE = 67600000
QID_SPAN = 100000

# Search filter encoding: fields of a filter and filters are joined by U+E000,
# values by U+FFFD; "is N/A" tests carry the value $_NULL_$.
FIELD_SEP = "\ue000"
VALUE_SEP = "\ufffd"
NULL_VALUE = "$_NULL_$"
FILTER_OPS = {
    "is": "EQ",
    "is_not": "NEQ",
    "greater_than": "GT",
    "greater_than_or_equal": "GE",
    "less_than_or_equal": "LE",
    "is_any_of": "EQany",
    "is_not_any_of": "NEQany",
    "contains_any_of": "CONany",
    "matches_any_of": "REXany",
    "not_matches_any_of": "NREXany",
    "is_na": "ENA",
    "is_not_na": "NENA",
}
CUSTOM_SUFFIX = " (custom)"
UNITS = {"minutes": "m", "hours": "h", "days": "d"}
CONTEXTS = {"local_to_local": "l2l", "local_to_remote": "l2r", "remote_to_local": "r2l", "remote_to_remote": "r2r"}
THRESHOLD_FIELDS = {
    "username": "UserName", "source IP": "SourceIP", "source port": "SourcePort",
    "destination IP": "DestinationIP", "destination port": "DestinationPort", "QID": "Qid",
    "event ID": "DeviceEventID", "log source": "DeviceId", "category": "Category",
}
NAMING = {  # newevent: (overrideOffenseName, contributeOffenseName)
    "set_or_replace": ("true", "false"),
    "contribute": ("false", "true"),
    "not_contribute": ("false", "false"),
}
# UD rules exported from QRadar set or replace the offense name.
DEFAULT_NAMING = "set_or_replace"
REFERENCE_SET_NAME = re.compile(r"^(?P<name>.+) - (?P<type>IP|CIDR|Port|Numeric|Date|AlphaNumeric(?: \(Ignore Case\))?)$")


class Missing(Exception):
    """A template or a QRadar ID the build needs is not there yet."""


class Pack:
    """What the rules of one extension share: QRadar IDs and objects to ship with them."""

    def __init__(self, ids, rule_uuids, reference_data, qids):
        self.ids = ids
        self.qids = qids              # event name -> [(qid, log source type id)], or None
        self.rule_log_source_types = set()
        self.rule_uuids = rule_uuids
        self.defined_sets = {s["name"]: s for s in reference_data.get("reference_sets", [])}
        self.offense_types = {}   # name -> definition
        self.reference_sets = {}  # name -> {"id", "element_type", "values"}
        self.set_users = set()    # (rule id, reference set id)
        self.required_extensions = set()
        self.rule_id = None       # rule being rendered

    def lookup(self, kind, name):
        try:
            return self.ids[kind][name]
        except (KeyError, TypeError):
            raise Missing(f"{kind} '{name}' in the IDs file") from None

    def property_key(self, kind, name):
        if name.endswith(CUSTOM_SUFFIX):
            return name[: -len(CUSTOM_SUFFIX)]
        try:
            return self.ids["properties"][kind][name]
        except (KeyError, TypeError):
            raise Missing(f"properties.{kind} '{name}' in the IDs file") from None

    def offense_type_definition(self, name):
        definition = self.lookup("offense_types", name)
        self.offense_types[name] = definition
        return definition

    def offense_type(self, name):
        return self.offense_type_definition(name)["id"]

    def add_reference_set(self, name, set_type, values=()):
        if name not in self.reference_sets:
            self.reference_sets[name] = {
                "id": REFERENCE_SET_ID_BASE + len(self.reference_sets),
                "element_type": self.lookup("reference_set_types", set_type),
                "values": list(values),
            }
        return self.reference_sets[name]["id"]

    def reference_set(self, label):
        m = REFERENCE_SET_NAME.match(label)
        if not m:
            raise Missing(f"type suffix (' - IP', ' - CIDR', ' - AlphaNumeric', ...) on reference set '{label}'")
        defined = self.defined_sets.get(m["name"])
        if defined and defined["type"] != m["type"]:
            raise Missing(f"one type for reference set '{m['name']}': {REFERENCE_DATA_FILE} says "
                          f"{defined['type']}, a rule says {m['type']}")
        set_id = self.add_reference_set(m["name"], m["type"])
        self.set_users.add((self.rule_id, set_id))
        return set_id

    def qid(self, name):
        """QIDs of an event name on the target console, narrowed to the rule's log source types."""
        if self.qids is None:
            raise Missing("--qids file with the console's QID records (rules name events)")
        found = self.qids.get(name)
        if not found:
            raise Missing(f"event '{name}' in the QID records")
        if self.rule_log_source_types:
            found = [f for f in found if f[1] in self.rule_log_source_types]
            if not found:
                raise Missing(f"event '{name}' for the rule's log source types in the QID records")
        elif len({f[1] for f in found}) > 1:
            raise Missing(f"log source type test to tell apart event '{name}' (several log source types)")
        return sorted({f[0] for f in found})

    def rule_uuid(self, name):
        """Rules of this pack, then rules of QRadar (SYSTEM-nnnn) and of IBM extensions."""
        if name in self.rule_uuids:
            return self.rule_uuids[name]
        if name in (self.ids.get("system_rules") or {}):
            return self.ids["system_rules"][name]
        for extension, rules in (self.ids.get("extension_rules") or {}).items():
            if name in rules:
                self.required_extensions.add(extension)
                return rules[name]
        raise Missing(f"rule '{name}' in this pack, system_rules or extension_rules (tests refer to rules by UUID)")


def template(name):
    path = TEMPLATES / name
    if not path.is_file():
        raise Missing(f"template static/extension/{name}")
    return path.read_text(encoding="utf-8")


def encode_uri_component(text):
    # JavaScript encodeURIComponent, except that QRadar also leaves commas as they are.
    return urllib.parse.quote(text, safe="-_.!~*'(),")


def encode_aql(aql):
    # Rule Wizard stores the query on one line, then a JSON list of the lines as typed,
    # both URL-encoded and joined by '|'.
    lines = aql.split("\n")
    as_json = json.dumps(lines, ensure_ascii=False, separators=(",", ":"))
    return encode_uri_component(" ".join(lines)) + "|" + encode_uri_component(as_json)


def encode_search_filter(filters, pack):
    parts = []
    for f in filters:
        if f["operator"] not in FILTER_OPS:
            raise Missing(f"search filter operator {f['operator']}")
        values = f.get("values", [NULL_VALUE])
        if f["property"] == "Event Name":
            values = [q for v in values for q in ([v] if isinstance(v, int) else pack.qid(v))]
        values = VALUE_SEP.join(str(v) for v in values)
        parts += [pack.property_key("search_filter", f["property"]), FILTER_OPS[f["operator"]], values]
    return FIELD_SEP.join(parts)


def render_category(t, pack):
    ids = []
    for c in t["categories"]:
        if "low" not in c:
            raise Missing("category test on a whole high-level category")
        ids.append(str(pack.lookup("low_level_categories", f"{c['high']} / {c['low']}")))
    return {"selection": ", ".join(ids)}


# Fields for each test template, keyed by (group, type).
RENDERERS = {
    ("log_source", "log_source_type"): lambda t, p: {
        "selection": ", ".join(str(p.lookup("log_source_types", n)) for n in t["log_source_types"]),
    },
    ("event", "qid"): lambda t, p: {
        "selection": ", ".join(str(q) for q in t.get("qids") or [q for n in t["events"] for q in p.qid(n)]),
    },
    ("event", "category"): render_category,
    ("common", "aql"): lambda t, p: {
        "selection": escape(encode_aql(t["filter"])),
    },
    ("common", "search_filter"): lambda t, p: {
        "selection": escape(encode_search_filter(t["filters"], p)),
    },
    ("common", "reference_set"): lambda t, p: {
        "properties": escape(", ".join(p.property_key("event_fields", n) for n in t["properties"])),
        "reference_sets": ", ".join(str(p.reference_set(n)) for n in t["reference_sets"]),
    },
    ("function_simple", "rule"): lambda t, p: {
        "match": t["match"],
        "selection": ", ".join(p.rule_uuid(n) for n in t["rules"]),
    },
    ("common", "protocol"): lambda t, p: {
        "selection": escape(", ".join(t["protocols"])),
    },
    ("network", "source_location"): lambda t, p: {"location": t["location"]},
    ("network", "destination_location"): lambda t, p: {"location": t["location"]},
    ("network", "destination_port"): lambda t, p: {
        "selection": ", ".join(str(n) for n in t["ports"]),
    },
    ("network", "context"): lambda t, p: {
        "selection": ", ".join(CONTEXTS[c] for c in t["contexts"]),
    },
    ("common", "regex"): lambda t, p: {
        "properties": escape(", ".join(p.property_key("event_fields", n) for n in t["properties"])),
        "regex": escape(t["regex"]),
    },
    ("function_counter", "distinct_properties"): lambda t, p: {
        "count": t["count"],
        "properties": escape(", ".join(p.property_key("event_fields", n) for n in t["properties"])),
        "distinct": escape(", ".join(p.property_key("event_fields", n) for n in t["distinct_properties"])),
        "within": t["within"],
        "unit": UNITS[t["unit"]],
    },
    ("function_counter", "rule_threshold"): lambda t, p: {
        "rules": ", ".join(p.rule_uuid(n) for n in t["rules"]),
        "same": THRESHOLD_FIELDS[t["same"]],
        "times": t["times"],
        "comparison": {"more_than": "gt", "exactly": "eq"}[t.get("comparison", "more_than")],
        "across": t["across"],
        "distinct": THRESHOLD_FIELDS[t["distinct"]],
        "within": t["within"],
        "unit": UNITS[t["unit"]],
    },
    ("function_counter", "same_properties"): lambda t, p: {
        "count": t["count"],
        "properties": escape(", ".join(p.property_key("event_fields", n) for n in t["properties"])),
        "within": t["within"],
        "unit": UNITS[t["unit"]],
    },
}


def render_test(test, uid, pack, rule_type):
    key = (test["group"], test["type"])
    # Tests of flow and common rules use other XML; they need their own template.
    suffix = "" if rule_type == "event" else f".{rule_type}"
    body = template(f"tests/{key[0]}.{key[1]}{suffix}.xml")
    if key not in RENDERERS:
        raise Missing(f"renderer for test {key[0]}.{key[1]}")
    negate = ' negate="true"' if test.get("negate") else ""
    return body.format(uid=uid, negate=negate, **RENDERERS[key](test, pack))


def annotation(tag, text):
    return f"<{tag}><formatString>{escape(text)}</formatString></{tag}>" if text else ""


def offense_fields(offense, pack):
    """offenseMapping and forceOffenseCreation for an action or a dispatched event."""
    if not offense:
        return {"offense_mapping": 0, "force_offense": "false"}
    if "include_events" in offense:
        raise Missing("offense include_events")
    if not offense.get("new_offense"):
        raise Missing("offense without new_offense (ensure part of an offense)")
    return {"offense_mapping": pack.offense_type(offense["index_on"]), "force_offense": "true"}


def render_metric(metric, adjustment):
    """Severity, credibility or relevance: set to, increase or decrease by a value."""
    (kind, value), = adjustment.items()
    operation = {"set": "set", "increase": "inc", "decrease": "dec"}[kind]
    name = metric.capitalize()
    return f'<alterMetric metric="set{name}" operation="{operation}{name}" value="{value}"/>'


def render_action(action, pack):
    if "bypass" in action:
        raise Missing("action bypass")
    metrics = "".join(render_metric(m, action[m]) for m in ("severity", "credibility", "relevance") if m in action)
    offense = action.get("offense")
    return template("action.xml").format(
        metrics=metrics,
        event_annotation=annotation("eventAnnotation", action.get("annotate")),
        offense_annotation=annotation("offenseAnnotation", (offense or {}).get("annotate")),
        drop=' drop="true"' if action.get("drop") else "",
        **offense_fields(offense, pack),
    )


def low_level_category(ev, pack):
    return pack.lookup("low_level_categories", f"{ev['high_cat']} / {ev['low_cat']}")


def render_reference_set_response(tag, action, pack):
    label = action["reference_set"]
    m = REFERENCE_SET_NAME.match(label)
    set_id = pack.reference_set(label)  # also checks the label
    return (f'<{tag} domainResponse="0" filter="{escape(pack.property_key("event_fields", action["property"]))}" '
            f'id="{set_id}" type="{pack.lookup("reference_set_response_types", m["type"])}" '
            f'name="{escape(m["name"], {chr(34): "&quot;"})}"/>')


def render_response(response, qid, pack):
    unsupported = sorted(set(response) - {"new_event", "add_to_reference_set", "remove_from_reference_set"})
    if unsupported:
        raise Missing(f"response {', '.join(unsupported)}")
    children, flags = "", ""
    if "new_event" in response:
        children += render_new_event(response["new_event"], qid, pack)
    if "add_to_reference_set" in response:
        children += render_reference_set_response("referenseSetResponse", response["add_to_reference_set"], pack)
        flags += ' referenceSet="true"'
    if "remove_from_reference_set" in response:
        children += render_reference_set_response(
            "removeFromReferenseSetResponse", response["remove_from_reference_set"], pack)
        flags += ' referenceSetRemove="true"'
    return template("response.xml").format(flags=flags, children=children)


def render_new_event(ev, qid, pack):
    offense = ev.get("offense")
    override, contribute = NAMING[(offense or {}).get("naming", DEFAULT_NAMING)]
    return template("newevent.xml").format(
        name=escape(ev["name"], {'"': "&quot;"}),
        description=escape(ev["description"].strip(), {'"': "&quot;"}),
        severity=ev["severity"],
        credibility=ev["credibility"],
        relevance=ev["relevance"],
        override_name=override,
        contribute_name=contribute,
        qid=qid,
        low_level_category=low_level_category(ev, pack),
        offense_annotation=annotation("offenseAnnotation", ev.get("annotate")),
        **offense_fields(offense, pack),
    ).strip()


def render_limiter(limiter, pack):
    return template("limiter.xml").format(
        # "per <property>" counts by an offense type; hostType is its limiter_string.
        host_type=pack.offense_type_definition(limiter["per_property"])["limiter_string"],
        unit=UNITS[limiter["unit"]],
        per_unit=limiter["per_unit"],
        times=limiter["times"],
    )


def render_qid(ev, qid, row_id, pack):
    fields = {
        "severity": ev["severity"],
        "low_level_category": low_level_category(ev, pack),
        "qid": qid,
        "description": escape(ev["description"].strip()),
        "name": escape(ev["name"]),
    }
    return (template("qidmap.xml").format(id=row_id, **fields)
            + template("dsmevent.xml").format(id=row_id, qidmap_id=row_id, qid=qid,
                                              credibility=ev["credibility"]))


def render_rule(rule, rule_id, qid, pack, missing, rel):
    def attempt(fn, *args):
        try:
            return fn(*args)
        except Missing as e:
            missing.setdefault(str(e), set()).add(rel)
            return ""

    rule_type = rule.get("type", "event")
    pack.rule_log_source_types = set()
    for t in rule["tests"]:
        if t["type"] == "log_source_type" and not t.get("negate"):
            pack.rule_log_source_types |= {attempt(pack.lookup, "log_source_types", n) for n in t["log_source_types"]} - {""}
    tests = "\n".join(attempt(render_test, t, uid, pack, rule_type) for uid, t in enumerate(rule["tests"]))
    actions = attempt(render_action, rule["action"], pack) if "action" in rule else ""
    responses = attempt(render_response, rule["response"], qid, pack) if "response" in rule else ""
    limiter = attempt(render_limiter, rule["limiter"], pack) if "limiter" in rule else ""
    return template("rule.xml").format(
        id=rule_id,
        scope=rule.get("scope", "local").upper(),
        type=rule.get("type", "event").upper(),
        building_block=str(rule.get("building_block", False)).lower(),
        enabled=str(rule.get("enabled", False)).lower(),
        name=escape(rule["name"]),
        notes=escape(rule["description"].strip()),
        tests=tests,
        actions=actions,
        responses=responses,
        limiter=limiter,
    )


def render_reference_data(pack, now):
    """Reference sets with their elements, and which rules use them."""
    created = int(now.timestamp() * 1000)
    seen = now.isoformat(timespec="milliseconds")
    out = []
    for name, s in pack.reference_sets.items():
        out.append(template("reference_data.xml").format(
            name=escape(name), id=s["id"], element_type=s["element_type"],
            uuid=uuid.uuid5(REFERENCE_SET_UUID_NAMESPACE, name),
            current_count=len(s["values"]), created_time=created))
        if not s["values"]:
            continue  # IBM ships empty sets without a key
        # One key per reference set, with the set's id; elements hang off it.
        out.append(template("reference_data_key.xml").format(id=s["id"], reference_data_id=s["id"]))
        for n, value in enumerate(s["values"]):
            out.append(template("reference_data_element.xml").format(
                date=seen, data=base64.b64encode(value.encode("utf-8")).decode("ascii"),
                key_id=s["id"], id=s["id"] * 10000 + n))
    for n, (rule_id, set_id) in enumerate(sorted(pack.set_users), start=1):
        out.append(template("reference_data_rules.xml").format(rule_id=rule_id, id=n, reference_data_id=set_id))
    return "".join(out)


def load_reference_data(folder, validator):
    path = folder / REFERENCE_DATA_FILE
    if not path.is_file():
        return {}, False
    rel = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
    data = yaml.load(path.read_text(encoding="utf-8"), Loader=RuleLoader)
    errors = list(validator.iter_errors(data))
    for e in errors:
        print(f"FAIL {rel}: {location(e)}: {message(e)}")
    return data or {}, bool(errors)


def load_pack(folder, validator):
    rules, failed = [], False
    for path in sorted(p for p in folder.glob("*.y*ml") if p.name != REFERENCE_DATA_FILE):
        rel = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
        rule = yaml.load(path.read_text(encoding="utf-8"), Loader=RuleLoader)
        errors = list(validator.iter_errors(rule))
        for e in errors:
            print(f"FAIL {rel}: {location(e)}: {message(e)}")
        failed |= bool(errors)
        rules.append((rel, rule))
    return rules, failed


def build(folder, out_dir, qradar_version, validators, ids, qids):
    folder = folder.resolve()
    rules_dir = ROOT / "rules"
    name = "-".join(folder.relative_to(rules_dir).parts) if folder.is_relative_to(rules_dir) else folder.name
    rules, failed = load_pack(folder, validators["rule"])
    reference_data, failed_reference_data = load_reference_data(folder, validators["reference_data"])
    if not rules and not reference_data:
        print(f"skip {name}: no rule files in {folder}")
        return True
    if failed or failed_reference_data:
        return False

    now = datetime.now(timezone.utc)
    date = now.isoformat(timespec="seconds")
    pack = Pack(ids, {r["name"]: r["id"] for _, r in rules}, reference_data, qids)
    missing = {}
    rel_reference_data = folder.relative_to(ROOT) / REFERENCE_DATA_FILE if folder.is_relative_to(ROOT) else folder
    for s in reference_data.get("reference_sets", []):
        try:
            pack.add_reference_set(s["name"], s["type"], s.get("values", []))
        except Missing as e:
            missing.setdefault(str(e), set()).add(rel_reference_data)

    groups = sorted({g for _, r in rules for g in r["groups"]})
    group_ids = {g: FGROUP_ID_BASE + i for i, g in enumerate(groups)}
    fgroup_tpl = template("fgroup.xml")
    fgroups = [fgroup_tpl.format(name=escape(g), id=group_ids[g], date=date) for g in groups]

    custom_rule_tpl, link_tpl = template("custom_rule.xml"), template("fgroup_link.xml")
    custom_rules, links, qids = [], [], []
    for rule_id, (rel, rule) in enumerate(sorted(rules, key=lambda x: x[1]["name"]), start=RULE_ID_BASE):
        qid = QID_BASE + uuid.UUID(rule["id"]).int % QID_SPAN
        pack.rule_id = rule_id
        rule_xml = render_rule(rule, rule_id, qid, pack, missing, rel)
        if "new_event" in rule.get("response", {}):
            try:
                qids.append(render_qid(rule["response"]["new_event"], qid, rule_id, pack))
            except Missing as e:
                missing.setdefault(str(e), set()).add(rel)
        custom_rules.append(custom_rule_tpl.format(
            date=date,
            rule_data=base64.b64encode(rule_xml.encode("utf-8")).decode("ascii"),
            uuid=rule["id"],
            id=rule_id,
        ))
        for g in rule["groups"]:
            links.append(link_tpl.format(fgroup_id=group_ids[g], rule_id=rule_id, id=len(links) + 1))

    if missing:
        print(f"FAIL {name}: cannot build, missing:")
        for what, files in sorted(missing.items()):
            print(f"  {what}  ({len(files)} file{'' if len(files) == 1 else 's'}, e.g. {sorted(files)[0]})")
        return False

    offense_type_tpl = template("offense_type.xml")
    offense_types = [offense_type_tpl.format(**{k: str(v).lower() if isinstance(v, bool) else v
                                                for k, v in d.items()})
                     for d in pack.offense_types.values()]
    reference_data_xml = render_reference_data(pack, now)
    content = template("content.xml").format(
        qradar_version=qradar_version,
        fgroups="".join(fgroups),
        offense_types="".join(offense_types),
        reference_data=reference_data_xml,
        qids="".join(qids),
        custom_rules="".join(custom_rules) + "".join(links),
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"{name}.zip"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"{name}.xml", content)
    print(f"ok   {name}: {len(rules)} rules -> {target.relative_to(ROOT) if target.is_relative_to(ROOT) else target}")
    for extension in sorted(pack.required_extensions):
        print(f"     needs on the console: {extension}")
    return True


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("folders", nargs="+", type=Path)
    parser.add_argument("--out", type=Path, default=ROOT / "dist")
    parser.add_argument("--qradar-version", default=DEFAULT_QRADAR_VERSION)
    parser.add_argument("--ids", type=Path, default=IDS, help="IDs file (default: static/qradar-ids.yml)")
    parser.add_argument("--qids", type=Path, help="QID records of the target console (JSON from /api/data_classification/qid_records)")
    args = parser.parse_args(argv)

    validators = {
        kind: Draft202012Validator(json.loads(schema.read_text()), format_checker=Draft202012Validator.FORMAT_CHECKER)
        for kind, schema in (("rule", SCHEMA), ("reference_data", REFERENCE_DATA_SCHEMA))
    }
    ids = yaml.safe_load(args.ids.read_text(encoding="utf-8")) or {}
    ids.update(yaml.safe_load(EXTENSION_RULES.read_text(encoding="utf-8")) or {})
    qids = None
    if args.qids:
        qids = {}
        for r in json.loads(args.qids.read_text(encoding="utf-8")):
            qids.setdefault(r["name"], []).append((r["qid"], r.get("log_source_type_id")))
    ok = [build(f, args.out, args.qradar_version, validators, ids, qids) for f in args.folders]
    return 0 if all(ok) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
