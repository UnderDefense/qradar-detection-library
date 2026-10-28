# Extension builder

`scripts/build_extension.py` turns one folder of rules into one QRadar content extension: a zip
with a single content XML, the same format that Use Case Manager and Extensions Management export.

```
python3 scripts/build_extension.py rules/cloud/o365 rules/network/firewall --qids qids.json
```

Each folder becomes `dist/<path joined by '-'>.zip`, for example `dist/cloud-o365.zip`.

## What goes into an extension

- every rule and Building Block of the folder, with its tests, actions, responses and limiter;
- the rule groups (`groups`);
- offense types the rules index on or limit by;
- reference sets the rules use, plus the sets and values of `reference-data.yml`;
- a QID record for every dispatched event (`response.new_event`).

Numeric IDs inside the file are local to the file. On import QRadar matches each object to its
own by identifier: rules by `uuid` (the rule's `id`), custom offense types by the custom property
identifier, Building Blocks of QRadar and IBM extensions by their UUID. That is why the same
extension works on any console.

## Inputs

| Input | What it holds |
|---|---|
| `static/qradar-ids.yml` | IDs that are the same on every console: log source types, low-level categories, offense types, property keys, reference set type codes, system rule UUIDs |
| `static/qradar-extension-rules.yml` | UUIDs of rules that IBM content extensions install, grouped by extension |
| `static/extension/` | XML templates; `tests/<group>.<type>.xml` per test, `.common.xml` for "events or flows" rules |
| `--qids FILE` | QID records of the target console (below) |
| `--ids FILE` | another IDs file instead of `static/qradar-ids.yml` |

### QID records

Rules name events; QIDs can be custom and differ per console. Export the QID records of the
console you build for and pass them with `--qids`. Keep the file outside the repository.

```
curl -sk -H "SEC: $TOKEN" -H "Range: items=0-499999" \
  "https://$QRADAR/api/data_classification/qid_records?fields=qid,name,log_source_type_id" > qids.json
```

The builder takes every QID with the event's name for the rule's log source types. Without a
`log_source_type` test a name must belong to one log source type only.

## When a build stops

The builder never guesses an XML form or an ID. If a rule uses something it has no template or
no ID for, it stops and lists what is missing:

```
FAIL network-firewall: cannot build, missing:
  reference_set_types 'CIDR' in the IDs file  (1 file, e.g. rules/network/firewall/...)
```

| Message | What to do |
|---|---|
| `template static/extension/...` | the test, action or response has no known XML form; see below |
| `<kind> '<name>' in the IDs file` | add the ID to `static/qradar-ids.yml` (only if it is the same on every console) |
| `rule '<name>' in this pack, system_rules or extension_rules` | add the Building Block to the folder, or check its name |
| `event '<name>' in the QID records` | the event name is not on that console, or is spelled differently |
| `search filter operator ...` | the operator code is not known yet |

### Supporting a new test, action or response

1. Create a rule that uses it on the test console and export it with Use Case Manager.
2. Decode the rule: the `rule_data` element of the export is the rule XML in base64.
3. Add the template under `static/extension/` and a renderer in `RENDERERS` (tests) or the
   matching `render_*` function, with the values the YAML gives.
4. Write the same rule in YAML, build it and compare the generated rule XML with the export:
   tests, parameters, actions and responses must be identical apart from IDs.

## Where the XML knowledge comes from

All templates and codes come from real QRadar content, never from guesses:

- Use Case Manager exports of UnderDefense rules and of test rules made for this purpose;
- 22 IBM content extensions and apps, among them Endpoint 3.3.0, Sysmon 1.3.2, Threat 3.1.0 and
  Hybrid Cloud 2.3.2, plus the 12 content packs bundled with UBA 5.1.0;
- the system rules of a QRadar 7.5 console (365 base rules and 1439 rules with extensions).

A few values are inferred and marked as such in `static/qradar-ids.yml`: the Numeric and Date
reference set codes (their position in the console's type list, which matches all known codes)
and property keys known only from one kind of test.

`static/qradar-extension-rules.yml` was generated from the console's system rules and the IBM
archives. Groups with a comment were set by hand: the Email BBs removed in 1.2.1, RFISI rules that
now ship with the Threat Intelligence app, and UEBA 6.0.0 rules confirmed by the console owner.

## Before the first import

Import on a test console first and check:

1. **Dispatched event QIDs.** The builder gives each dispatched event a QID derived from the
   rule's `id` in the 676xxxxx range. Check that import does not overwrite an existing QID.
2. **Existing reference sets.** Shared sets such as `(Shared) misp_srcip` already exist on client
   consoles with their own UUID. Check whether import reuses them, duplicates them or fails.
3. **Custom offense types.** Rules that index on `Machine Identifier (custom)` should map to the
   console's own offense type for that property.
4. **Rule Wizard view.** Open a few imported rules: every test should read exactly like the YAML.
