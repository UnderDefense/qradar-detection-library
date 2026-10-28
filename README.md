# QRadar Detection Library

UnderDefense detection content for IBM QRadar, kept as code. Each rule and Building Block is a
YAML file that mirrors what the QRadar Rule Wizard shows. A validator checks every file against a
JSON schema, and a builder turns each log source folder into a QRadar content extension that you
can import on any console.

The library is client-agnostic: no client domains, hosts, accounts, IP ranges or QID numbers.
Anything a client has to tune lives in shared reference sets that each console fills itself.

## Layout

```
rules/                      one folder per log source = one extension
  cloud/o365/               Microsoft Office 365
  cloud/entraid/            Microsoft Entra ID
  endpoints/ad/             Active Directory (Windows Security Event Log)
  endpoints/sysmon/         Sysmon (Windows Security Event Log)
  endpoints/windows/        Windows Security Event Log
  network/firewall/         Fortinet FortiGate and generic firewall events
examples/                   one example of every field the schema knows
scripts/validate.py         schema check for all YAML files
scripts/build_extension.py  builds QRadar content extensions
static/rule-schema.json     schema for rule and Building Block files
static/reference-data-schema.json  schema for reference-data.yml
static/qradar-ids.yml       QRadar IDs and keys that are the same on every console
static/qradar-extension-rules.yml  rules that IBM content extensions install, by name
static/extension/           XML templates the builder fills in
docs/                       guides
```

## Quick start

```
pip install -r requirements.txt
python3 scripts/validate.py                          # all rules and examples
python3 scripts/build_extension.py rules/endpoints/sysmon --qids qids.json
```

The builder writes `dist/endpoints-sysmon.zip`. Rules name events instead of QIDs, so the builder
needs the target console's QID records (`qids.json`); see
[docs/extension-builder.md](docs/extension-builder.md#qid-records) for how to get them.

In VS Code with the YAML extension, every rule file gets completion and inline errors from the
schema through its first line (`# yaml-language-server: $schema=...`).

## Guides

- [Writing rules](docs/writing-rules.md): file format, naming, tests, what must not go in the library.
- [Extension builder](docs/extension-builder.md): how extensions are built, where the XML comes from,
  what to check on a test console, how to support a new test.

## Status

| Pack | Rules and BBs | Builds |
|---|---|---|
| endpoints-ad | 4 | yes |
| endpoints-sysmon | 15 | yes |
| endpoints-windows | 6 | yes |
| cloud-o365 | 7 | yes |
| cloud-entraid | 7 | yes |
| network-firewall | 37 | yes |

"Builds" means the builder produces the extension with a QID records file. No extension has been
imported on a console yet; see the checklist in the builder guide before the first import.
