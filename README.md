# QRadar Detection Library

<!-- badges:start -->
![rules: 50](https://img.shields.io/badge/rules-50-2E7D32) ![building blocks: 26](https://img.shields.io/badge/building%20blocks-26-2E7D32) ![log sources: 6](https://img.shields.io/badge/log%20sources-6-2E7D32)

[![Active Directory: 2 rules, 2 BBs](https://img.shields.io/badge/Active%20Directory-2%20rules%2C%202%20BBs-00A4EF)](rules/endpoints/ad) [![Fortinet FortiGate: 17 rules, 20 BBs](https://img.shields.io/badge/Fortinet%20FortiGate-17%20rules%2C%2020%20BBs-EE3124)](rules/network/firewall) [![Microsoft Entra ID: 5 rules, 2 BBs](https://img.shields.io/badge/Microsoft%20Entra%20ID-5%20rules%2C%202%20BBs-0078D4)](rules/cloud/entraid) [![Microsoft Office 365: 7 rules](https://img.shields.io/badge/Microsoft%20Office%20365-7%20rules-0078D4)](rules/cloud/o365) [![Sysmon: 15 rules](https://img.shields.io/badge/Sysmon-15%20rules-00A4EF)](rules/endpoints/sysmon) [![Windows Security Event Log: 4 rules, 2 BBs](https://img.shields.io/badge/Windows%20Security%20Event%20Log-4%20rules%2C%202%20BBs-00A4EF)](rules/endpoints/windows)
<!-- badges:end -->

UnderDefense detection content for IBM QRadar, kept as code. Each rule and Building Block is a
YAML file that mirrors what the QRadar Rule Wizard shows. A validator checks every file against a
JSON schema, and a builder turns each log source folder into a QRadar content extension that you
can import on any console.

The library is client-agnostic: no client domains, hosts, accounts, IP ranges or QID numbers.
Anything a client has to tune lives in shared reference sets that each console fills itself.

## Layout

```
rules/                               one folder per log source = one extension, each with a README
  cloud/o365/                        Microsoft Office 365
  cloud/entraid/                     Microsoft Entra ID
  endpoints/ad/                      Active Directory (Windows Security Event Log)
  endpoints/sysmon/                  Sysmon (Windows Security Event Log)
  endpoints/windows/                 Windows Security Event Log
  network/firewall/                  Fortinet FortiGate and generic firewall events
examples/                            one example of every field the schema knows
scripts/validate.py                  schema check for all YAML files
scripts/build_extension.py           builds QRadar content extensions
scripts/update_readme.py             refreshes the badges above and the pack READMEs
static/rule-schema.json              schema for rule and Building Block files
static/reference-data-schema.json    schema for reference-data.yml
static/qradar-ids.yml                QRadar IDs and keys that are the same on every console
static/qradar-extension-rules.yml    rules that IBM content extensions install, by name
static/extension/                    XML templates the builder fills in
docs/                                guides
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

All six packs build. No extension has been imported on a console yet; see the checklist in the
[builder guide](docs/extension-builder.md#before-the-first-import) before the first import.

After changing rules, run `python3 scripts/update_readme.py` to refresh the badges and the pack READMEs.
