# Structured formats

Release version and format version are independent. v1.7 changes no format version.
This document describes the existing contracts; it is not a formal JSON Schema.

| Format | Version field | Current value | Owner |
| --- | --- | --- | --- |
| Command JSON | schema_version | string "1" | json_output.SCHEMA_VERSION and command exporters |
| Graph JSON | graph_version (also schema_version) | string "1" (both) | access_graph.GRAPH_VERSION |
| Saved snapshot / monitor baseline | snapshot_version | integer 1 | access_snapshot.SNAPSHOT_VERSION |
| Policy input | policy_version | integer 1 | policy_drift parser / Policy |

Diagnose, audit, process, process-audit, graph and policy reports normally identify
the release using `tool.name` and `tool.version`. Snapshot, diff and monitor formats
use `tool_version`. Some early-error envelopes also use `tool_version`; consumers
must examine `command` and the envelope rather than assume one universal shape.
Snapshot stdout is a saved snapshot document, not a command-report envelope.

Command reports carry verdict/result and exit status, reasons and available
observations. Process reports add `ordinary_verdict`, `lsm`, `lsm_result`, credentials,
namespaces and capability context. An absent value (`null`) is not a negative
permission result. JSON retains individual results even when text groups accounts
or hides process churn. Syntax errors from argparse are stderr text with exit 2,
even if the malformed request contains `--json`.

Graphs include `nodes`, `edges` and an ordered `spine`. Node IDs link observed
decisions within that graph; they are not durable cross-run identities. DOT is a
presentation format without a separate machine-contract version.

Snapshots contain scope, literal target path, requested mode, capture timestamp,
system identity, target metadata, subjects and capture errors. Account matching
uses UID plus username; process matching requires PID plus start ticks within a
known host/boot/PID namespace. A snapshot is neither signed nor proof of historical
kernel access. Monitor baselines use snapshots unchanged. Diff and monitor-check
reports contain all individual comparisons and summary counts; monitor reports
add baseline/current headers and `baseline_updated`.

Policy input uses strict JSON with explicit resources, modes and account/process
expectations. Unknown policy keys are rejected. Read [reference examples](reference.md)
for exact policy shapes; policy version 1 is not inferred from missing metadata.

## Compatibility policy

- Preserve existing field names, types and meanings within a format version.
- Output may gain optional fields; consumers should ignore unknown output keys.
- Existing strict input validators remain authoritative. Do not assume arbitrary
  extra policy keys or malformed nested snapshot values will be accepted.
- Missing optional historical observations remain unknown, never fabricated.
- Removing/renaming fields, changing types or reinterpreting identities requires a
  format-version change, migration notes and regression fixtures. New semantic
  enum values need an explicit consumer-compatibility review; unknown values must
  not be treated as permitted.
- Export consumers should reject unsupported major formats or preserve uncertainty.
  Current snapshot/policy loaders reject unsupported version numbers with exit 2.

The changelog must identify schema changes separately from tool-version changes.
No consolidated formal JSON Schema or automatic migration tool is provided yet.

## v1.7 additive LSM evidence

All format versions remain unchanged. `lsm_result.layer_results` contains module
results with `module`, `decision` (`allowed`, `denied`, `unresolved`), `reason` and
`evidence`. SELinux evidence includes contexts, path, class, requested permissions,
access vectors, policy sequence and adapter/source. AppArmor evidence identifies
historical events and correlation limits. `lsm_result.status` additionally supports
`denied`; `resolved` retains its existing meaning. Consumers must treat unfamiliar
statuses conservatively.

LSM denial adds `effective_blocker` (stage, mechanism, path, reason).
`ordinary_verdict` and `first_blocker` retain ordinary filesystem meanings.
Graphs and snapshots retain the evidence; snapshot mechanisms use the effective
blocker. Old snapshots remain readable. Recent-log evidence changes can appear as
context drift in diff/monitor, without proving a current authorization change.
