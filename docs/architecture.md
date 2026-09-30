# Architecture

The flat module layout is deliberate for compatibility with direct script execution
and existing imports. The wheel explicitly includes every runtime module; there is
no package discovery and no runtime third-party dependency.

```text
CLI / permissionhell.main
  -> account resolution OR proc subject snapshot
  -> namespace identity validation (processes)
  -> path resolution and directory search
  -> exclusive Unix DAC / POSIX access ACL
  -> effective DAC capability override (processes)
  -> mount restrictions
  -> LSM observation and optional policy decision (processes)
  -> final modeled verdict
```

| Module | Responsibility |
| --- | --- |
| permissionhell | CLI, account identities, traversal, DAC, mount inspection, verdict orchestration, text rendering, canonical version |
| posix_acl | Access-ACL xattr parsing, validation, mask and selection |
| process_subject | Read proc identity, credentials, maps, roots and namespaces; PID revalidation |
| idmap | Pure ID-map validation and debugger/local identity interpretation |
| capabilities | Effective capability sets and supported DAC overrides |
| lsm | Kernel-interface detection, AppArmor/SELinux context and conservative policy confidence |
| lsm_policy | Optional libselinux queries and bounded AppArmor denial-log correlation |
| json_output | Structured command projections; no authorization decisions |
| process_audit | Visible-PID inventory, per-PID classification, summaries and text/JSON |
| access_graph | Collected diagnoses to nodes/edges, text, JSON and DOT |
| policy_drift | Validate explicit JSON expectations and compare existing observations |
| access_snapshot | Portable capture, validation, safe file publication and offline comparisons |
| access_monitor | One-shot baseline initialization/check/update orchestration |

Account audits reuse account diagnosis. Process audits reuse process diagnosis.
Graphs render observations rather than repeat permission evaluation. Policy checks
compare expectations with those same engines, preserving unknown results. Snapshot
diff is offline; monitoring captures once and calls that diff. No scheduling layer
or resident process is installed.

Dataclasses carry decisions independently of output formatting. Process diagnosis
retains the ordinary DAC/ACL/capability/mount result separately from LSM context
and final confidence. LSM uncertainty can invalidate a permit, not an established
ordinary denial. Namespace/capability uncertainty follows the existing conservative
model; rendering does not grant fallback permission.

`permissionhell.__version__` is the canonical release version. Setuptools reads its
literal value through dynamic metadata; console and script entry points both call
`main`. Export versions are separate contracts: see [schemas](schemas.md).

`lsm.resolve` runs after ordinary permission checks and before final process
revalidation. SELinux vectors, labels and inode identities are rechecked; evidence
is returned independently of rendering. A policy denial can refine an ordinary
permit to DENIED. AppArmor correlations remain historical evidence. Downstream
consumers reuse this single decision path.
