# Permission Hell

**Explain why an account or running process can—or cannot—access a Linux path.**

Permission Hell traces directory search checks, Unix permissions, POSIX ACLs,
effective DAC capabilities, mount restrictions and observable LSM context. It also
audits subjects, exports access graphs, compares intended policy, saves snapshots
and checks access changes against a baseline.

It is a **read-only access model**, not a complete Linux authorization simulator or
a syscall probe. A modeled permit is not a guarantee that an actual operation will
succeed. Unresolved process context or enforcing LSM policy remains indeterminate.

## Installation

Requires Linux and **Python 3.10 or newer**. CI covers CPython 3.10–3.14 on Ubuntu.
Runtime dependencies: **Python standard library only**. Windows users can run live
analysis inside WSL; offline `diff` also works on Windows.

From a checkout, install an isolated command using pipx:

```bash
pipx install .
permissionhell --version
permissionhell --help
```

Or install in a virtual environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
permissionhell --help
```

Direct source execution remains supported: `python3 permissionhell.py --help`.
There is no runtime need for Rich, Graphviz, getfacl, aa-status or sestatus.
Build tooling may need network access during installation.

**Release gap:** this checkout has no LICENSE file. No license grant or SPDX
identifier has been invented. The owner must decide licensing before distribution
as an openly licensed project. These instructions describe local installation.

## Quick start

```bash
permissionhell diagnose /srv/music/song.flac --as navidrome
permissionhell diagnose /var/www/app.db --as www-data --mode w
permissionhell audit /srv/data.db --explain www-data
permissionhell process /srv/data.db --pid 812
```

Read (`r`) is the default; `w` checks write and `x` execute/search. Process commands
require absolute paths in the debugger's visible filesystem. Use
`permissionhell COMMAND --help` for an example and command-specific options.

## Commands

| Command | Purpose |
| --- | --- |
| `diagnose TARGET --as USER` | Explain one account's modeled access |
| `audit TARGET` | Audit explicit local accounts; `--explain USER` expands one |
| `process TARGET --pid PID` | Analyze live filesystem credentials and process context |
| `audit-processes TARGET` | Audit visible processes, optionally selected with repeated `--pid` |
| `graph TARGET --as USER` or `--pid PID` | Access graph in text, JSON or DOT |
| `policy-check POLICY.json` | Compare explicit policy expectations with observations |
| `snapshot TARGET` | Save account/process observations as JSON |
| `diff BEFORE.json AFTER.json` | Compare snapshots offline |
| `monitor-init TARGET --baseline FILE` | Create a complete snapshot baseline |
| `monitor-check TARGET --baseline FILE` | One-shot change detection; optional explicit update |

## Effective access model

An account's UID and primary/supplementary groups select exactly one Unix class:
OWNER first, then GROUP, otherwise OTHER. A denied owner never falls through to
more permissive group/other bits. Every traversed directory requires search (`x`).
Symlinks are followed in resolution order, including their necessary parent checks.

POSIX access ACLs apply named users, matching group unions and the ACL mask.
Read-only mounts block writes; noexec restricts regular-file execution. Account
UID 0 uses the documented traditional root model; executing a regular file still
requires an execute bit. These checks do not open/read the target's data.

### Processes, capabilities and namespaces

Live process analysis uses observed fsuid/fsgid and supplementary groups, not the
account database's memberships. UID 0 alone grants no process bypass. Effective
`CAP_DAC_OVERRIDE` and `CAP_DAC_READ_SEARCH` are modeled when their scope over the
inode can be established; other capability effects are not simulated.

Proc credentials are debugger-visible IDs. Namespace maps validate translations;
foreign mount/root paths and uncertain capability scope remain conservative.
PID identity and credentials are rechecked, but observations are not atomic.

### LSM awareness

AppArmor profiles/modes and SELinux contexts/enforcement are observed without full
policy simulation. Confined/enforcing policy can turn an ordinary permit into
INDETERMINATE; a clear ordinary denial stays DENIED. Account-only checks have no
live process security context. See the [detailed reference](docs/reference.md) for
complain/permissive behavior, stacking and unsupported-LSM limitations.

## Graphs, policy, snapshots and monitoring

```bash
permissionhell graph /srv/data.db --as www-data --dot > access.dot
permissionhell policy-check policy.json --json
permissionhell snapshot /srv/data.db --output before.json
permissionhell snapshot /srv/data.db --output after.json
permissionhell diff before.json after.json
permissionhell monitor-init /srv/data.db --baseline baseline.json
permissionhell monitor-check /srv/data.db --baseline baseline.json --json
permissionhell monitor-check /srv/data.db --baseline baseline.json --update-baseline
```

Policy files express explicit account/PID expectations; uncertainty cannot become
a false match. Snapshot diffs distinguish gained/lost access, mechanism/context
changes, target replacement and subject additions/removals. PID reuse is never
matched using PID alone. Add `--processes` when capturing a process baseline.

Monitoring runs once. It installs no cron jobs, timers or services. Updates occur
only when explicitly requested and the comparison is complete. Publication uses
private staging and atomic replacement; concurrent updates are last successful
replacement wins. See [monitoring details](docs/reference.md#one-shot-access-monitoring-v15).

## Output and exit codes

Default text emphasizes diagnostic reasons; `--verbose` exposes detail where
supported. `--json` retains individual observations. Graph `--dot` emits text and
never launches Graphviz. Structured format versions are independent of the tool
release: see [schemas](docs/schemas.md).

| Commands | 0 | 1 | 2 | 3 |
| --- | --- | --- | --- | --- |
| diagnose, process, graph | Modeled permit | Denied | Invalid input | Incomplete/indeterminate/error |
| audit, audit-processes | Completed inventory, including denials | Not used | Invalid input | Incomplete/error |
| policy-check | Matches | Policy drift | Invalid policy/input | Indeterminate |
| snapshot | Complete capture | Not used | Invalid input/output | Partial/error |
| diff, monitor-check | No meaningful change | Changes | Invalid/incompatible input | Incomplete/error |
| monitor-init | Baseline created | Not used | Invalid input/output | Incomplete/error |

`--help`/`--version` exit 0; malformed CLI usage exits 2. Exit 1 can be an expected
automation signal, not a runtime failure. See [all exit-code details](docs/exit-codes.md).

## Safety, limitations and privacy

Permission Hell never applies its remediation suggestions. It does not change
permissions, ACLs, labels, processes, credentials, mappings, namespaces, mounts or
LSM policy. Explicit snapshot/baseline paths and temporary staging are application
write exceptions; shell redirects and Python bytecode caches are separate.

It does not read target file contents, process memory or process environment
variables. **`audit-processes --verbose` can read command lines**, which may contain
secrets. Reports can expose names, UIDs/GIDs, PIDs, paths, ACL identities, namespace
maps, capabilities, security labels, policy intent and snapshot history.

Full LSM policies, Landlock rulesets, filesystem-specific NFS/SMB/FUSE behavior,
inode flags, idmapped mounts and arbitrary namespace path translation are not
fully modeled. Visibility restrictions, target changes, policy updates and PID
reuse can race any observation. Root is not required and should not be assumed
necessary; increased privileges also increase metadata exposure.

Read the [threat model](docs/threat-model.md) before relying on exported results.

## Development and release checks

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install '.[dev]'
python -m pytest -q
python -m build
python scripts/release_check.py
```

Existing stdlib tests also run with `python -m unittest discover -s tests -q`.
The release checker builds sdist/wheel, checks archive contents, installs the wheel
into an isolated environment and exercises the installed command/imports and
tests outside the checkout. It publishes nothing.

See [contributing](CONTRIBUTING.md), [release procedure](docs/releasing.md),
[architecture](docs/architecture.md), [security reporting](SECURITY.md),
[changelog](CHANGELOG.md) and the [complete command/model reference](docs/reference.md).
