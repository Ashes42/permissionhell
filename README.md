# Permission Hell

`permissionhell` is a read-only Linux effective-access debugger. It explains why
an account passes or fails each directory search check, which Unix permission
class applies to the target, and whether its mount adds a restriction.

**v0.1 models Unix DAC and mount restrictions, not every Linux access-control
layer.** POSIX ACLs, SELinux, AppArmor, Linux capabilities, user namespaces,
Docker/container UID/GID mapping, and NFS/SMB/CIFS/FUSE-specific behavior are not
modeled. A permitted result means this model permits the request; it is not a
guarantee that a real process can perform it. Reports identify the DAC + mount
model; `--verbose` and `--help` include the full scope and limitations.

## Installation

Requires **Linux and Python 3.10+**. There are no runtime dependencies or required
external utilities. Plain text output works without Rich.

Run directly from the checkout:

```bash
python3 permissionhell.py --help
python3 permissionhell.py diagnose /srv/music/song.flac --as navidrome
```

Optionally install a `permissionhell` command into a virtual environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install .
permissionhell diagnose /srv/music/song.flac --as navidrome
```

Installation uses setuptools; direct script execution needs only Python's
standard library. Unsupported operating systems report a clear error, while
`--help` and `--version` remain available.

## Usage

```bash
python3 permissionhell.py diagnose TARGET_PATH --as USERNAME [--mode {r,w,x}] [--verbose]

python3 permissionhell.py diagnose /srv/music/song.flac --as navidrome --mode r
python3 permissionhell.py diagnose /var/www/app.db --as www-data --mode w
python3 permissionhell.py diagnose /opt/scripts/backup.sh --as backup --mode x
python3 permissionhell.py diagnose /srv/music/song.flac --as navidrome --verbose
```

Default output leads with the verdict and its reason, then shows compact PASS/FAIL
search checks, target metadata, and a single mount summary. `BLOCKED HERE` marks
the first failing inode. `--verbose` restores every search observation, detailed
per-inode reasoning, group memberships, all mount options, and model limitations.

The default mode is `r`. Read (`r`), write (`w`), and execute/search (`x`) each
request one permission on an **existing inode**. This is not a create, delete,
rename, shell execution, or database transaction simulation. A directory's `r`
bit concerns listing names, `w` concerns modifying entries, and `x` concerns
searching it. Creating an entry normally requires both `w` and `x`; a `--mode w`
check alone does not establish that a whole operation will succeed.

Relative paths start at the debugger's current working directory. Shell expansion
of `~` happens before invocation; the program does not expand a quoted `~`.

The account being evaluated is always `--as`, regardless of who launches the
debugger. The program does not impersonate the account or call `os.access()`.
An unprivileged debugger may be unable to read necessary metadata. That produces
a diagnostic error, not a false denial attributed to the subject. Run from an
account that can inspect the path when necessary; even a privileged invocation
still evaluates the supplied subject.

## Example output

Illustrative output for a subject whose group permits traversal but whose
target access falls into OTHER:

```text
PERMISSION HELL v0.1 | READ as navidrome (UID 1001)
Target: '/srv/music/song.flac'

ACCESS DENIED (DAC + mount model)
navidrome lacks READ permission on '/srv/music/song.flac'.
OTHER selected: subject is neither owner nor in the owning group. Its --- bits lack r; no fallback to another class.

PATH (search x)
  PASS '/'  OTHER r-x
  PASS '/srv'  GROUP r-x
  PASS '/srv/music'  GROUP r-x

TARGET FAIL '/srv/music/song.flac'  <-- BLOCKED HERE
  Owner: ash (1000) | Group: ash (1000) | Mode: 0640 (-rw-r-----)
  Access: OTHER --- | Required: READ (r)
Mount: '/srv' | ext4 | READ-WRITE
```

Successful checks instead start with `ACCESS PERMITTED` and a short explanation
that directory search, target access, and mount checks pass. If a parent fails
search, the report identifies that exact directory, preserves earlier steps, and
marks the target and mount as unevaluated because resolution did not complete.

## How access is evaluated

### Identity and exclusive permission classes

User and group names come from Python's `pwd` and `grp` interfaces to the system
account database. `os.getgrouplist()` resolves primary and supplementary group
membership. The verbose report lists primary and supplementary names and numeric IDs;
unmapped inode owners or groups are displayed numerically.

For each inode, select exactly one class:

1. Subject UID equals inode UID: **OWNER**.
2. Otherwise, inode GID is a primary or supplementary subject GID: **GROUP**.
3. Otherwise: **OTHER**.

There is no fallback. An owner accessing a `0044` file is denied read even though
GROUP and OTHER both have read bits. A matching group with no permission likewise
does not fall back to OTHER. Supplementary groups count equally with the primary
group when choosing GROUP.

### Directory traversal

Resolving `/srv/music/song.flac` requires search (`x`) on `/`, `/srv`, and
`/srv/music`. Directory read permission is not required simply to look up a known
name. The analyzer records each parent inode's UID, GID, mode, selected class,
available bits, and search result. It stops at the first failing parent.

`..` and `.` are processed during traversal, not removed before checking access:
`/blocked/../file` still requires search on `/blocked`. The path `/` itself has no
parent search steps; its inode is checked for the requested target permission.

### Mount restrictions

The mount inspector parses `/proc/self/mountinfo`, including escaped mount paths
and optional fields. It chooses the longest mount-point match on path-component
boundaries, using the resolved target path. Both per-mount and superblock `ro`
options block a write request, including for root. A `noexec` mount blocks direct
execution of non-directory targets; it does not block directory search. Other
reported options, such as `nosuid`, do not independently deny this simple check.

Unreadable, missing, malformed, unmatched, or ambiguous mount information cannot
produce an allowed verdict. A known DAC denial remains denied even if mount
inspection fails, and the mount error is shown separately.

### Root

v0.1 assumes UID 0 is **traditional privileged root**, with the usual DAC bypass:
read/write and directory search are permitted regardless of ordinary mode bits.
For execution of a non-directory inode, at least one OWNER, GROUP, or OTHER
execute bit must be present. Mount `ro` and `noexec` restrictions still apply.
The report leads with `ROOT OVERRIDE` when a check uses that bypass, or `ROOT`
otherwise, with the ordinary class shown in brackets for context. It explicitly
states the privileged-root assumption. Dropped capabilities and namespace-restricted root are not
modeled; UID 0 alone does not establish actual process capabilities.

### Symlink policy

v0.1 follows all symbolic links, including the final component, and checks the
resolved target rather than a link's own permission bits. Each link and its
destination appears in the ordered trace. Absolute destinations restart at `/`;
relative destinations start at the link's containing directory. Required search
checks along both the original path and the link destination are retained. A
successful trace shows the final resolved path.

The concise display omits repeated identical successful directory checks and
notes how many were omitted. It never suppresses a failed or changed observation.
`--verbose` shows the full ordered trace; this display choice does not change
resolution or permission evaluation.

The limit is 40 followed links, matching Linux's ordinary pathname resolution
limit. Missing destinations report a possible broken link and preserve the link
trace. A trailing slash requires a directory. Symlink ownership protections
(`fs.protected_symlinks`), `/proc` magic-link semantics, and `openat2` resolution
flags are not modeled.

## Exit codes

Definitions are centralized in `ExitCode` in `permissionhell.py`.

| Code | Meaning |
| --- | --- |
| 0 | Requested access permitted by the v0.1 model |
| 1 | Requested access denied by a modeled check |
| 2 | Invalid CLI/input: malformed arguments, unknown user, missing component, broken/looping link, non-directory component |
| 3 | Diagnostic/system error: inaccessible metadata, unavailable mount information without an established denial, unsupported platform |

Broken links and other unresolved paths display `UNRESOLVED PATH`, while keeping
exit code 2. Malformed CLI arguments and empty/NUL paths remain invalid input.

## Safety and limitations

The utility only reads identity databases, metadata, symlink destinations, and
mount information. It never changes permissions, ownership, ACLs, memberships,
mounts, target contents, or system configuration. It does not attempt to open the
target for writing or execute it. Python can create normal interpreter cache
files when imported; use `python3 -B` if those should also be suppressed.

In addition to the excluded security layers stated above:

- Identity comes from current account databases, not an existing process's
  potentially stale supplementary groups, fsuid/fsgid, or credentials.
- Paths and mounts are inspected in the debugger's namespace and filesystem
  root, not another process's container, chroot, or service sandbox.
- Inspection is a sequence of observations, not an atomic snapshot. Concurrent
  filesystem/mount changes can invalidate a result.
- ACLs can grant access beyond mode bits or restrict matching named identities.
  Both permitted and denied model results can differ from actual ACL decisions.
- Immutable/append-only flags, security policies, quotas, full filesystems,
  special-device rules, file formats, script interpreters, and executable loaders
  are not checked. A mode-bit check does not prove successful I/O or execution.
- Mount selection uses the visible mountinfo paths. Ambiguous identical mount
  points produce an error; complex overmount arrangements with hidden descendants
  are outside the model.

## Architecture and tests

The single importable module keeps separate layers:

| Layer | Entry point / structured result |
| --- | --- |
| CLI | `main()` |
| Identity | `resolve_subject()` / `Subject` |
| Permission engine | `evaluate_permission()` / `PermissionDecision` |
| Path resolution and traversal | `trace_path()` / `PathTrace`, `Inode`, `Symlink` |
| Mount inspection | `read_mounts()`, `find_mount()` / `Mount` |
| Verdict | `diagnose()`, `determine_verdict()` / `Diagnosis` |
| Presentation | `render_report(report, verbose=False)`, `render_verbose_report()` |

The engine returns dataclasses; only the renderer formats terminal output.

Run on Linux without root privileges:

```bash
python3 -m unittest discover -s tests -v
```

Unit tests mock identities, metadata, and mounts for deterministic precedence,
root, traversal, symlink, failure, and mount checks. A Linux integration test uses
a temporary file and relative symlink, the current account, real mountinfo, and a
CLI subprocess. Tests never change system users or mounts.
Rendering tests cover concise and verbose output, blocker explanations, root
labels, symlink display, scope visibility, CLI flag routing, and unchanged exit
codes. The original 43 semantic/CLI tests are preserved.

## Roadmap

- JSON output backed by the existing structured results.
- POSIX ACL analysis as an additional decision layer.
- SELinux and AppArmor context and policy diagnostics.
- Process-aware credentials, capability sets, and mount namespaces.
- Container mappings and filesystem-specific behavior.

Semantics references: Linux [path_resolution(7)](https://man7.org/linux/man-pages/man7/path_resolution.7.html)
and [symlink(7)](https://man7.org/linux/man-pages/man7/symlink.7.html).
