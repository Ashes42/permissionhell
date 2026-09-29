# Permission Hell

`permissionhell` is a read-only Linux effective-access debugger. It explains why
an account passes or fails each directory search check, which Unix permission
class or POSIX access-ACL entry applies to the target, how an ACL mask changes
effective permissions, and whether its mount adds a restriction.

**v0.5 models Unix DAC, POSIX access ACLs, and mount restrictions, not every Linux
access-control layer.** SELinux, AppArmor, Linux capabilities, user namespaces,
Docker/container UID/GID mapping, and NFS/SMB/CIFS/FUSE-specific behavior are not
modeled. A permitted result means this model permits the request; it is not a
guarantee that a real process can perform it. Reports identify the DAC + ACL + mount
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
python3 permissionhell.py audit TARGET_PATH [--mode {r,w,x}] [--verbose]
python3 permissionhell.py audit TARGET_PATH --explain USERNAME [--mode {r,w,x}] [--verbose]

python3 permissionhell.py diagnose /srv/music/song.flac --as navidrome --mode r
python3 permissionhell.py diagnose /var/www/app.db --as www-data --mode w
python3 permissionhell.py diagnose /opt/scripts/backup.sh --as backup --mode x
python3 permissionhell.py diagnose /srv/music/song.flac --as navidrome --verbose
python3 permissionhell.py audit /srv/music/song.flac
python3 permissionhell.py audit /srv/customer-data/report.csv --mode w
python3 permissionhell.py audit /srv/customer-data/report.csv --verbose
```

`diagnose` asks whether **one named account** can access the path and explains
each step. `audit` asks **which local accounts** can access it, with compact
per-account explanations and permitted/denied/error totals. Both default to read.

Default output leads with the verdict and its reason, then shows compact PASS/FAIL
search checks, target metadata, and a single mount summary. `BLOCKED HERE` marks
the first failing inode. `--verbose` restores every search observation, detailed
per-inode reasoning, inspected ACL entries and masks, group memberships, all mount
options, and model limitations. Unrelated ACL entries are hidden in concise output.

The default mode is `r`. Read (`r`), write (`w`), and execute/search (`x`) each
request one permission on an **existing inode**. This is not a create, delete,
rename, shell execution, or database transaction simulation. A directory's `r`
bit concerns listing names, `w` concerns modifying entries, and `x` concerns
searching it. Creating an entry normally requires both `w` and `x`; a `--mode w`
check alone does not establish that a whole operation will succeed.

Relative paths start at the debugger's current working directory. Shell expansion
of `~` happens before invocation; the program does not expand a quoted `~`.

The account being evaluated is supplied by `--as` or `--explain`, regardless of who launches the
debugger. The program does not impersonate the account or call `os.access()`.
An unprivileged debugger may be unable to read necessary metadata. That produces
a diagnostic error, not a false denial attributed to the subject. Run from an
account that can inspect the path when necessary; even a privileged invocation
still evaluates the supplied subject.

## Focused audit explanations (v0.4)

```bash
permissionhell audit /srv/secrets/report.csv --explain www-data
permissionhell audit /srv/secrets/report.csv --mode w --explain www-data
permissionhell audit /srv/secrets/report.csv --explain www-data --verbose
```

`diagnose --as USER` gives a single-account diagnostic. Normal `audit` summarizes
all local accounts. `audit --explain USER` shows just that identity's ordered
access path with selected mechanisms and the first blocker. Adding `--verbose`
appends the complete underlying diagnostic, including inspected ACL entries,
group memberships, mount options, and scope. No all-account audit runs first.

The dedicated `AuditExplanation` retains the existing engine's `Diagnosis`.
Rendering consumes those decisions; it does not evaluate permissions again.
Explicit `--explain` names use the same system identity lookup as `diagnose`
(which may consult NSS), rather than enumerating `/etc/passwd`. Unlike the
all-account audit's global existence preflight, resolution follows the chosen
subject's traversal and stops at its first blocker. An unreachable later missing
component therefore does not replace a known earlier traversal denial.

Illustrative permitted result (ordinary metadata shortened here):

```text
PERMISSION HELL v0.5 | AUDIT EXPLAIN
Target: '/data/file'
Subject: member (UID 2000)
Requested: READ

RESULT: PERMITTED

ACCESS PATH
  '/'  PASS search | OTHER r-x
  '/data'  PASS search | GROUP r-x
    via supplementary group media (GID 500)
  '/data/file'  PASS READ | GROUP r--
    via supplementary group media (GID 500)
    Owner: owner (UID 9000) | Group: media (GID 500) | Mode: 0644 (-rw-r--r--)
  Mount: '/' | ext4 | READ-WRITE | PASS

WHY
  Every parent permits search.
  Access via GROUP (supplementary group media, GID 500); effective: r--.
  Requested access survives the mount checks.
```

Illustrative denial excerpt:

```text
PERMISSION HELL v0.5 | AUDIT EXPLAIN
Target: '/data/file'
Subject: visitor (UID 2001)
Requested: READ

RESULT: DENIED

ACCESS PATH
  '/'  PASS search | OTHER r-x
  '/data'  FAIL search | OTHER --- <-- BLOCKED HERE
    OTHER applies: subject is neither owner nor in the owning group. Missing EXECUTE/SEARCH.
  Target not evaluated because path resolution/traversal stopped.
  Mount: not evaluated; target unresolved.

WHY
  Traversal blocked at '/data': subject lacks execute/search permission.
```

Relevant ACL steps show matching entries, group union, mask, effective bits and
requested permission/result; unrelated ACL entries stay hidden by default.
Root overrides are marked only where they change the decision. Symlinks appear
as `link -> destination`, followed by the final resolved target when available.
Repeated identical successful searches retain their sequence position with a
short reference to the previous check. Mount denials mark the mount as the first
blocker if the inode checks passed.

Focused exit codes are **0 permitted, 1 denied, 2 invalid input/path/user,
3 diagnostic/system error**. Normal audit still returns **0** when evaluation
completes, even if some or all accounts are denied; it returns 2 for invalid
input/path and 3 for incomplete inspection. A known denial remains definitive
even when mount inspection is unavailable, with that limitation shown.

The canonical version is `permissionhell.__version__`. Package metadata and
`--version` use its full value (**0.5.0**); all report headings derive their compact
label (**v0.5**) from it. Nonzero patch versions remain visible (for example,
`0.5.1` displays as `v0.5.1`). The permission model is unchanged.

## Informational change suggestions (v0.5)

```bash
permissionhell audit /srv/data/file.db --explain www-data --mode w --suggest-fixes
permissionhell audit /srv/data/file.db --explain www-data --suggest-fixes --verbose
```

`--suggest-fixes` requires `--explain USER`. It appends structured alternatives
to the focused report without changing the verdict or exit code. Denied access
produces ways to address the first inode blocker and any known mount restriction;
permitted access produces ways to narrow or remove the modeled permission.

**Suggestions are informational text only and are never executed.** There is no
interactive prompt or apply-fix command. No chmod, chown, setfacl, group change,
remount, or other modifying operation runs. Commands are quoted for a POSIX shell,
with option termination before paths. Reinspect the current state before manually
using any command; diagnostics are observations, not an atomic snapshot.

Alternatives describe scope and tradeoffs, not intended organizational policy or
a universally best fix. Each identifies affected identities/objects and relevant
privilege requirements. Commands are alternatives, not a script to run in sequence.
For example, a WRITE denial through OTHER on a plain 0600 file can show:

```text
RESULT: DENIED
POSSIBLE CHANGES

BROADER MODE CHANGE
  Grant OTHER w on '/srv/data/file.db'
    chmod o+w -- /srv/data/file.db
  Effect: Changes rights for every account using OTHER, not just the subject.

NARROW CHANGE
  Set a named-user access ACL
    setfacl -n -m u:www-data:-w-,m::-w- -- /srv/data/file.db
  Effect: Changes the named account's entry while preserving the owning-group entry.
```

For READ access already permitted through OTHER on a plain 0644 file:

```text
RESULT: PERMITTED
POSSIBLE CHANGES

BROADER MODE CHANGE
  Remove OTHER r on '/srv/data/file.db'
    chmod o-r -- /srv/data/file.db
  Effect: Changes rights for every account using OTHER, not just the subject.

NARROW CHANGE
  Set a named-user access ACL
    setfacl -n -m u:www-data:---,m::r-- -- /srv/data/file.db
  Effect: The named entry prevents fallback to OTHER; existing group rights remain.
```

These excerpts omit the repeated caveats shown by the command. Inode changes
require owner or administrator authority; account membership changes require
account administration and refreshed process credentials. Group changes can
affect access to other resources. Directory `x` means search/traversal and changes
reachability of descendants. Every suggested change needs a fresh full-path check.

For existing named-user ACLs, generated edits preserve the mask with `setfacl -n`.
A mask expansion is a separate alternative and explicitly warns that **all
mask-governed named-user and group ACL entries** may gain effective rights.
For reductions, retaining a restrictive named entry prevents fallback; simply
deleting it could restore access via GROUP or OTHER. Matching-group ACL redesign
is conceptual because multiple entries can contribute to the group union.
With extended ACLs, `chmod g` edits the shared mask, so no ordinary group-bit
command is inferred for that case.

Read-only/noexec mount guidance identifies the filesystem restriction and its
system-wide scope without inventing a remount command. File mode changes alone
cannot overcome it. Root execution guidance preserves the existing execute-bit
rule; ordinary DAC/ACL reductions do not reliably revoke privileged root access.
Unknown diagnostic states receive no concrete permission commands.

Suggestions cover only the existing DAC, ACL, traversal, group, mount, and
traditional-root model. They do not model intended policy or suggest changes to
SELinux, AppArmor, capabilities, namespaces, containers, or filesystem-specific
controls. No ownership reassignment is inferred. Filesystem ACL support and
unchanged identity/metadata state must be verified before manually applying ACLs.

`RemediationSuggestion` holds category, title, commands, effect, and caveats.
`suggest_remediations()` consumes a `Diagnosis` without mutation or extra system
inspection; a separate renderer formats it. Package/CLI version is **0.5.0**;
all explanation and diagnostic banners use the same canonical version source.

## Local-account access audits

```bash
permissionhell audit /srv/customer-data/report.csv --mode r
```

Audit calls the same structured `diagnose()` engine for each account. It includes
parent search, exclusive DAC classes, supplementary groups, access ACLs and masks,
symlinks, the documented root model, and mount restrictions. It never shells out
to repeated CLI invocations. Each `AccountAudit` retains its complete `Diagnosis`
for future JSON, visualization, or per-account explanation features.

**Local account** means an explicit record in the debugger's `/etc/passwd`.
The inventory includes UID 0, service/system accounts, locked accounts, and
accounts with `nologin` shells. There is no UID cutoff. Distinct names sharing a
UID are evaluated separately because their configured supplementary groups may
differ. Comments and NIS `+`/`-` compatibility directives are not account records.
Malformed records and duplicate names produce an inventory error rather than
silently omitting identities.

The inventory deliberately avoids `pwd.getpwall()`, whose system-wide enumeration
can include remote NSS identities. Each local name is resolved using the existing
`pwd.getpwnam()` and `os.getgrouplist()` path, preserving diagnose semantics. Its
resolved name/UID/primary GID must agree with the local record; mismatches become
per-account errors. These individual lookups can still consult configured NSS
providers. LDAP/AD/NIS-only and dynamically supplied accounts absent from
`/etc/passwd` are not audited. Account authentication or login ability is not
tested: a service account can access files without interactive login.

Illustrative output for a three-account inventory:

```text
PERMISSION HELL v0.5 | ACCESS AUDIT
Target: '/srv/customer-data/report.csv'
Requested: READ (r)
Local accounts: /etc/passwd (including service accounts)

2 accounts permitted | 1 account denied | 0 account errors
Permitted means parent search, target access, and mount checks passed.

PERMITTED
  alice (UID 1001)
    Access via OWNER; effective: rw-.
  root (UID 0)
    Access via ROOT OVERRIDE [ordinary OTHER ---]; assumes traditional privileged UID 0.

DENIED
  visitor (UID 1003)
    BLOCKED at '/srv/customer-data/report.csv': missing READ.
    OTHER --- (neither owner nor in the owning group).

Modeled DAC + ACL + mount access, not intended authorization policy.
```

Group explanations distinguish primary from supplementary membership. ACL
explanations identify selected entries, group unions, masks, and effective bits.
ACL-dependent parent search is shown where relevant. Mount denials identify the
mount restriction; traversal denials identify the first blocked directory. For
symlink/relative paths the observed resolved target is also shown. Ordinary
successful parent checks are not repeated for every account. Use the existing
`diagnose TARGET --as USER --verbose` command for the complete individual trace.

Default audit output compresses the dominant repeated **ordinary OTHER** result
in each section when at least three accounts share it. Grouping requires matching
traversal, inode/ACL observations, resolved paths, mount information, and reasons;
identical-looking short labels alone are insufficient. OWNER, ROOT, group access
(including supplementary groups), matched named ACLs, mount restrictions, and
errors stay individual. Less-common blockers and materially different paths also
remain individual. Counts always count accounts, not display groups.

A compressed entry looks like:

```text
  25 accounts with the same result (sample: daemon, backup, bin; +22 more)
    Access via OTHER; effective: r--.
```

`audit TARGET --verbose` expands the full per-account summary list. It does not
change evaluation, counts, or exit codes. Use `diagnose ... --verbose` when you
also want every detailed traversal/ACL check for one account.

### Audit failures and exit codes

Audit first checks that the debugger can resolve and inspect the target's
metadata, without testing the debugger's own read/write/execute rights. This
prevents an absent or broken target from being concealed by early traversal
denials for every account. It then evaluates each subject's traversal normally;
the preflight check grants no subject access and never opens target contents.

| Code | Audit meaning |
| --- | --- |
| 0 | Every enumerated account has a definitive modeled permitted/denied result; denials are normal data |
| 2 | Invalid arguments or unresolved/invalid path, including a path becoming unresolved during evaluation |
| 3 | Inventory/preflight failure, empty inventory, or any per-account diagnostic error; partial results are retained |

Audit does **not** return 1 merely because access is denied. A group lookup or
required ACL/metadata inspection failure goes into **ERRORS / UNKNOWN**, never
PERMITTED or DENIED, and evaluation continues for other accounts. If a target
disappears mid-audit, completed results are retained with exit 2. The existing
engine can establish a definite DAC denial despite failed mount inspection;
such results remain denials and the mount failure is reported as an inspection
note. Exit 0 then means every account's access result is known, not that every
inspection layer was available.

### Audit limitations and privacy

This reports **effective modeled access, not intended authorization policy**.
OTHER or supplementary-group access is factual; the tool does not label it
unexpected or illegitimate. It does not enumerate processes, impersonate users,
inspect password hashes in `/etc/shadow`, or evaluate authentication policy.

Reports can reveal account names/UIDs, group relationships, paths, and ACL access
patterns. Review output before sharing it. Only names/UIDs/primary GIDs are retained
from `/etc/passwd`; password, GECOS, home-directory, and shell fields are not stored
in results or printed. The application sends no audit report to external services;
normal system NSS lookups may contact providers configured on the host.

An audit shares one lazily read mount-table snapshot (or its inspection error).
Other inode/ACL observations and identity lookups remain per-account. The
`AuditContext` can accommodate more shared metadata readers later without caching
subject-specific decisions. This is a sequential observation, not an atomic
security snapshot: account, group, path, ACL, or mount changes can invalidate it.
All existing security-layer and namespace limitations below still apply.

## Example output

Illustrative output for a subject whose group permits traversal but whose
target access falls into OTHER:

```text
PERMISSION HELL v0.5 | READ as navidrome (UID 1001)
Target: '/srv/music/song.flac'

ACCESS DENIED (DAC + ACL + mount model)
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

Without an extended access ACL, select exactly one class for each inode:

1. Subject UID equals inode UID: **OWNER**.
2. Otherwise, inode GID is a primary or supplementary subject GID: **GROUP**.
3. Otherwise: **OTHER**.

There is no fallback. An owner accessing a `0044` file is denied read even though
GROUP and OTHER both have read bits. A matching group with no permission likewise
does not fall back to OTHER. Supplementary groups count equally with the primary
group when choosing GROUP.

### POSIX access ACLs

An access ACL can identify additional users and groups. Mode bits alone are then
insufficient: the inode's group mode bits represent **`mask::`**, rather than
the permissions in **`group::`**. A displayed group `rw-` is a ceiling, not proof
that every group member has both permissions.

For non-root subjects, evaluation follows this order:

1. **Owner:** `user::` applies exclusively and is not masked. A named entry for
   the same UID cannot override the owner entry.
2. **Named user:** an exact UID match selects `user:UID:` exclusively. Effective
   permissions are that entry intersected with `mask::`. Denial does not fall
   through to group or OTHER entries.
3. **Groups:** consider `group::` if the subject belongs to the owning GID, plus
   every `group:GID:` matching a primary or supplementary GID. For the CLI's
   single `r`, `w`, or `x` request, combine those entries' permissions and apply
   `mask::`. A matching group with zero permissions still prevents OTHER fallback.
4. **Other:** `other::` applies only when no owner, named-user, or group entry
   matches. It is not masked.

A mask can remove permissions but cannot add them. The output identifies the
matched entries, their specified permissions, any group union, the mask, and the
effective bits. Numeric UID/GID qualifiers are shown deliberately, so missing or
ambiguous account names cannot change interpretation. The requesting account's
name and UID remain in the header.

**Single-permission scope:** Linux checks an entire requested permission set
against a matching group entry. Combining separate read and write grants does
not necessarily authorize one combined read/write syscall. This CLI requests
only one bit at a time, where the group union is equivalent. The ACL evaluator
rejects combined bitmasks rather than implying multi-permission syscall support.

For example, with `user:33:rw-` and `mask::r--`, UID 33 can read but cannot write.
An illustrative concise denial (assuming the parent directories permit search):

```text
PERMISSION HELL v0.5 | WRITE as www-data (UID 33)
Target: '/srv/data/file.txt'

ACCESS DENIED (DAC + ACL + mount model)
www-data lacks WRITE permission on '/srv/data/file.txt'.
ACL NAMED USER: user:33:rw-. Mask: r--; effective: r--. The ACL mask removes WRITE; access denied, no fallback.

PATH (search x)
  PASS '/'  OTHER r-x
  PASS '/srv'  OTHER r-x
  PASS '/srv/data'  OTHER r-x

TARGET FAIL '/srv/data/file.txt'  <-- BLOCKED HERE
  Owner: ash (1000) | Group: staff (1001) | Mode: 0640 (-rw-r-----)
  Access: ACL NAMED USER r-- | Required: WRITE (w)
Mount: '/' | ext4 | READ-WRITE
```

The mode is `0640`, not `0660`, because the ACL mask is `r--`.
`--verbose` also lists unmatched entries, marks selected entries, and explains
the relationship between the mode's group bits and the ACL mask.

### ACL inspection and errors

The standard-library `os.getxattr(path, "system.posix_acl_access",
follow_symlinks=False)` reads Linux's access-ACL xattr. The decoder validates the
version-2 little-endian format, tags, permission bits, identifiers, required
entries, uniqueness, ordering, and mask requirements. It also checks that ACL
owner/mask/other permissions agree with the observed mode bits. `getfacl`,
`setfacl`, `libacl`, Rich, and other runtime dependencies are not required.

Only `ENODATA` means no stored access ACL. A three-entry ACL without a mask is
equivalent to the mode bits. An ACL containing a mask is extended even without
named users/groups. The tool never treats `EACCES`, `EPERM`, `ENOTSUP`/
`EOPNOTSUPP`, missing Python support, malformed data, or a mode/ACL mismatch as
"no ACL". When inspection is needed, these conditions produce exit **3**, identify
the inode, retain the preceding trace, and stop before accessing children.
This conservative policy may return incomplete on filesystems that do not
support this interface, even if their own authorization is simple.

Two safe shortcuts avoid unnecessary inspection:

- For the inode's owner, owner mode bits equal the unmasked `user::` entry, so
  the existing mode-bit decision is definitive within this model.
- For traditional privileged UID 0, the existing DAC bypass and execute-bit
  rule remain definitive; an access ACL cannot restrict that bypass.

These cases do not read or claim absence of an ACL. Verbose output explains why
inspection was unnecessary instead of dumping unrelated entries. They remain
usable when ACL inspection is unavailable. Other inspection failures remain
errors; the implementation does not guess from OTHER or mask bits.

### Directory traversal

Resolving `/srv/music/song.flac` requires search (`x`) on `/`, `/srv`, and
`/srv/music`. Directory read permission is not required simply to look up a known
name. The analyzer records each parent inode's UID, GID, mode, selected class,
available bits, and search result. It stops at the first failing parent.

The same access-ACL rules apply to each parent's search (`x`) permission. An ACL
can permit traversal that OTHER would deny, or block traversal despite permissive
mode bits. ACL denials identify the directory as `BLOCKED HERE`, explain the
entry/mask decision, and leave unreachable target components unevaluated.

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

v0.3 preserves the **traditional privileged root** model for UID 0:
read/write and directory search bypass ordinary mode bits and POSIX access ACLs.
For execution of a non-directory inode, at least one OWNER, GROUP, or OTHER
execute bit must be present. Mount `ro` and `noexec` restrictions still apply.
The report leads with `ROOT OVERRIDE` when a check uses that bypass, or `ROOT`
otherwise, with the ordinary class shown in brackets for context. It explicitly
states the privileged-root assumption. Dropped capabilities and namespace-restricted root are not
modeled; UID 0 alone does not establish actual process capabilities.

### Symlink policy

Permission Hell follows all symbolic links, including the final component, and checks the
resolved target rather than a link's own permission bits. Each link and its
destination appears in the ordered trace. Absolute destinations restart at `/`;
relative destinations start at the link's containing directory. Required search
checks along both the original path and the link destination are retained. A
successful trace shows the final resolved path.
ACLs are inspected on the traversed directories and resolved target, never used
to interpret the symbolic link's own permission bits.

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

Definitions are centralized in `ExitCode` in `permissionhell.py`. The following
table describes **diagnose and audit --explain**; normal audit semantics are above.

| Code | Meaning |
| --- | --- |
| 0 | Requested access permitted by the DAC + ACL + mount model |
| 1 | Requested access denied by a modeled check |
| 2 | Invalid CLI/input: malformed arguments, unknown user, missing component, broken/looping link, non-directory component |
| 3 | Diagnostic/system error: inaccessible metadata, required ACL inspection failed, unavailable mount information without an established denial, unsupported platform |

Broken links and other unresolved paths display `UNRESOLVED PATH`, while keeping
exit code 2. Malformed CLI arguments and empty/NUL paths remain invalid input.

## Safety and limitations

The utility only reads identity databases, metadata, access ACLs, symlink
destinations, and mount information. It never changes permissions, ownership, ACLs, memberships,
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
- ACL support covers Linux POSIX **access** ACLs. Default ACLs govern inheritance
  and are not applied to existing inode access; creation/inheritance is not modeled.
  NFSv4 ACLs, Windows/SMB ACLs, idmapped mounts, and filesystem-specific or
  server-side authorization remain unsupported. A filesystem returning ENODATA
  is taken to expose no POSIX access ACL; alternate authorization remains outside
  this model.
- ACL and metadata reads are separate. The consistency check detects differing
  mode bits, but cannot eliminate all races, inode replacement, or policy changes.
- Immutable/append-only flags, security policies, quotas, full filesystems,
  special-device rules, file formats, script interpreters, and executable loaders
  are not checked. A mode-bit check does not prove successful I/O or execution.
- Mount selection uses the visible mountinfo paths. Ambiguous identical mount
  points produce an error; complex overmount arrangements with hidden descendants
  are outside the model.

## Architecture and tests

The modules keep separate layers. `posix_acl.py` contains the read-only ACL
decoder and pure ACL evaluator; `permissionhell.py` integrates their results:

| Layer | Entry point / structured result |
| --- | --- |
| CLI | `main()` |
| Identity | `resolve_subject()` / `Subject` |
| Permission engine | `evaluate_permission()` / `PermissionDecision` |
| ACL inspection and selection | `read_access_acl()`, `evaluate_acl()` / `AccessACL`, `ACLMatch` |
| Path resolution and traversal | `trace_path()` / `PathTrace`, `Inode`, `Symlink` |
| Mount inspection | `read_mounts()`, `find_mount()` / `Mount` |
| Verdict | `diagnose()`, `determine_verdict()` / `Diagnosis` |
| Local inventory | `enumerate_local_accounts()` / `LocalAccount` |
| Audit | `audit_target()` / `AuditReport`, `AccountAudit`, `AuditContext` |
| Presentation | `render_report(report, verbose=False)`, `render_verbose_report()` |
| Audit presentation | `render_audit()` |

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
codes. All original **119** v0.2 semantic/CLI/rendering/ACL tests remain unchanged.

ACL tests cover parsing failures, exclusive selection, masks, supplementary
groups, group unions, traversal, root/owner shortcuts, and rendering. Linux
integration tests apply real ACLs **only to test-owned temporary files and
directories**, exercise symlinks and default/access ACL separation, and clean up
afterward. No root privileges are required. The integration tests skip when the
temporary filesystem cannot manipulate ACLs; parser and decision tests still run.

Audit tests mock local inventory and exercise the existing engine across multiple
subjects. They cover counts, access mechanisms, shared mount reads, per-account
errors, invalid paths, and exit codes. Additional Linux integration tests audit
real local accounts against temporary files/symlinks, without requiring root.

## Roadmap

- JSON output backed by the existing structured results.
- Audit account filtering and `--explain USER` using retained diagnoses.
- Default-ACL inheritance and richer ACL inspection output.
- SELinux and AppArmor context and policy diagnostics.
- Process-aware credentials, capability sets, and mount namespaces.
- Container mappings and filesystem-specific behavior.

Semantics references: Linux [path_resolution(7)](https://man7.org/linux/man-pages/man7/path_resolution.7.html)
and [symlink(7)](https://man7.org/linux/man-pages/man7/symlink.7.html).
ACL references: [acl(5)](https://man7.org/linux/man-pages/man5/acl.5.html),
the Linux kernel's [ACL access algorithm](https://github.com/torvalds/linux/blob/master/fs/posix_acl.c),
and [ACL xattr ABI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/posix_acl_xattr.h).
