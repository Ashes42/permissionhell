# Threat model and trust boundaries

Permission Hell is an observer, not an enforcement boundary. Its output helps
explain a modeled decision; Linux still authorizes the actual operation. It is not
a replacement for kernel checks, audit logs or syscall tracing.

## Subjects and visibility

Account mode models NSS account/group data and traditional privileged root. It
cannot invent a process's profile, credentials, namespaces or capabilities. Live
process mode reads filesystem credentials, group IDs, namespace maps and security
context; UID 0 alone is not a capability override.

The debugger's privileges and proc/sysfs visibility limit evidence. Running as root
may expose more metadata but does not eliminate namespace ambiguity or races.
Foreign mount/root paths are not entered. Proc IDs are debugger-visible and must
not be translated twice. Unsupported mappings or capability scope remain unknown.

## Races and incomplete authorization

Procfs is racy. PID plus start time and context rechecks mitigate reuse but do not
create an atomic snapshot. A task can exit, change credentials or change profile
between observations. Target paths, symlinks, mounts, ACLs and policies can change
between inspection and use (TOCTOU). Snapshot metadata rechecks detect some changes,
not every possible interleaving. Monitor baselines are observations, not guarantees.

LSM awareness does not simulate complete AppArmor/SELinux policies. Enforcing
unevaluated policy may invalidate an ordinary permit; known DAC denials remain
denials. Landlock task rulesets and other documented layers remain unmodeled.
Filesystem-specific behavior, idmapped mounts and inode flags are not fully covered.

## Input and output boundaries

Policies and snapshots are untrusted JSON data, never executable code. Parsers
reject unsupported versions, invalid types and incompatible identities. This is
not a sandbox: arbitrarily large files may consume substantial memory/CPU, there
is no authenticity/signature check, and a forged baseline can misrepresent history.
Read input files and write baselines only from directories appropriate to your
trust boundary. Do not run elevated analysis against attacker-controlled paths
expecting path checks to provide race-proof filesystem confinement.

Snapshot/baseline writes are explicit. Target aliases are rejected, staging files
are private and publication is atomic. These protections are not a guarantee
against an adversary concurrently replacing parent directories or changing target
aliases. Directory fsync and hard-crash durability are not guaranteed. Interrupted
writes may leave staging files. Concurrent explicit monitor updates are last
successful replacement wins; serialize them externally when ordering matters.

## Read-only and privacy guarantees

Analysis never applies chmod/chown, ACL/label updates, remounts, credentials,
namespace entry or process signals. Suggested commands are text only. Application
writes are explicit snapshot/baseline output and staging; shell redirects and
Python bytecode caches have their usual separate behavior.

The tool does not read analyzed target contents, process memory or process
environment variables. It does read explicit input policy/snapshot files and
kernel/account metadata. `audit-processes --verbose` additionally reads available
process command lines, potentially including secrets.

Reports can expose usernames, UIDs/GIDs, process names/PIDs, paths, ACL identities,
namespace mappings, capabilities, LSM labels/profiles, intended policy and snapshot
history. Protect exports and avoid attaching unsanitized reports to public issues.
There is no telemetry, remote reporting, scheduler or background daemon.

See [SECURITY.md](../SECURITY.md) for reporting suspected vulnerabilities.

## Optional LSM evidence trust

Host SELinux bindings/libraries and kernel policy establish only queried vectors
for observed labels, not full syscall authorization. Inode, label, policy sequence
and process rechecks reduce races but are not atomic. Inconsistent/unavailable
queries never create permission. The selinuxfs query exchange does not mutate
policy. Execution transitions and incomplete operation coverage remain unresolved.

AppArmor logs may be stale, incomplete, rotated, forged, or refer to another PID
namespace/generation or inode. Even exact recent matches remain historical
evidence, not authoritative current authorization. Missing records never permit
access. File reads are bounded and refuse symlinks/nonregular files; journal calls
have fixed arguments and a timeout. Journal output is captured before its size
check, so memory use is not absolutely bounded. No root requirement, installation
or network lookup is introduced. Exports can disclose profile names, paths and
audit event IDs. Live enforcing SELinux/AppArmor decisions are tested with mocks;
WSL does not provide a real enforcing-policy integration environment.
