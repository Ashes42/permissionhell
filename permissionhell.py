#!/usr/bin/env python3
"""Permission Hell v0.3: read-only Linux access diagnosis and local-account audits."""

from __future__ import annotations

import argparse
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import IntEnum
import errno
import os
import re
import stat
import sys

from posix_acl import (AccessACL, ACLEntry, ACLMatch, ACLInspectionError, Tag,
                       evaluate_acl, read_access_acl, validate_acl_mode)

try:
    import grp
    import pwd
except ImportError:  # Allow --help and a useful platform error on Windows.
    grp = pwd = None


class ExitCode(IntEnum):
    ALLOWED = 0
    DENIED = 1
    INPUT = 2
    ERROR = 3


OPERATIONS = {"r": (4, "READ"), "w": (2, "WRITE"), "x": (1, "EXECUTE/SEARCH")}


class DiagnosticError(Exception):
    def __init__(self, message: str, code: ExitCode = ExitCode.ERROR):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Subject:
    username: str
    uid: int
    primary_gid: int
    primary_group: str
    supplementary_gids: tuple[int, ...]
    supplementary_groups: tuple[str, ...]

    @property
    def gids(self) -> frozenset[int]:
        return frozenset((self.primary_gid, *self.supplementary_gids))


def group_name(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def owner_name(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def resolve_subject(username: str) -> Subject:
    try:
        entry = pwd.getpwnam(username)
    except KeyError:
        raise DiagnosticError(f"No such user: {username!r}", ExitCode.INPUT) from None
    try:
        gids = tuple(sorted(set(os.getgrouplist(entry.pw_name, entry.pw_gid)) - {entry.pw_gid}))
        return Subject(entry.pw_name, entry.pw_uid, entry.pw_gid, group_name(entry.pw_gid),
                       gids, tuple(group_name(gid) for gid in gids))
    except OSError as exc:
        raise DiagnosticError(f"Cannot resolve groups for {username!r}: {exc}") from exc


@dataclass(frozen=True)
class PermissionDecision:
    permission_class: str
    available: int
    required: int
    allowed: bool
    reason: str
    root_override: bool = False


def evaluate_permission(subject: Subject, inode: os.stat_result, mode: str) -> PermissionDecision:
    """Evaluate the supplied identity, never the debugger's access credentials."""
    required, operation = OPERATIONS[mode]
    if subject.uid == inode.st_uid:
        selected, shift = "OWNER", 6
        reason = f"Subject UID {subject.uid} matches inode owner UID {inode.st_uid}."
    elif inode.st_gid in subject.gids:
        selected, shift = "GROUP", 3
        reason = f"Inode GID {inode.st_gid} matches the subject's primary or supplementary groups."
    else:
        selected, shift = "OTHER", 0
        reason = "Subject is neither the inode owner nor a member of its owning group."
    available = (inode.st_mode >> shift) & 7
    allowed = bool(available & required)
    override = False
    if subject.uid == 0:
        # Explicit v0.1 assumption: traditional privileged root, not namespaced root.
        allowed = mode != "x" or stat.S_ISDIR(inode.st_mode) or bool(inode.st_mode & 0o111)
        override = allowed and not bool(available & required)
        reason += (" Assuming traditional privileged UID 0: read/write and directory search bypass DAC;"
                   " non-directory execution requires at least one execute bit.")
    else:
        reason += f" Only {selected} bits apply; no fallback to another class."
    reason += f" {operation} {'permitted' if allowed else 'denied'} by this DAC model."
    return PermissionDecision(selected, available, required, allowed, reason, override)


@dataclass(frozen=True)
class Inode:
    path: str
    uid: int
    gid: int
    owner: str
    group: str
    mode: int
    decision: PermissionDecision
    acl: AccessACL | None = None
    acl_match: ACLMatch | None = None
    acl_note: str | None = None
    dac_decision: PermissionDecision | None = None


def inspect_inode(path: str, metadata: os.stat_result, subject: Subject, mode: str) -> Inode:
    dac = evaluate_permission(subject, metadata, mode)
    decision = dac
    acl = match = None
    # These decisions are independent of access ACLs. Owner bits mirror user::,
    # which is unmasked; our documented privileged-root model bypasses ACL DAC.
    # Avoid an unnecessary xattr dependency when the answer is already known.
    if subject.uid == 0:
        note = "ACL inspection not needed: traditional privileged root bypasses ACL DAC; execute-bit checks still apply."
    elif subject.uid == metadata.st_uid:
        note = "ACL inspection not needed: OWNER mode bits equal unmasked user:: permissions; no named entry can override them."
    else:
        try:
            acl = read_access_acl(path)
            if acl is not None:
                validate_acl_mode(acl, metadata.st_mode)
                match = evaluate_acl(acl, subject.uid, subject.gids, metadata.st_uid, metadata.st_gid, dac.required)
        except ACLInspectionError as exc:
            raise DiagnosticError(f"ACL inspection failed at {path!r}: {exc} Effective access is unknown.") from exc
        note = "No access ACL (ENODATA)." if acl is None else None
        if acl is not None and acl.extended:
            selected = "ACL USER" if match.selection == "NAMED USER" else match.selection
            decision = PermissionDecision(selected, match.effective, dac.required, match.allowed,
                f"POSIX access ACL {'permits' if match.allowed else 'denies'} {OPERATIONS[mode][1]}"
                f" via {match.selection.lower()} selection; no fallback after a match.")
    return Inode(path, metadata.st_uid, metadata.st_gid, owner_name(metadata.st_uid),
                 group_name(metadata.st_gid), metadata.st_mode, decision, acl, match, note, dac)


@dataclass(frozen=True)
class Symlink:
    path: str
    destination: str


@dataclass
class PathTrace:
    # Ordered events preserve absolute symlink restarts and repeated '..' checks.
    events: list[Inode | Symlink] = field(default_factory=list)
    target: Inode | None = None
    resolved_path: str | None = None
    failure: str | None = None
    code: ExitCode | None = None


def trace_path(path: str, subject: Subject, mode: str) -> PathTrace:
    trace = PathTrace()
    if not path or "\x00" in path:
        trace.failure, trace.code = "Target path is empty or contains a NUL byte.", ExitCode.INPUT
        return trace
    current = "/"
    links = 0
    try:
        # Do not use abspath/normpath/resolve: they can erase mandatory search checks.
        absolute = path if path.startswith("/") else os.getcwd().rstrip("/") + "/" + path
        pending = deque(part for part in absolute.split("/") if part)
        require_directory = path.endswith("/")
        while pending:
            metadata = os.lstat(current)
            if not stat.S_ISDIR(metadata.st_mode):
                raise DiagnosticError(f"Not a directory: {current!r}", ExitCode.INPUT)
            directory = inspect_inode(current, metadata, subject, "x")
            trace.events.append(directory)
            if not directory.decision.allowed:
                trace.failure = f"Traversal blocked at {current!r}: subject lacks execute/search permission."
                trace.code = ExitCode.DENIED
                return trace
            component = pending.popleft()
            candidate = (current.rstrip("/") + "/" + component)
            metadata = os.lstat(candidate)
            if stat.S_ISLNK(metadata.st_mode):
                destination = os.readlink(candidate)
                trace.events.append(Symlink(candidate, destination))
                links += 1
                if links > 40:
                    raise DiagnosticError("Too many symbolic links (Linux limit: 40); possible symlink loop.",
                                          ExitCode.INPUT)
                if not pending and destination.endswith("/"):
                    require_directory = True
                pending.extendleft(reversed([part for part in destination.split("/") if part]))
                if destination.startswith("/"):
                    current = "/"
            else:
                # Normalize only AFTER checking the preceding directory's search bit.
                current = os.path.normpath(candidate)
        metadata = os.lstat(current)
        if require_directory and not stat.S_ISDIR(metadata.st_mode):
            raise DiagnosticError(f"Trailing slash requires a directory: {current!r}", ExitCode.INPUT)
        trace.resolved_path = current
        trace.target = inspect_inode(current, metadata, subject, mode)
    except FileNotFoundError as exc:
        detail = " (possibly a broken symlink)" if links else ""
        trace.failure = f"Path component does not exist{detail}: {exc.filename!r}"
        trace.code = ExitCode.INPUT
    except NotADirectoryError as exc:
        trace.failure, trace.code = f"Not a directory: {exc.filename!r}", ExitCode.INPUT
    except OSError as exc:
        trace.failure = (f"Debugger cannot inspect metadata: {exc}. This is an inspection error,"
                         " not proof that the subject is denied. Try an account able to inspect the path.")
        trace.code = ExitCode.ERROR
    except DiagnosticError as exc:
        trace.failure, trace.code = str(exc), exc.code
    return trace


@dataclass(frozen=True)
class Mount:
    mount_id: int
    point: str
    filesystem: str
    options: frozenset[str]
    super_options: frozenset[str]

    @property
    def readonly(self) -> bool:
        return "ro" in self.options or "ro" in self.super_options


def unescape_mount(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), value)


def parse_mountinfo(content: str) -> list[Mount]:
    mounts = []
    try:
        for line in content.splitlines():
            if not line.strip():
                continue
            left, right = line.split(" - ", 1)
            fields, filesystem = left.split(), right.split()
            if len(fields) < 6 or len(filesystem) < 3 or not fields[4].startswith("/"):
                raise ValueError("missing required fields")
            mounts.append(Mount(int(fields[0]), unescape_mount(fields[4]), filesystem[0],
                                frozenset(fields[5].split(",")), frozenset(filesystem[2].split(","))))
        if not mounts:
            raise ValueError("mount table is empty")
    except (ValueError, IndexError) as exc:
        raise DiagnosticError(f"Cannot parse /proc/self/mountinfo: {exc}") from exc
    return mounts


def read_mounts() -> list[Mount]:
    try:
        with open("/proc/self/mountinfo", encoding="utf-8", errors="surrogateescape") as source:
            return parse_mountinfo(source.read())
    except OSError as exc:
        raise DiagnosticError(f"Cannot inspect /proc/self/mountinfo: {exc}") from exc


def find_mount(path: str, mounts: list[Mount]) -> Mount:
    matches = [mount for mount in mounts
               if mount.point == "/" or path == mount.point or path.startswith(mount.point.rstrip("/") + "/")]
    if not matches:
        raise DiagnosticError(f"No mount information matches {path!r}.")
    longest = max(len(mount.point) for mount in matches)
    matches = [mount for mount in matches if len(mount.point) == longest]
    if len(matches) != 1:
        raise DiagnosticError(f"Ambiguous stacked mounts for {path!r}; cannot identify the visible mount reliably.")
    return matches[0]


@dataclass
class Diagnosis:
    subject: Subject
    requested_path: str
    mode: str
    trace: PathTrace
    mount: Mount | None = None
    mount_error: str | None = None
    code: ExitCode = ExitCode.ERROR
    reasons: list[str] = field(default_factory=list)


def determine_verdict(report: Diagnosis) -> None:
    """Combine independently collected DAC/path and mount results."""
    if report.trace.failure:
        report.code = report.trace.code
        report.reasons.append(report.trace.failure)
        return
    target = report.trace.target
    if not target.decision.allowed:
        report.reasons.append(f"{report.subject.username} lacks {OPERATIONS[report.mode][1]} permission on {target.path!r}.")
        report.reasons.append(target.decision.reason)
    if report.mount:
        if report.mode == "w" and report.mount.readonly:
            report.reasons.append(f"Mount {report.mount.point!r} is READ-ONLY and blocks writing.")
        if report.mode == "x" and not stat.S_ISDIR(target.mode) and "noexec" in report.mount.options:
            report.reasons.append(f"Mount {report.mount.point!r} has noexec and blocks direct execution.")
    if report.reasons:
        report.code = ExitCode.DENIED
    elif report.mount_error:
        report.code = ExitCode.ERROR
        report.reasons.append("DAC permits access, but mount restrictions could not be determined.")
    else:
        report.code = ExitCode.ALLOWED
        report.reasons.append("Every required directory permits search, the target permits the requested mode,"
                              " and the inspected mount imposes no applicable restriction.")


def diagnose(path: str, subject: Subject, mode: str, *,
             mount_reader: Callable[[], list[Mount]] | None = None) -> Diagnosis:
    report = Diagnosis(subject, path, mode, trace_path(path, subject, mode))
    if report.trace.resolved_path is not None:
        try:
            report.mount = find_mount(report.trace.resolved_path, (mount_reader or read_mounts)())
        except DiagnosticError as exc:
            report.mount_error = str(exc)
    determine_verdict(report)
    return report


@dataclass(frozen=True)
class LocalAccount:
    username: str
    uid: int
    primary_gid: int


def enumerate_local_accounts() -> list[LocalAccount]:
    """Inventory explicit /etc/passwd records, not remote NSS enumeration.

    Authentication fields are neither retained nor displayed. Compat +/- NIS
    directives are not local account definitions and are deliberately ignored.
    """
    accounts = []
    names = set()
    try:
        with open("/etc/passwd", encoding="utf-8", errors="surrogateescape") as source:
            for line_number, raw in enumerate(source, 1):
                line = raw.rstrip("\n")
                if not line.strip() or line.lstrip().startswith("#") or line.startswith(("+", "-")):
                    continue
                fields = line.split(":")
                if (len(fields) != 7 or not fields[0] or "\x00" in line
                        or not re.fullmatch(r"[0-9]+", fields[2])
                        or not re.fullmatch(r"[0-9]+", fields[3])):
                    raise DiagnosticError(f"Malformed local account record at /etc/passwd:{line_number}.")
                numeric = [value.lstrip("0") or "0" for value in fields[2:4]]
                if any(len(value) > 10 for value in numeric):
                    raise DiagnosticError(f"Invalid UID/GID at /etc/passwd:{line_number}.")
                uid, gid = map(int, numeric)
                if uid >= 0xFFFFFFFF or gid >= 0xFFFFFFFF:
                    raise DiagnosticError(f"Invalid UID/GID at /etc/passwd:{line_number}.")
                if fields[0] in names:
                    raise DiagnosticError(f"Duplicate local username at /etc/passwd:{line_number}.")
                names.add(fields[0])
                accounts.append(LocalAccount(fields[0], uid, gid))
    except OSError as exc:
        raise DiagnosticError(f"Cannot enumerate local accounts from /etc/passwd: {exc}") from exc
    return sorted(accounts, key=lambda account: account.username)


@dataclass
class AccountAudit:
    account: LocalAccount
    diagnosis: Diagnosis | None = None
    error: str | None = None


@dataclass
class AuditReport:
    requested_path: str
    mode: str
    permitted: list[AccountAudit] = field(default_factory=list)
    denied: list[AccountAudit] = field(default_factory=list)
    errors: list[AccountAudit] = field(default_factory=list)
    failure: str | None = None
    code: ExitCode = ExitCode.ALLOWED


@dataclass
class AuditContext:
    """One audit's shared inspection context; never cache subject decisions."""
    mounts: list[Mount] | None = None
    mount_error: DiagnosticError | None = None

    def read_mounts(self) -> list[Mount]:
        if self.mount_error is not None:
            raise self.mount_error
        if self.mounts is None:
            try:
                self.mounts = read_mounts()
            except DiagnosticError as exc:
                self.mount_error = exc
                raise
        return self.mounts


def inspect_audit_target(path: str) -> None:
    """Check existence as the debugger, not subject access; preserve the raw path.

    Otherwise all subjects could fail early traversal and conceal a missing or
    broken target. Every account still undergoes the normal subject traversal.
    """
    if not path or "\x00" in path:
        raise DiagnosticError("Target path is empty or contains a NUL byte.", ExitCode.INPUT)
    try:
        os.stat(path)
    except (FileNotFoundError, NotADirectoryError) as exc:
        raise DiagnosticError(f"Unresolved target {path!r} (missing component, broken link, or non-directory): {exc}",
                              ExitCode.INPUT) from exc
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise DiagnosticError(f"Unresolved target {path!r}: too many symbolic links.", ExitCode.INPUT) from exc
        raise DiagnosticError(f"Debugger cannot inspect audit target {path!r}: {exc}") from exc


def audit_target(path: str, mode: str = "r") -> AuditReport:
    report = AuditReport(path, mode)
    try:
        inspect_audit_target(path)
        accounts = enumerate_local_accounts()
        if not accounts:
            raise DiagnosticError("No local accounts found in /etc/passwd; no identities were evaluated.")
    except DiagnosticError as exc:
        report.failure, report.code = str(exc), exc.code
        return report
    context = AuditContext()
    path_error = False
    for account in accounts:
        try:
            subject = resolve_subject(account.username)
            if (subject.username, subject.uid, subject.primary_gid) != (
                    account.username, account.uid, account.primary_gid):
                raise DiagnosticError("System identity lookup disagrees with the local account record;"
                                      " account may have changed or an NSS identity may shadow it.")
            diagnosis = diagnose(path, subject, mode, mount_reader=context.read_mounts)
        except (DiagnosticError, OSError) as exc:
            report.errors.append(AccountAudit(account, error=str(exc)))
            continue
        result = AccountAudit(account, diagnosis=diagnosis)
        if diagnosis.code == ExitCode.ALLOWED:
            report.permitted.append(result)
        elif diagnosis.code == ExitCode.DENIED:
            report.denied.append(result)
        else:
            # Unknown identity/ACL/metadata states are never counted as denials.
            result.error = diagnosis.trace.failure or "; ".join(diagnosis.reasons)
            report.errors.append(result)
            path_error |= diagnosis.code == ExitCode.INPUT
    if path_error:
        report.code = ExitCode.INPUT
        report.failure = "Path resolution failed during the audit; the filesystem may have changed."
    elif report.errors:
        report.code = ExitCode.ERROR  # Partial results remain useful, but completion is not success.
    return report


def bits(value: int) -> str:
    return "".join(letter if value & bit else "-" for bit, letter in ((4, "r"), (2, "w"), (1, "x")))


SCOPE_TEXT = (
    "Scope: account database groups; debugger's mount namespace; traditional privileged root.\n"
    "Modeled: Unix DAC, POSIX ACLs (access ACLs), and mount restrictions.\n"
    "Not modeled: SELinux, AppArmor, process capabilities, user namespaces,\n"
    "container UID/GID mappings, NFS/SMB/FUSE rules, inode flags, or other process restrictions.\n"
    "This is a read-only model, not a guarantee that an actual syscall will succeed."
)


def verdict_label(report: Diagnosis) -> str:
    # A path that cannot resolve is not necessarily malformed CLI input.
    # This presentation distinction intentionally leaves the exit code unchanged.
    if report.code == ExitCode.INPUT and report.requested_path and "\x00" not in report.requested_path:
        return "UNRESOLVED PATH"
    return {ExitCode.ALLOWED: "ACCESS PERMITTED", ExitCode.DENIED: "ACCESS DENIED",
            ExitCode.INPUT: "INVALID INPUT", ExitCode.ERROR: "DIAGNOSIS INCOMPLETE"}[report.code]


def access_summary(inode: Inode, subject: Subject) -> str:
    decision = inode.decision
    ordinary = f"{decision.permission_class} {bits(decision.available)}"
    if subject.uid == 0:
        label = "ROOT OVERRIDE" if decision.root_override else "ROOT"
        return f"{label} [ordinary {ordinary}]"
    if acl_relevant(inode):
        return f"ACL {inode.acl_match.selection} {bits(inode.acl_match.effective)}"
    return ordinary


def acl_relevant(inode: Inode) -> bool:
    """Whether ACL detail helps explain this particular subject's access."""
    match = inode.acl_match
    return bool(inode.acl and inode.acl.extended and match and (
        match.selection == "NAMED USER"
        or any(entry.tag == Tag.GROUP for entry in match.entries)
        or match.specified != match.effective
        or (inode.dac_decision and match.effective != inode.dac_decision.available)))


def acl_entry_text(entry: ACLEntry) -> str:
    tag = {Tag.OWNER: "user", Tag.USER: "user", Tag.GROUP_OBJ: "group",
           Tag.GROUP: "group", Tag.MASK: "mask", Tag.OTHER: "other"}[entry.tag]
    qualifier = "" if entry.qualifier is None else str(entry.qualifier)
    return f"{tag}:{qualifier}:{bits(entry.permissions)}"


def acl_explanation(inode: Inode) -> str:
    match = inode.acl_match
    entries = ", ".join(acl_entry_text(entry) for entry in match.entries)
    prefix = f"ACL {match.selection}: {entries}."
    if match.selection == "GROUP":
        prefix += f" Group union: {bits(match.specified)}."
    if match.mask is not None:
        prefix += f" Mask: {bits(match.mask)}; effective: {bits(match.effective)}."
        if match.specified & match.required and not match.effective & match.required:
            operation = {4: "READ", 2: "WRITE", 1: "EXECUTE/SEARCH"}[match.required]
            return prefix + f" The ACL mask removes {operation}; access denied, no fallback."
    else:
        prefix += f" Effective: {bits(match.effective)} (unmasked)."
    operation = {4: "READ", 2: "WRITE", 1: "EXECUTE/SEARCH"}[match.required]
    if match.allowed:
        return prefix + f" {operation} permitted."
    return prefix + f" Selected ACL permissions lack {operation}; access denied, no fallback."


def render_acl(inode: Inode, verbose: bool = False) -> list[str]:
    if verbose:
        if inode.acl_note:
            return [f"  ACL: {inode.acl_note}"]
        if inode.acl is not None:
            lines = ["  ACL (access):"]
            for entry in inode.acl.entries:
                marker = " [matched]" if entry in inode.acl_match.entries else ""
                lines.append(f"    {acl_entry_text(entry)}{marker}")
            lines.append(f"    {acl_explanation(inode)}")
            if inode.acl.extended:
                lines.append("    Mode group bits represent mask::, not group:: permissions.")
                if inode.dac_decision:
                    dac = inode.dac_decision
                    lines.append(f"    Mode-only comparison: {dac.permission_class} {bits(dac.available)}"
                                 f" -> {'PERMITTED' if dac.allowed else 'DENIED'}; ACL result governs.")
            return lines
    if acl_relevant(inode):
        return [f"  {acl_explanation(inode)}"]
    return []


def denial_explanation(inode: Inode, subject: Subject) -> str:
    decision = inode.decision
    if subject.uid == 0:
        return "Root still needs at least one execute bit on a non-directory inode; none is set."
    if acl_relevant(inode):
        return acl_explanation(inode)
    selected = decision.permission_class
    why = {"OWNER": f"UID {subject.uid} owns this inode",
           "GROUP": f"subject belongs to owning GID {inode.gid}",
           "OTHER": "subject is neither owner nor in the owning group"}[selected]
    return (f"{selected} selected: {why}. Its {bits(decision.available)} bits lack "
            f"{bits(decision.required).replace('-', '')}; no fallback to another class.")


def concise_reasons(report: Diagnosis) -> list[str]:
    if report.code == ExitCode.ALLOWED:
        return ["Directory search and target access pass; no applicable mount restriction."]
    if report.trace.failure:
        lines = [report.trace.failure]
        blocked = next((event for event in report.trace.events
                        if isinstance(event, Inode) and not event.decision.allowed), None)
        if blocked:
            lines.append(denial_explanation(blocked, report.subject))
        return lines
    target = report.trace.target
    # Retain the verdict engine's reasons (including all mount restrictions),
    # replacing only its long DAC paragraph with a compact explanation.
    return [denial_explanation(target, report.subject)
            if target and reason == target.decision.reason else reason
            for reason in report.reasons]


def render_report(report: Diagnosis, verbose: bool = False) -> str:
    if verbose:
        return render_verbose_report(report)
    subject, target = report.subject, report.trace.target
    path = repr(report.requested_path)
    if report.trace.resolved_path is not None and report.trace.resolved_path != report.requested_path:
        path += f" -> {report.trace.resolved_path!r}"
    lines = [f"PERMISSION HELL v0.3 | {OPERATIONS[report.mode][1]} as {subject.username} (UID {subject.uid})",
             f"Target: {path}", "", f"{verdict_label(report)} (DAC + ACL + mount model)",
             *concise_reasons(report)]
    if subject.uid == 0:
        lines.append("Root: assumes privileged UID 0; DAC bypasses are marked ROOT OVERRIDE.")
    lines.extend(["", "PATH (search x)"])
    seen = set()
    repeated = 0
    for event in report.trace.events:
        if isinstance(event, Symlink):
            lines.append(f"  LINK {event.path!r} -> {event.destination!r}")
            continue
        # Collapse only identical successful observations; never hide a failure
        # or a changed inode. The full event sequence remains available in verbose.
        if event.decision.allowed and event in seen:
            repeated += 1
            continue
        seen.add(event)
        status = "PASS" if event.decision.allowed else "FAIL"
        marker = "" if event.decision.allowed else "  <-- BLOCKED HERE"
        lines.append(f"  {status} {event.path!r}  {access_summary(event, subject)}{marker}")
        if event.decision.allowed:  # Failure reasoning is already prominent above.
            lines.extend(render_acl(event))
    if repeated:
        lines.append(f"  ({repeated} repeated successful search checks omitted; --verbose shows all)")
    if not report.trace.events:
        lines.append("  No parent search steps." if target else "  Resolution did not start.")
    lines.append("")
    if target:
        status = "PASS" if target.decision.allowed else "FAIL"
        marker = "" if target.decision.allowed else "  <-- BLOCKED HERE"
        lines.extend([f"TARGET {status} {target.path!r}{marker}",
                      f"  Owner: {target.owner} ({target.uid}) | Group: {target.group} ({target.gid})"
                      f" | Mode: {stat.S_IMODE(target.mode):04o} ({stat.filemode(target.mode)})",
                      f"  Access: {access_summary(target, subject)} | Required: {OPERATIONS[report.mode][1]} ({report.mode})"])
        if target.decision.allowed:
            lines.extend(render_acl(target))
    else:
        lines.append("Target and mount not evaluated: path traversal did not complete."
                     if report.trace.resolved_path is None else
                     "Target access not evaluated: inspection did not complete.")
    if report.mount:
        mount = report.mount
        options = "READ-ONLY" if mount.readonly else "READ-WRITE"
        if "noexec" in mount.options:
            options += ", noexec"
        lines.append(f"Mount: {mount.point!r} | {mount.filesystem} | {options}")
    if report.mount_error:
        lines.append(f"Mount inspection error: {report.mount_error}")
    return "\n".join(lines)


def render_verbose_report(report: Diagnosis) -> str:
    subject = report.subject
    lines = ["PERMISSION HELL v0.3", f"Diagnosing {OPERATIONS[report.mode][1]} access", "",
             "SUBJECT", f"User: {subject.username} (UID {subject.uid})",
             f"Primary group: {subject.primary_group} (GID {subject.primary_gid})",
             "Supplementary groups: " + (", ".join(f"{name} ({gid})" for name, gid in
                zip(subject.supplementary_groups, subject.supplementary_gids)) or "none"),
             "", "TARGET", repr(report.requested_path), "", "PATH TRAVERSAL"]
    for event in report.trace.events:
        if isinstance(event, Symlink):
            lines.append(f"LINK {event.path!r} -> {event.destination!r}")
            continue
        decision = event.decision
        lines.extend([f"{'PASS' if decision.allowed else 'FAIL'} {event.path!r}  {access_summary(event, subject)}"
                      f"  requires x"
                      f"  UID={event.uid} GID={event.gid} mode={stat.S_IMODE(event.mode):04o}",
                      f"     {decision.reason}"])
        lines.extend(render_acl(event, verbose=True))
    if not report.trace.events:
        lines.append("No parent components to traverse (or resolution could not start).")
    lines.extend(["", "TARGET INODE"])
    target = report.trace.target
    if target:
        lines.extend([f"Resolved path: {report.trace.resolved_path!r}",
                      f"Owner: {target.owner} (UID {target.uid})", f"Group: {target.group} (GID {target.gid})",
                      f"Mode: {stat.S_IMODE(target.mode):04o} ({stat.filemode(target.mode)})",
                      f"Access: {access_summary(target, subject)}",
                      f"Required: {OPERATIONS[report.mode][1]} ({report.mode})",
                      f"Available: {bits(target.decision.available)}",
                      f"DAC: {'PERMITTED' if target.decision.allowed else 'DENIED'}",
                      target.decision.reason])
        lines.extend(render_acl(target, verbose=True))
    else:
        lines.append("Not evaluated: path resolution/traversal did not complete.")
    lines.extend(["", "MOUNT"])
    if report.mount:
        mount = report.mount
        lines.extend([f"Mount point: {mount.point!r}", f"Filesystem: {mount.filesystem}",
                      f"Mount options: {','.join(sorted(mount.options))}",
                      f"Filesystem options: {','.join(sorted(mount.super_options))}",
                      f"Status: {'READ-ONLY' if mount.readonly else 'READ-WRITE'}"])
    else:
        lines.append(report.mount_error or "Not evaluated: target path was not resolved.")
    lines.extend(["", verdict_label(report) + " (v0.3 DAC + ACL + mount model)", *report.reasons, "", SCOPE_TEXT])
    return "\n".join(lines)


def audit_access_reason(inode: Inode, subject: Subject) -> str:
    if subject.uid == 0:
        return f"Access via {access_summary(inode, subject)}; assumes traditional privileged UID 0."
    if acl_relevant(inode):
        reason = acl_explanation(inode)
        supplementary = sorted({inode.gid if entry.tag == Tag.GROUP_OBJ else entry.qualifier
                                for entry in inode.acl_match.entries
                                if entry.tag in (Tag.GROUP_OBJ, Tag.GROUP)} & set(subject.supplementary_gids))
        if supplementary:
            reason += " Matching supplementary GIDs: " + ", ".join(map(str, supplementary)) + "."
        return reason
    selected = inode.decision.permission_class
    if selected == "GROUP":
        kind = "primary" if inode.gid == subject.primary_gid else "supplementary"
        return (f"Access via GROUP ({kind} group {inode.group}, GID {inode.gid});"
                f" effective: {bits(inode.decision.available)}.")
    return f"Access via {selected}; effective: {bits(inode.decision.available)}."


def audit_denial_reason(inode: Inode, subject: Subject) -> str:
    if subject.uid == 0 or acl_relevant(inode):
        return denial_explanation(inode, subject)
    selected = inode.decision.permission_class
    why = {"OWNER": f"matches owner UID {inode.uid}",
           "GROUP": f"matches owning GID {inode.gid}",
           "OTHER": "neither owner nor in the owning group"}[selected]
    return f"{selected} {bits(inode.decision.available)} ({why})."


def audit_account_lines(result: AccountAudit) -> list[str]:
    diagnosis = result.diagnosis
    if result.error is not None:
        lines = [result.error]
        if diagnosis and diagnosis.mount_error:
            lines.append(diagnosis.mount_error)
        return lines
    subject, target = diagnosis.subject, diagnosis.trace.target
    if diagnosis.code == ExitCode.ALLOWED:
        lines = [audit_access_reason(target, subject)]
        # Surface ACL-dependent parent search without repeating every ordinary
        # successful path component. The structured result retains the full trace.
        seen = set()
        for event in diagnosis.trace.events:
            if isinstance(event, Inode) and event not in seen:
                seen.add(event)
                if acl_relevant(event):
                    lines.append(f"Search at {event.path!r}: {audit_access_reason(event, subject)}")
                elif event.decision.root_override:
                    lines.append(f"Search at {event.path!r}: ROOT OVERRIDE.")
        return lines
    if diagnosis.trace.failure:
        blocked = next((event for event in diagnosis.trace.events
                        if isinstance(event, Inode) and not event.decision.allowed), None)
        if blocked:
            return [f"BLOCKED at {blocked.path!r}: missing EXECUTE/SEARCH.",
                    audit_denial_reason(blocked, subject)]
        return [diagnosis.trace.failure]
    lines = []
    if not target.decision.allowed:
        lines.extend([f"BLOCKED at {target.path!r}: missing {OPERATIONS[diagnosis.mode][1]}.",
                      audit_denial_reason(target, subject)])
        # The engine lists the target denial and detailed DAC reason first.
        mount_reasons = diagnosis.reasons[2:]
    else:
        mount_reasons = diagnosis.reasons
    lines.extend(f"BLOCKED by mount: {reason}" for reason in mount_reasons)
    return lines


def audit_group_key(result: AccountAudit) -> tuple | None:
    """Conservative display equivalence, never an access decision.

    Only ordinary OTHER paths are candidates. Comparing complete observations
    avoids hiding differences in traversal, ACLs, resolved paths, or mounts just
    because their short explanations happen to look alike.
    """
    diagnosis = result.diagnosis
    if (result.error is not None or diagnosis is None or diagnosis.subject.uid == 0
            or diagnosis.code not in (ExitCode.ALLOWED, ExitCode.DENIED) or diagnosis.mount_error):
        return None
    trace = diagnosis.trace
    inodes = [event for event in trace.events if isinstance(event, Inode)]
    if trace.target is not None:
        inodes.append(trace.target)
    if not inodes or any(inode.decision.permission_class != "OTHER"
                         or inode.decision.root_override or acl_relevant(inode) for inode in inodes):
        return None
    if diagnosis.code == ExitCode.DENIED:
        if trace.failure:
            if not any(not inode.decision.allowed for inode in inodes):
                return None
        elif (trace.target is None or trace.target.decision.allowed or len(diagnosis.reasons) != 2):
            # Keep mount denials (including an additional mount restriction
            # after target denial) individual. The engine retains both reasons.
            return None
    return (diagnosis.code, diagnosis.mode, diagnosis.requested_path, tuple(trace.events),
            trace.target, trace.resolved_path, trace.failure, diagnosis.mount,
            tuple(audit_account_lines(result)))


def audit_display_groups(accounts: list[AccountAudit], verbose: bool = False) -> list[list[AccountAudit]]:
    if verbose:
        return [[result] for result in accounts]
    keys = [audit_group_key(result) for result in accounts]
    buckets = {}
    for result, key in zip(accounts, keys):
        if key is not None:
            buckets.setdefault(key, []).append(result)
    if not buckets:
        return [[result] for result in accounts]
    bulk_key = max(buckets, key=lambda key: len(buckets[key]))
    if len(buckets[bulk_key]) < 3:
        return [[result] for result in accounts]
    # Collapse only the dominant repeated result in this section. Less-common
    # failure locations and materially different paths stay individually visible.
    groups = []
    emitted = False
    for result, key in zip(accounts, keys):
        if key == bulk_key:
            if not emitted:
                groups.append(buckets[bulk_key])
                emitted = True
        else:
            groups.append([result])
    return groups


def render_audit(report: AuditReport, verbose: bool = False) -> str:
    operation = OPERATIONS[report.mode][1]
    lines = ["PERMISSION HELL v0.3 | ACCESS AUDIT", f"Target: {report.requested_path!r}",
             f"Requested: {operation} ({report.mode})", "Local accounts: /etc/passwd (including service accounts)", ""]
    resolved = sorted({result.diagnosis.trace.resolved_path
                       for result in report.permitted + report.denied + report.errors
                       if result.diagnosis and result.diagnosis.trace.resolved_path is not None})
    if resolved and resolved != [report.requested_path]:
        lines.extend(["Resolved target(s): " + ", ".join(repr(path) for path in resolved), ""])
    if report.failure:
        label = "INVALID INPUT / UNRESOLVED PATH" if report.code == ExitCode.INPUT else "AUDIT INCOMPLETE"
        lines.extend([label, report.failure, ""])
    elif report.errors:
        lines.extend(["AUDIT INCOMPLETE: some accounts could not be evaluated.", ""])
    permitted, denied, errors = len(report.permitted), len(report.denied), len(report.errors)
    lines.extend([f"{permitted} account{'s' if permitted != 1 else ''} permitted"
                  f" | {denied} account{'s' if denied != 1 else ''} denied"
                  f" | {errors} account error{'s' if errors != 1 else ''}",
                  "Permitted means parent search, target access, and mount checks passed."])
    compressed = False
    for title, accounts in (("PERMITTED", report.permitted), ("DENIED", report.denied), ("ERRORS / UNKNOWN", report.errors)):
        if not accounts:
            continue
        lines.extend(["", title])
        for group in audit_display_groups(accounts, verbose=verbose):
            result = group[0]
            if len(group) == 1:
                lines.append(f"  {result.account.username} (UID {result.account.uid})")
            else:
                compressed = True
                sample = ", ".join(entry.account.username for entry in group[:3])
                more = f"; +{len(group) - 3} more" if len(group) > 3 else ""
                lines.append(f"  {len(group)} accounts with the same result (sample: {sample}{more})")
            lines.extend(f"    {line}" for line in audit_account_lines(result))
    if compressed:
        lines.append("\nGrouped identical OTHER results; use --verbose for the full account list.")
    # A known DAC denial can be definitive even if mount inspection failed.
    mount_notes = sorted({result.diagnosis.mount_error for result in report.denied
                          if result.diagnosis.mount_error})
    lines.extend(f"\nInspection note (known denials retained): {note}" for note in mount_notes)
    lines.extend(["", "Modeled DAC + ACL + mount access, not intended authorization policy."])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="permissionhell", description=__doc__, epilog=SCOPE_TEXT)
    parser.add_argument("--version", action="version", version="permissionhell 0.3.0")
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("diagnose", help="Explain Linux DAC, ACL, and mount access decisions", epilog=SCOPE_TEXT)
    command.add_argument("target_path")
    command.add_argument("--as", dest="username", required=True, help="Account to evaluate")
    command.add_argument("--mode", choices=OPERATIONS, default="r")
    command.add_argument("--verbose", action="store_true",
                         help="Show all traversal checks, detailed reasoning, groups, mount options, and limitations")
    audit = commands.add_parser("audit", help="Show modeled access for every explicit local /etc/passwd account",
                                epilog="Includes service accounts; reports modeled access, not intended policy. " + SCOPE_TEXT)
    audit.add_argument("target_path")
    audit.add_argument("--mode", choices=OPERATIONS, default="r")
    audit.add_argument("--verbose", action="store_true", help="Show every account individually without grouping")
    args = parser.parse_args(argv)
    if not sys.platform.startswith("linux"):
        print("permissionhell: unsupported platform; diagnosis requires Linux.", file=sys.stderr)
        return ExitCode.ERROR
    try:
        if args.command == "audit":
            audit_report = audit_target(args.target_path, args.mode)
            print(render_audit(audit_report, verbose=args.verbose))
            return audit_report.code
        subject = resolve_subject(args.username)
        report = diagnose(args.target_path, subject, args.mode)
        print(render_report(report, verbose=args.verbose))
        return report.code
    except (DiagnosticError, OSError) as exc:
        print(f"permissionhell: {exc}", file=sys.stderr)
        return exc.code if isinstance(exc, DiagnosticError) else ExitCode.ERROR


if __name__ == "__main__":
    sys.exit(main())
