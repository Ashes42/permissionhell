#!/usr/bin/env python3
"""Permission Hell: read-only Linux access diagnosis and change suggestions."""

from __future__ import annotations

import argparse
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from enum import IntEnum
import errno
import os
import re
import shlex
import stat
import sys

import json_output
import lsm
from process_subject import ProcessSubject, ProcessInspectionError, inspect_process
from capabilities import CapabilitySet, CapabilityDecision, CapabilityError, evaluate_capabilities
from idmap import NamespaceIdentity, IDMapError, namespace_identity

__version__ = "1.5.0"


def display_version() -> str:
    """Compact release label derived from the package's canonical version."""
    return "v" + (__version__[:-2] if __version__.endswith(".0") else __version__)

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
    def __init__(self, message: str, code: ExitCode = ExitCode.ERROR, *, kind: str | None = None,
                 partial_inode: Inode | None = None):
        super().__init__(message)
        self.code = code
        self.kind = kind
        self.partial_inode = partial_inode


@dataclass(frozen=True)
class Subject:
    username: str
    uid: int
    primary_gid: int
    primary_group: str
    supplementary_gids: tuple[int, ...]
    supplementary_groups: tuple[str, ...]
    process_identity: bool = False
    effective_capabilities: CapabilitySet | None = None
    capability_context_supported: bool = True
    namespace_identity: NamespaceIdentity | None = None
    uncertain_groups: bool = False
    capability_context_reason: str | None = None

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
    if subject.uid == 0 and not subject.process_identity:
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
    base_decision: PermissionDecision | None = None
    capability_decision: CapabilityDecision | None = None


def inspect_inode(path: str, metadata: os.stat_result, subject: Subject, mode: str) -> Inode:
    dac = evaluate_permission(subject, metadata, mode)
    decision = dac
    acl = match = None
    # These decisions are independent of access ACLs. Owner bits mirror user::,
    # which is unmasked; our documented privileged-root model bypasses ACL DAC.
    # Avoid an unnecessary xattr dependency when the answer is already known.
    if subject.uid == 0 and not subject.process_identity:
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
    base = capability = None
    if subject.process_identity:
        base = decision
        if subject.uncertain_groups and subject.uid != metadata.st_uid:
            # Unknown groups must never become a grant or a false OTHER fallback.
            # For single-bit requests, each possible matching group suffices to
            # check whether an additional group could change the ordinary result.
            candidates = {metadata.st_gid}
            if acl and acl.extended:
                candidates.update(entry.qualifier for entry in acl.entries if entry.tag == Tag.GROUP)
            for gid in candidates:
                if acl and acl.extended:
                    alternative = evaluate_acl(acl, subject.uid, subject.gids | {gid}, metadata.st_uid,
                                               metadata.st_gid, base.required)
                else:
                    alternative = evaluate_permission(replace(subject, supplementary_gids=(*subject.supplementary_gids, gid)),
                                                      metadata, mode)
                if alternative.allowed != base.allowed:
                    raise DiagnosticError(f"Unresolved process GID translation could change DAC/ACL access at {path!r}.",
                                          kind="group_mapping_unresolved")
        try:
            capability = evaluate_capabilities(base.allowed, metadata.st_mode, base.required,
                                                subject.effective_capabilities, subject.capability_context_supported,
                                                context_reason=subject.capability_context_reason)
        except CapabilityError as exc:
            kind = "capability_scope_unestablished" if subject.capability_context_reason else "capability_unknown"
            partial = Inode(path, metadata.st_uid, metadata.st_gid, owner_name(metadata.st_uid),
                            group_name(metadata.st_gid), metadata.st_mode, base, acl, match, note, dac, base)
            raise DiagnosticError(f"Capability inspection at {path!r}: {exc}", kind=kind, partial_inode=partial) from exc
        decision = replace(base, allowed=capability.allowed, reason=base.reason + " " + capability.reason)
    return Inode(path, metadata.st_uid, metadata.st_gid, owner_name(metadata.st_uid),
                 group_name(metadata.st_gid), metadata.st_mode, decision, acl, match, note, dac, base, capability)


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
    error_kind: str | None = None
    partial_inode: Inode | None = None


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
        trace.error_kind = exc.kind
        trace.partial_inode = exc.partial_inode
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


@dataclass
class AuditExplanation:
    """Focused audit result; retain the complete engine diagnosis for expansion."""

    diagnosis: Diagnosis

    @property
    def code(self) -> ExitCode:
        return self.diagnosis.code


def explain_audit_target(path: str, username: str, mode: str = "r") -> AuditExplanation:
    """Evaluate only the explicitly named identity, using the diagnosis engine.

    Unlike inventory audit, no /etc/passwd enumeration or global path preflight
    is needed: the subject's own ordered traversal provides the focused result.
    Explicit names use the same system identity lookup as diagnose, including NSS.
    This separate result keeps audit framing extensible without another evaluator.
    """
    return AuditExplanation(diagnose(path, resolve_subject(username), mode))


@dataclass
class ProcessDiagnosis:
    requested_path: str
    pid: int
    mode: str
    process: ProcessSubject | None = None
    diagnosis: Diagnosis | None = None
    limitations: list[str] = field(default_factory=list)
    code: ExitCode = ExitCode.ERROR
    namespace_identity: NamespaceIdentity | None = None
    indeterminate_reason: str | None = None
    inspection_kind: str | None = None
    lsm: lsm.LSMState | None = None
    lsm_result: lsm.LSMDecision | None = None


def process_filesystem_subject(process: ProcessSubject) -> Subject:
    """Adapt proc credentials to the existing DAC/ACL interface; no NSS groups."""
    identity = namespace_identity(process)
    if not identity.fsuid.mapped_ok:
        raise DiagnosticError(f"Cannot establish filesystem UID mapping for observed debugger UID {identity.fsuid.observed}: "
                              f"{identity.fsuid.reason}.", kind="uid_mapping_unresolved")
    uid, gid = identity.fsuid.mapped, identity.fsgid.mapped
    groups = tuple(g.mapped for g in identity.supplementary if g.mapped_ok)
    uncertain_groups = not identity.fsgid.mapped_ok or any(not g.mapped_ok for g in identity.supplementary)
    # Conservative support boundary for capabilities: no namespace translation.
    supported = identity.same_as_debugger is True and all(mapping is not None and len(mapping) == 1 and
                    (mapping[0].inside, mapping[0].outside, mapping[0].length) == (0, 0, 0xFFFFFFFF)
                    for mapping in (process.uid_map, process.gid_map))
    reason = ("Capability scope over this debugger-visible inode cannot be established for a foreign user namespace."
              if identity.same_as_debugger is False else None)
    return Subject(process.uid_names.get(uid) or str(uid), uid, gid if gid is not None else -1,
                   process.gid_names.get(gid) or (str(gid) if gid is not None else "unresolved"),
                   groups, tuple(process.gid_names.get(g) or str(g) for g in groups),
                   True, process.status.capabilities.effective, supported, identity, uncertain_groups, reason)


def diagnose_process(path: str, pid: int, mode: str = "r") -> ProcessDiagnosis:
    report = ProcessDiagnosis(path, pid, mode)
    if not path.startswith("/") or "\x00" in path:
        report.code = ExitCode.INPUT
        report.limitations.append("Process targets must be absolute paths in the debugger's root; no process cwd translation is performed.")
        return report
    try:
        report.process = inspect_process(pid)
        report.lsm = report.process.lsm
        report.namespace_identity = namespace_identity(report.process)
        report.limitations.extend(report.process.limitations)
        if report.limitations:
            report.indeterminate_reason = "path_context_unresolved"
            return report
        diagnosis = diagnose(path, process_filesystem_subject(report.process), mode)
        if report.lsm is not None and diagnosis.trace.target is not None:
            report.lsm = lsm.inspect_target(report.lsm, diagnosis.trace.target.path)
        # Recheck identity, credentials, root and namespaces after the path walk.
        # A changed/exited/reused PID must not inherit the earlier observation's verdict.
        try:
            after = inspect_process(pid)
        except ProcessInspectionError as exc:
            raise ProcessInspectionError(f"PID {pid} could not be revalidated after analysis: {exc}",
                                         kind="exited" if exc.kind == "not_visible" else exc.kind) from exc
        if after != report.process:
            raise ProcessInspectionError(f"PID {pid} identity, credentials, or context changed during analysis; retry",
                                         kind="identity_changed")
        report.diagnosis, report.code = diagnosis, diagnosis.code
        if report.lsm is not None:
            report.lsm_result = lsm.evaluate(report.lsm, diagnosis.code)
            if report.lsm_result.status in ("indeterminate", "error"):
                report.code = ExitCode.ERROR
                report.indeterminate_reason = ("lsm_policy_unresolved" if report.lsm_result.status == "indeterminate"
                                               else "lsm_inspection_error")
        if diagnosis.code == ExitCode.ERROR:
            report.indeterminate_reason = diagnosis.trace.error_kind or "diagnostic_error"
    except (ProcessInspectionError, DiagnosticError, OSError, IDMapError) as exc:
        report.inspection_kind = getattr(exc, "kind", None)
        report.code = ExitCode(exc.code) if hasattr(exc, "code") else ExitCode.ERROR
        report.limitations.append(str(exc))
        if report.code == ExitCode.ERROR:
            report.indeterminate_reason = (exc.kind if isinstance(exc, DiagnosticError) else None) or "process_inspection_failed"
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
    if inode.capability_decision and inode.capability_decision.applied:
        return f"CAPABILITY {inode.capability_decision.capability} [base {ordinary}]"
    if subject.uid == 0 and not subject.process_identity:
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
                    conclusion = "base ACL result shown; capability follows." if inode.capability_decision else "ACL result governs."
                    lines.append(f"    Mode-only comparison: {dac.permission_class} {bits(dac.available)}"
                                 f" -> {'PERMITTED' if dac.allowed else 'DENIED'}; {conclusion}")
            return lines
    if acl_relevant(inode):
        return [f"  {acl_explanation(inode)}"]
    return []


def denial_explanation(inode: Inode, subject: Subject) -> str:
    decision = inode.decision
    if subject.process_identity and inode.capability_decision:
        base = acl_explanation(inode) if acl_relevant(inode) else inode.base_decision.reason
        return base + " " + inode.capability_decision.reason
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
    lines = [f"PERMISSION HELL {display_version()} | {OPERATIONS[report.mode][1]} as {subject.username} (UID {subject.uid})",
             f"Target: {path}", "", f"{verdict_label(report)} (DAC + ACL + mount model)",
             *concise_reasons(report)]
    if subject.uid == 0 and not subject.process_identity:
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


def render_verbose_report(report: Diagnosis, *, scope_text: str = SCOPE_TEXT) -> str:
    subject = report.subject
    lines = [f"PERMISSION HELL {display_version()}", f"Diagnosing {OPERATIONS[report.mode][1]} access", "",
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
                      f"{'Effective DAC/ACL/capability result' if target.base_decision else 'DAC'}: {'PERMITTED' if target.decision.allowed else 'DENIED'}",
                      target.decision.reason])
        if target.base_decision:
            lines.append(f"Base DAC/ACL: {'PERMITTED' if target.base_decision.allowed else 'DENIED'}")
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
    lines.extend(["", verdict_label(report) + f" ({display_version()} DAC + ACL + mount model)", *report.reasons, "", scope_text])
    return "\n".join(lines)


def audit_access_reason(inode: Inode, subject: Subject) -> str:
    if inode.capability_decision and inode.capability_decision.applied:
        return "Ordinary DAC/ACL would deny. " + inode.capability_decision.reason
    if subject.uid == 0 and not subject.process_identity:
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
    lines = [f"PERMISSION HELL {display_version()} | ACCESS AUDIT", f"Target: {report.requested_path!r}",
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


def explanation_inode_lines(inode: Inode, subject: Subject, operation: str,
                            first_blocker: bool) -> list[str]:
    decision = inode.decision
    marker = " <-- BLOCKED HERE" if first_blocker else ""
    lines = [f"  {inode.path!r}  {'PASS' if decision.allowed else 'FAIL'} {operation}"
             f" | {access_summary(inode, subject)}{marker}"]
    if acl_relevant(inode):
        lines.append("    " + ("Base " if inode.capability_decision else "") + acl_explanation(inode))
    if inode.capability_decision and inode.capability_decision.applied:
        lines.extend(["    DAC/ACL would DENY; capability override: " + inode.capability_decision.capability,
                      "    " + inode.capability_decision.reason + " Effective result: PASS."])
    # Use captured identity data only; rendering must not query NSS or the disk.
    matched_gids = set()
    if inode.acl_match and inode.acl_match.selection == "GROUP":
        matched_gids = {inode.gid if entry.tag == Tag.GROUP_OBJ else entry.qualifier
                        for entry in inode.acl_match.entries}
    elif decision.permission_class == "GROUP" and (subject.uid != 0 or subject.process_identity):
        matched_gids = {inode.gid}
    names = dict(zip(subject.supplementary_gids, subject.supplementary_groups))
    for gid in sorted(matched_gids):
        if gid == subject.primary_gid:
            lines.append(f"    via primary group {subject.primary_group} (GID {gid})")
        elif gid in names:
            lines.append(f"    via supplementary group {names[gid]} (GID {gid})")
    # Relevant ACL detail above already includes the denial explanation.
    if not decision.allowed and not acl_relevant(inode):
        lines.append("    " + denial_explanation(inode, subject))
    elif not decision.allowed and inode.capability_decision:
        lines.append("    " + inode.capability_decision.reason)
    return lines


def render_audit_explanation(explanation: AuditExplanation, verbose: bool = False) -> str:
    """Project existing decisions into an ordered access path, without evaluating access."""
    report = explanation.diagnosis
    subject, trace = report.subject, report.trace
    result = {ExitCode.ALLOWED: "PERMITTED", ExitCode.DENIED: "DENIED",
              ExitCode.INPUT: "UNRESOLVED PATH / INVALID INPUT", ExitCode.ERROR: "INCOMPLETE"}[report.code]
    lines = [f"PERMISSION HELL {display_version()} | AUDIT EXPLAIN", f"Target: {report.requested_path!r}",
             f"Subject: {subject.username} (UID {subject.uid})",
             f"Requested: {OPERATIONS[report.mode][1]}", "", f"RESULT: {result}", "", "ACCESS PATH"]
    lines.extend(explanation_detail_lines(report, verbose))
    return "\n".join(lines)


def explanation_detail_lines(report: Diagnosis, verbose: bool = False, *, scope_text: str = SCOPE_TEXT) -> list[str]:
    """Shared presentation of an already-evaluated account or process identity."""
    subject, trace = report.subject, report.trace
    lines = []
    if subject.uid == 0 and not subject.process_identity:
        lines.append("  ROOT: assumes traditional privileged UID 0; overrides marked where applied.")
    seen = set()
    blocked = False
    for event in trace.events:
        if isinstance(event, Symlink):
            lines.append(f"  LINK {event.path!r} -> {event.destination!r}")
        else:
            if event in seen and event.decision.allowed:
                # Keep the position visible without repeating ACL/group detail.
                lines.append(f"  {event.path!r}  PASS search | {access_summary(event, subject)} (same check as above)")
                continue
            seen.add(event)
            lines.extend(explanation_inode_lines(event, subject, "search", not event.decision.allowed and not blocked))
            blocked |= not event.decision.allowed
    if any(isinstance(event, Symlink) for event in trace.events) and trace.resolved_path:
        lines.append(f"  Resolved target: {trace.resolved_path!r}")
    target = trace.target
    if target:
        lines.extend(explanation_inode_lines(target, subject, OPERATIONS[report.mode][1],
                                             not target.decision.allowed and not blocked))
        blocked |= not target.decision.allowed
        lines.append(f"    Owner: {target.owner} (UID {target.uid}) | Group: {target.group} (GID {target.gid})"
                     f" | Mode: {stat.S_IMODE(target.mode):04o} ({stat.filemode(target.mode)})")
    else:
        lines.append("  Target not evaluated because path resolution/traversal stopped.")
    if trace.failure and not blocked:
        if trace.partial_inode:
            partial = trace.partial_inode
            lines.append(f"  {partial.path!r}: base DAC/ACL {'PERMITTED' if partial.base_decision.allowed else 'DENIED'}; "
                         "capability result UNKNOWN; no effective permission verdict.")
        lines.append(f"  {'FAIL' if report.code == ExitCode.DENIED else 'ERROR'}: {trace.failure} <-- STOPPED HERE")
    # The verdict engine places mount denials after the two target-denial reasons.
    # Consume those decisions, rather than reimplementing ro/noexec semantics here.
    mount_reasons = (report.reasons[2:] if target and not target.decision.allowed else report.reasons)
    mount_reasons = mount_reasons if not trace.failure and report.code == ExitCode.DENIED else []
    if report.mount:
        mount = report.mount
        status = "FAIL" if mount_reasons else "PASS"
        marker = " <-- BLOCKED HERE" if mount_reasons and not blocked else ""
        lines.append(f"  Mount: {mount.point!r} | {mount.filesystem} | "
                     f"{'READ-ONLY' if mount.readonly else 'READ-WRITE'} | {status}{marker}")
        lines.extend("    " + reason for reason in mount_reasons)
    elif not report.mount_error:
        lines.append("  Mount: not evaluated; target unresolved.")
    if report.mount_error:
        lines.append("  Mount: UNKNOWN | " + report.mount_error)
    lines.extend(["", "WHY"])
    if report.code == ExitCode.ALLOWED:
        lines.extend(["  Every parent permits search.", "  " + audit_access_reason(target, subject),
                      "  Requested access survives the mount checks."])
    else:
        lines.extend("  " + reason for reason in concise_reasons(report))
    if verbose:
        lines.extend(["", "FULL DIAGNOSTIC DETAIL", render_verbose_report(report, scope_text=scope_text)])
    return lines


def render_process_report(report: ProcessDiagnosis, verbose: bool = False) -> str:
    lines = [f"PERMISSION HELL {display_version()} | PROCESS DIAGNOSE", f"PID: {report.pid}",
             f"Target: {report.requested_path!r}", f"Requested: {OPERATIONS[report.mode][1]}"]
    process = report.process
    if process:
        status = process.status
        identity = report.namespace_identity
        used_uid = identity.fsuid.mapped if identity else status.uids.used
        used_gid = identity.fsgid.mapped if identity else status.gids.used
        lines.extend([f"Process: {status.name!r}", "", "PROCESS CREDENTIALS",
                      f"  ruid={status.uids.real} euid={status.uids.effective} suid={status.uids.saved} fsuid={status.uids.filesystem}",
                      f"  rgid={status.gids.real} egid={status.gids.effective} sgid={status.gids.saved} fsgid={status.gids.filesystem}",
                      f"  Used for filesystem checks: UID {used_uid if used_uid is not None else 'unresolved'} ({status.uids.source}), "
                      f"GID {used_gid if used_gid is not None else 'unresolved'} ({status.gids.source})",
                      "  Supplementary: " + (", ".join(f"{process.gid_names.get(g) or g!r} (GID {g})" for g in status.supplementary_gids) or "none"),
                      "", "NAMESPACES"])
        for label, observation in (("mount", process.mount_namespace), ("user", process.user_namespace)):
            comparison = {True: "same as debugger", False: "different from debugger", None: "unknown"}[observation.matches_debugger]
            lines.append(f"  {label}: {comparison} ({observation.identifier})")
        lines.extend([f"  root: {process.root.path!r} (matches debugger: {process.root.matches_debugger})",
                      "  Target interpretation: debugger's absolute path, root and mount namespace."])
        if identity:
            lines.extend(["", "USER NAMESPACE / FILESYSTEM IDENTITY"])
            if identity.same_as_debugger is True:
                lines.append("  Same user namespace; IDs interpreted directly.")
            else:
                lines.append("  Status IDs are debugger-visible; local IDs are recovered from the maps, not double-translated.")
                for label, mapping in (("UID", process.uid_map), ("GID", process.gid_map)):
                    display = mapping if verbose or mapping is None else mapping[:3]
                    lines.append(f"  {label} map: " + ("unavailable" if display is None else "empty" if not display else
                                 ", ".join(f"{e.inside}-{e.inside + e.length - 1} -> {e.outside}-{e.outside + e.length - 1}" for e in display)))
                    if mapping is not None and not verbose and len(mapping) > 3:
                        lines.append(f"    +{len(mapping) - 3} ranges (--verbose shows all)")
                values = [("fsuid", identity.fsuid), ("fsgid", identity.fsgid)]
                supplementary = identity.supplementary if verbose else identity.supplementary[:6]
                values.extend(("supplementary", value) for value in supplementary)
                for label, value in values:
                    lines.append(f"  {label}: local {value.local if value.local is not None else 'unknown'} -> "
                                 f"debugger ID {value.mapped if value.mapped_ok else 'unmapped/unresolved'} "
                                 f"(observed {value.observed}" + (f"; {value.reason}" if value.reason else "") + ")")
                if not verbose and len(identity.supplementary) > 6:
                    lines.append(f"    +{len(identity.supplementary) - 6} supplementary translations (--verbose shows all)")
                lines.append("  DAC/ACL uses mapped debugger-visible IDs, never namespace-local root as host root.")
            lines.append(f"  setgroups: {process.setgroups} (does not remove currently observed memberships)")
        lines.extend("  Note: " + note for note in process.notes)
        sets = status.capabilities
        effective = sets.effective
        effective_names = effective.names if effective else ()
        display_names = effective_names if verbose else effective_names[:6]
        more = f" (+{len(effective_names) - 6} others; --verbose)" if not verbose and len(effective_names) > 6 else ""
        relevant = [name for name in effective_names if name in ("CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH")]
        lines.extend(["", "CAPABILITIES", "  Effective: " + (", ".join(display_names) or ("none" if effective else "unavailable")) + more,
                      "  Relevant modeled effective: " + (", ".join(relevant) or "none"),
                      "  Live process model: UID 0 alone grants no bypass; only effective capabilities apply."])
        if effective and effective.unknown_bits:
            lines.append(f"  Unknown effective capability bits (not modeled): {effective.unknown_bits}")
        if verbose:
            lines.extend([f"  PID start time (ticks): {process.start_time_ticks}",
                          f"  UID map (observed only): {process.uid_map}",
                          f"  GID map (observed only): {process.gid_map}",
                          f"  CapEff: {status.effective_capabilities}"])
            for name in ("inheritable", "permitted", "effective", "bounding", "ambient"):
                observed = getattr(sets, name)
                lines.append(f"  {name}: " + (f"{', '.join(observed.names) or 'none'}; mask={observed.mask:x}; unknown_bits={observed.unknown_bits}"
                                              if observed is not None else "unavailable"))
    result = {ExitCode.ALLOWED: "PERMITTED", ExitCode.DENIED: "DENIED",
              ExitCode.INPUT: "INVALID INPUT / UNRESOLVED PATH", ExitCode.ERROR: "INDETERMINATE"}[report.code]
    if report.lsm_result and report.lsm_result.status == "error":
        result = "ERROR"
    if report.lsm is not None:
        lines.extend(["", "LSM", *("  " + line for line in lsm.summary_lines(report.lsm))])
        if verbose:
            lines.extend("  Observation: " + repr(error) for error in report.lsm.errors)
            lines.extend("  Observation: " + repr(error) for error in
                         (report.lsm.apparmor.error, report.lsm.selinux.error) if error)
    lines.extend(["", f"RESULT: {result}"])
    if report.diagnosis:
        process_scope = ("Scope: live process fsuid/fsgid/groups, effective CAP_DAC_OVERRIDE and CAP_DAC_READ_SEARCH; "
                         "no UID-0 shortcut. Foreign capability scope, mount/root translation and LSM policies remain unmodeled.")
        lines.extend(["", "ACCESS PATH", *explanation_detail_lines(report.diagnosis, verbose, scope_text=process_scope)])
    else:
        lines.extend(["", "WHY", *report.limitations])
    if report.lsm_result:
        lines.extend(["", "LSM DECISION",
                      "  Ordinary DAC/ACL, capability and mount result: " +
                      ("PERMITTED" if report.diagnosis and report.diagnosis.code == 0 else "not permitted"),
                      *("  " + reason for reason in report.lsm_result.reasons)])
    lines.extend(["", "Model: proc filesystem IDs/groups + DAC/ACL + effective DAC capabilities + mount restrictions.",
                  "LSM policies, other capability effects, foreign capability scope and mount/root translation remain unmodeled.",
                  "Process snapshots are not atomic. Process remediation commands are not supported."])
    return "\n".join(lines)


@dataclass(frozen=True)
class RemediationSuggestion:
    category: str
    title: str
    commands: tuple[str, ...]
    effect: str
    caveats: tuple[str, ...] = ()


def suggest_remediations(report: Diagnosis) -> list[RemediationSuggestion]:
    """Read existing decisions; generate alternatives, never run commands or probe state.

    ACL group redesign and mount changes intentionally remain conceptual: an
    observed access check does not establish policy or a safe persistent layout.
    """
    suggestions = []
    if report.subject.process_identity:
        return [RemediationSuggestion("STRUCTURAL CHANGE", "Process remediation is unsupported", (),
                "Live capability or credential changes are not suggested; no setcap commands are generated.")]
    if report.code not in (ExitCode.ALLOWED, ExitCode.DENIED):
        return [RemediationSuggestion("STRUCTURAL CHANGE", "Resolve the inspection failure first", (),
                "No reliable permission change can be derived from an incomplete diagnosis.")]
    subject = report.subject
    blocked = next((event for event in report.trace.events
                    if isinstance(event, Inode) and not event.decision.allowed), None)
    inode = blocked or report.trace.target
    granting = report.code == ExitCode.DENIED
    if inode is None:
        return [RemediationSuggestion("STRUCTURAL CHANGE", "Inspect the unresolved blocker", (),
                "No concrete permission command can be derived from this result.")]
    # Mount reasons are already verdict-engine output; do not reevaluate mounts.
    mount_reasons = report.reasons[2:] if report.trace.target and not report.trace.target.decision.allowed else report.reasons
    if granting and not report.trace.failure and report.mount:
        for reason in mount_reasons:
            if reason.startswith("Mount "):
                suggestions.append(RemediationSuggestion("SYSTEM-LEVEL CHANGE", "Review the mount restriction", (),
                    reason + " Inode permission changes alone cannot overcome this restriction.",
                    ("An administrator can review whether to use a filesystem with the required access policy; "
                     "changing mount policy affects all users and objects on that mount. No remount command is inferred.",)))
    if granting and inode.decision.allowed:
        return suggestions or [RemediationSuggestion("STRUCTURAL CHANGE", "Review the reported blocker", (),
                              "No concrete permission change is supported by this diagnosis.")]
    required = inode.decision.required
    letter = bits(required).replace("-", "")
    operation = "grant" if granting else "remove"
    path = inode.path
    # '--' protects option-like operands, quoting protects shell metacharacters.
    def command(*args: str) -> str:
        return shlex.join(args)
    caveats = ["Commands are alternatives, not a sequence. The owner or an administrator must authorize inode changes.",
               "Recheck the complete path afterward; another traversal, ACL, or mount check may still block access."]
    if stat.S_ISDIR(inode.mode):
        caveats.append("Directory x means search/traversal; changing it affects reachable descendants, not file execution.")
    if subject.uid == 0:
        if granting:
            suggestions.append(RemediationSuggestion("BROADER MODE CHANGE", "Set an execute bit if execution is intended",
                (command("chmod", "u+x", "--", path),),
                "Root requires at least one execute bit on this non-directory inode. This also grants execute to its owner.",
                tuple(caveats)))
        else:
            suggestions.append(RemediationSuggestion("STRUCTURAL CHANGE", "Review use of a privileged identity", (),
                "Under the traditional UID 0 model, ordinary DAC/ACL reductions do not reliably revoke root access.",
                ("An administrator can arrange execution under a non-root identity and evaluate that identity separately.",)))
        return suggestions
    match = inode.acl_match
    qualifier = subject.username if subject.username and not any(c in subject.username for c in ":,\n") else str(subject.uid)
    if acl_relevant(inode):
        if granting and match.mask is not None and match.specified & required and not match.effective & required:
            suggestions.append(RemediationSuggestion("GROUP-LEVEL CHANGE", "Expand the ACL mask",
                (command("setfacl", "-n", "-m", "m::" + bits(match.mask | required), "--", path),),
                "This can expand effective rights for ALL mask-governed named-user and group ACL entries, not only this account.",
                tuple(caveats)))
        if match.selection == "NAMED USER":
            permissions = (match.specified | required) if granting else (match.specified & ~required)
            if permissions != match.specified:
                suggestions.append(RemediationSuggestion("NARROW CHANGE", f"{operation.capitalize()} the named account's ACL permission",
                    (command("setfacl", "-n", "-m", f"u:{qualifier}:{bits(permissions)}", "--", path),),
                    f"Changes only {subject.username} (UID {subject.uid})'s entry on {path!r}; keeps the existing mask.",
                    tuple(caveats + (["The mask must also allow the requested permission; changing it can affect every mask-governed entry."]
                                    if granting else ["Keeping the entry prevents fallback. Deleting it instead may restore access through GROUP or OTHER."]))))
        else:
            suggestions.append(RemediationSuggestion("GROUP-LEVEL CHANGE", "Review matching ACL groups and their union", (),
                "Changing a matching group entry affects its members; multiple matching groups contribute to the union.",
                tuple(caveats + ["To remove access, every contributing route must be considered. The mask governs all named users and groups."])))
        suggestions.append(RemediationSuggestion("STRUCTURAL CHANGE", "Review the ACL and group design", (),
            "If group sharing is intended, review membership and matching entries together; no ownership or group reassignment is inferred.",
            ("Group membership changes require account administration, affect other resources using that group, and require refreshed process credentials.",)))
        return suggestions
    selected = inode.decision.permission_class
    if selected == "GROUP" and inode.acl and inode.acl.extended:
        return suggestions + [RemediationSuggestion("GROUP-LEVEL CHANGE", "Review the owning-group ACL entry and mask", (),
            "With an extended ACL, chmod g changes the shared mask rather than just the owning-group entry. "
            "Review both before changing access; all mask-governed entries can be affected.", tuple(caveats))]
    selector = {"OWNER": "u", "GROUP": "g", "OTHER": "o"}[selected]
    suggestions.append(RemediationSuggestion("GROUP-LEVEL CHANGE" if selected == "GROUP" else "BROADER MODE CHANGE",
        f"{operation.capitalize()} {selected} {letter} on {path!r}",
        (command("chmod", selector + ("+" if granting else "-") + letter, "--", path),),
        {"OWNER": "Changes rights for the owning UID, including other accounts sharing that UID.",
         "GROUP": "Changes rights for every account using the owning-group class.",
         "OTHER": "Changes rights for every account using OTHER, not just the subject."}[selected], tuple(caveats)))
    if selected != "OWNER":
        if not inode.acl or not inode.acl.extended:
            permissions = inode.decision.available | required if granting else inode.decision.available & ~required
            mask = ((inode.mode >> 3) & 7) | (required if granting else 0)
            suggestions.append(RemediationSuggestion("NARROW CHANGE", "Set a named-user access ACL",
                (command("setfacl", "-n", "-m", f"u:{qualifier}:{bits(permissions)},m::{bits(mask)}", "--", path),),
                f"Changes the access entry for {subject.username} (UID {subject.uid}) while preserving the existing owning-group entry. "
                "The explicit mask preserves current group rights; the named entry prevents fallback to OTHER.",
                tuple(caveats + ["Requires filesystem ACL support. Review the current ACL again before applying: a changed ACL could make this mask affect other entries."])))
        # For extended ACLs whose OTHER path was selected, use conceptual guidance
        # rather than chmod g (which would edit the mask) or guessing a new mask.
        if granting and inode.acl and inode.acl.extended:
            suggestions.append(RemediationSuggestion("NARROW CHANGE", "Consider a named-user access ACL", (),
                f"An entry for {subject.username} (UID {subject.uid}) could grant access on {path!r} without widening OTHER.",
                tuple(caveats + ["Preserve intended existing rights and inspect the ACL mask first. Automatic mask recalculation can widen rights for other named users and groups."])))
        if inode.gid in subject.supplementary_gids or granting:
            suggestions.append(RemediationSuggestion("GROUP-LEVEL CHANGE", "Review supplementary group membership", (),
                f"Owning group: {inode.group} (GID {inode.gid}). "
                + ("Membership can select GROUP, but that class must grant the permission; OWNER takes precedence."
                   if granting else "Removing membership may narrow access, but OTHER or another matching ACL group may still permit it."),
                ("Membership changes require account administration and refreshed process credentials; they affect every resource using that group.",)))
    return suggestions


def render_remediations(suggestions: list[RemediationSuggestion]) -> str:
    lines = ["POSSIBLE CHANGES", "Informational alternatives only; no commands are executed."]
    for suggestion in suggestions:
        lines.extend(["", suggestion.category, "  " + suggestion.title])
        lines.extend("    " + command for command in suggestion.commands)
        lines.append("  Effect: " + suggestion.effect)
        lines.extend("  Note: " + caveat for caveat in suggestion.caveats)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="permissionhell", description=__doc__, epilog=SCOPE_TEXT)
    parser.add_argument("--version", action="version", version=f"permissionhell {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("diagnose", help="Explain Linux DAC, ACL, and mount access decisions", epilog=SCOPE_TEXT)
    command.add_argument("target_path")
    command.add_argument("--as", dest="username", required=True, help="Account to evaluate")
    command.add_argument("--mode", choices=OPERATIONS, default="r")
    command.add_argument("--json", action="store_true", help="Emit schema-versioned JSON instead of human text")
    command.add_argument("--verbose", action="store_true",
                         help="Show all traversal checks, detailed reasoning, groups, mount options, and limitations")
    audit = commands.add_parser("audit", help="Show modeled access for every explicit local /etc/passwd account",
                                epilog="Includes service accounts; reports modeled access, not intended policy. " + SCOPE_TEXT)
    audit.add_argument("target_path")
    audit.add_argument("--mode", choices=OPERATIONS, default="r")
    audit.add_argument("--json", action="store_true", help="Emit all results as JSON; --verbose does not change JSON detail")
    audit.add_argument("--explain", metavar="USER", help="Explain one named account's ordered access path")
    audit.add_argument("--suggest-fixes", action="store_true", help="With --explain, show informational change alternatives; never execute them")
    audit.add_argument("--verbose", action="store_true",
                       help="Show every account without grouping; with --explain, add full diagnostic detail")
    process = commands.add_parser("process", help="Evaluate a running PID's filesystem credentials",
                                  epilog="Absolute debugger-visible paths only; foreign roots/namespaces are indeterminate. No process fixes.")
    process.add_argument("target_path")
    def pid_argument(value: str) -> int:
        if not re.fullmatch(r"[0-9]{1,10}", value) or not 0 < int(value) <= 0x7FFFFFFF:
            raise argparse.ArgumentTypeError("PID must be a positive Linux process ID")
        return int(value)
    process.add_argument("--pid", required=True, type=pid_argument)
    process.add_argument("--mode", choices=OPERATIONS, default="r")
    process.add_argument("--json", action="store_true", help="Emit schema 1 JSON, including process metadata")
    process.add_argument("--verbose", action="store_true", help="Show full trace and observed process maps/capabilities")
    process_audit = commands.add_parser("audit-processes", help="Audit access for visible processes in /proc",
                                       epilog="Absolute debugger-visible paths only. Sequential snapshots; hidden PIDs are not discovered. "
                                              "--verbose may expose secrets in command lines. No process fixes.")
    process_audit.add_argument("target_path")
    process_audit.add_argument("--pid", action="append", type=pid_argument,
                               help="Restrict to a PID; repeat for multiple PIDs")
    process_audit.add_argument("--mode", choices=OPERATIONS, default="r")
    process_audit.add_argument("--json", action="store_true", help="Include every process individually as schema 1 JSON")
    process_audit.add_argument("--verbose", action="store_true",
                               help="Expand all processes, full reasoning and readable command lines (may contain secrets)")
    graph_parser = commands.add_parser("graph", help="Graph one account or process access decision",
                                       epilog="Representation of the access model, not kernel tracing. DOT is emitted only; Graphviz is never executed.")
    graph_parser.add_argument("target_path")
    identity = graph_parser.add_mutually_exclusive_group(required=True)
    identity.add_argument("--as", dest="username", help="Account to graph")
    identity.add_argument("--pid", type=pid_argument, help="Running process to graph (absolute targets only)")
    graph_parser.add_argument("--mode", choices=OPERATIONS, default="r")
    exports = graph_parser.add_mutually_exclusive_group()
    exports.add_argument("--json", action="store_true", help="Emit graph schema 1 with every node and edge")
    exports.add_argument("--dot", action="store_true", help="Emit Graphviz DOT without running Graphviz")
    graph_parser.add_argument("--verbose", action="store_true", help="Expand traversal and show collected graph metadata")
    policy_parser = commands.add_parser("policy-check", help="Compare JSON policy intentions with modeled access",
                                        epilog="Explicit account/PID scopes; no permission changes or automatic remediation.")
    policy_parser.add_argument("policy_file")
    policy_parser.add_argument("--json", action="store_true", help="Emit every comparison and underlying observation as schema 1 JSON")
    policy_parser.add_argument("--verbose", action="store_true", help="Show all comparisons and complete effective-access observations")
    snapshot_parser = commands.add_parser("snapshot", help="Capture account or process audit state as portable JSON")
    snapshot_parser.add_argument("target_path", help="Absolute Linux target path; contents are never read")
    snapshot_parser.add_argument("--mode", choices=OPERATIONS, default="r")
    snapshot_parser.add_argument("--processes", action="store_true", help="Capture visible processes instead of local accounts")
    snapshot_parser.add_argument("--output", help="Atomically publish snapshot here; default is JSON stdout")
    snapshot_parser.add_argument("--force", action="store_true", help="Replace an existing regular output file")
    snapshot_parser.add_argument("--json", action="store_true", help="Print full snapshot JSON even when --output is used")
    diff_parser = commands.add_parser("diff", help="Compare two saved snapshots offline")
    diff_parser.add_argument("before")
    diff_parser.add_argument("after")
    diff_parser.add_argument("--json", action="store_true", help="Emit every comparison as schema 1 JSON")
    diff_parser.add_argument("--verbose", action="store_true", help="Include unchanged subjects and full before/after observations")
    for command in ("monitor-init", "monitor-check"):
        monitor = commands.add_parser(command, help="Create a baseline" if command == "monitor-init" else "One-shot access change check")
        monitor.add_argument("target_path")
        monitor.add_argument("--baseline", required=True)
        monitor.add_argument("--mode", choices=("r", "w", "x"), default="r" if command == "monitor-init" else None)
        scope = monitor.add_mutually_exclusive_group()
        scope.add_argument("--processes", dest="processes", action="store_true")
        scope.add_argument("--accounts", dest="processes", action="store_false")
        monitor.set_defaults(processes=False if command == "monitor-init" else None)
        monitor.add_argument("--json", action="store_true")
        if command == "monitor-init":
            monitor.add_argument("--force", action="store_true")
        else:
            monitor.add_argument("--update-baseline", action="store_true")
            monitor.add_argument("--verbose", action="store_true")
            monitor.add_argument("--ignore-process-churn", action="store_true", help="Hide additions/removals in text only; exit code and JSON unchanged")
    args = parser.parse_args(argv)
    if args.command == "audit" and args.suggest_fixes and args.explain is None:
        parser.error("--suggest-fixes requires --explain USER")
    if args.command == "snapshot" and args.force and not args.output:
        parser.error("--force requires --output FILE")
    if args.command == "snapshot" and args.output == "":
        parser.error("--output must name a file")
    def emit_error(message: str, code: ExitCode, stage: str = "request") -> None:
        if args.command in ("snapshot", "diff", "monitor-init", "monitor-check"):
            if args.json or args.command == "snapshot" and not args.output:
                error_document = {"schema_version": "1", "command": args.command,
                                  "tool_version": __version__, "exit_code": int(code), "errors": [message]}
                if args.command.startswith("monitor-"):
                    error_document.update(baseline={"path": args.baseline}, baseline_updated=False)
                print(json_output.render_json(error_document), end="")
            else:
                print(f"permissionhell: {message}", file=sys.stderr)
            return
        if args.command == "policy-check":
            import policy_drift
            report = policy_drift.DriftReport(args.policy_file, errors=[{
                "drift": "policy_error" if code == ExitCode.INPUT else "indeterminate", "message": message}])
            emit_policy(report)
            return
        if args.command == "graph":
            import access_graph
            document = json_output.error_document(__version__, "graph", "graph", args.target_path,
                                                   args.mode, args.username, message, code, stage)
            if args.pid is not None:
                document["pid"] = args.pid
            emit_graph(access_graph.build_graph(document))
            return
        if args.json:
            username = args.username if args.command == "diagnose" else getattr(args, "explain", None)
            mode = "explain" if args.command == "audit" and args.explain is not None else args.command
            document = json_output.error_document(__version__, args.command, mode, args.target_path,
                                                  args.mode, username, message, code, stage)
            if getattr(args, "suggest_fixes", False):
                document["remediations"] = []
            if args.command == "process":
                document.update({"pid": args.pid, "process": None, "limitations": [message]})
                if code == ExitCode.ERROR:
                    document["verdict"] = "indeterminate"
            print(json_output.render_json(document), end="")
        else:
            print(f"permissionhell: {message}", file=sys.stderr)
    def emit_graph(graph) -> None:
        import access_graph
        if args.json:
            print(access_graph.serialize_graph_json(graph), end="")
        elif args.dot:
            print(access_graph.serialize_graph_dot(graph), end="")
        else:
            print(access_graph.render_terminal_graph(graph, verbose=args.verbose))
    def emit_policy(report) -> None:
        import policy_drift
        if args.json:
            print(json_output.render_json(policy_drift.policy_document(report, __version__)), end="")
        else:
            print(policy_drift.render_policy(report, __version__, verbose=args.verbose))
    if not sys.platform.startswith("linux") and args.command != "diff":
        emit_error("unsupported platform; diagnosis requires Linux.", ExitCode.ERROR, "platform")
        return ExitCode.ERROR
    try:
        if args.command in ("monitor-init", "monitor-check"):
            import access_monitor
            import access_snapshot
            try:
                if args.command == "monitor-init":
                    current = access_monitor.initialize(args.target_path, args.baseline, args.mode,
                        processes=args.processes, force=args.force, engine=sys.modules[__name__])
                    print(json_output.render_json(access_monitor.init_document(current, args.baseline, __version__)) if args.json
                          else access_monitor.render_init(current, args.baseline))
                    return current.code
                result = access_monitor.check(args.target_path, args.baseline, mode=args.mode,
                                               processes=args.processes, engine=sys.modules[__name__])
                if not args.json:
                    print(access_monitor.render_check(result, __version__, verbose=args.verbose,
                                                      ignore_process_churn=args.ignore_process_churn), flush=True)
                # Serialize the complete comparison before any replacement. JSON is
                # emitted once afterward so baseline_updated reflects actual success.
                if args.json:
                    json_output.render_json(access_monitor.document(result, __version__))
                if args.update_baseline:
                    access_monitor.update_baseline(result)
                    if not args.json:
                        print("Baseline updated atomically." if result.baseline_updated else "Baseline update not performed.")
                        for error in result.errors:
                            print("Error: " + error)
                if args.json:
                    print(json_output.render_json(access_monitor.document(result, __version__)), end="")
                return result.code
            except access_snapshot.SnapshotError as exc:
                emit_error(str(exc), exc.code)
                return exc.code
        if args.command in ("snapshot", "diff"):
            import access_snapshot
            try:
                if args.command == "snapshot":
                    snapshot = access_snapshot.capture_snapshot(args.target_path, args.mode, processes=args.processes,
                                                                 engine=sys.modules[__name__])
                    if args.output:
                        access_snapshot.write_snapshot(snapshot, args.output, force=args.force)
                    if args.json or not args.output:
                        print(access_snapshot.serialize_snapshot(snapshot), end="")
                    else:
                        print(access_snapshot.render_capture(snapshot, args.output))
                    return snapshot.code
                comparison = access_snapshot.diff_snapshots(access_snapshot.load_snapshot(args.before),
                                                            access_snapshot.load_snapshot(args.after))
                if args.json:
                    print(json_output.render_json(access_snapshot.diff_document(comparison, __version__)), end="")
                else:
                    print(access_snapshot.render_diff(comparison, __version__, verbose=args.verbose))
                return comparison.code
            except access_snapshot.SnapshotError as exc:
                emit_error(str(exc), exc.code)
                return exc.code
        if args.command == "policy-check":
            import policy_drift
            report = policy_drift.check_policy_file(args.policy_file, engine=sys.modules[__name__])
            emit_policy(report)
            return report.code
        if args.command == "graph":
            import access_graph
            if args.pid is not None:
                report = diagnose_process(args.target_path, args.pid, args.mode)
                graph = access_graph.build_process_graph(report, __version__)
            else:
                report = diagnose(args.target_path, resolve_subject(args.username), args.mode)
                graph = access_graph.build_account_graph(report, __version__)
            emit_graph(graph)
            return report.code
        if args.command == "audit-processes":
            import process_audit
            engine = sys.modules[__name__]
            report = process_audit.audit_processes(args.target_path, args.mode, pids=args.pid,
                                                    include_cmdline=args.verbose, engine=engine)
            if args.json:
                print(json_output.render_json(process_audit.audit_document(report, __version__)), end="")
            else:
                print(process_audit.render_audit(report, verbose=args.verbose, engine=engine))
            return report.code
        if args.command == "process":
            process_report = diagnose_process(args.target_path, args.pid, args.mode)
            if args.json:
                print(json_output.render_json(json_output.process_document(process_report, __version__)), end="")
            else:
                print(render_process_report(process_report, verbose=args.verbose))
            return process_report.code
        if args.command == "audit":
            if args.explain is not None:
                explanation = explain_audit_target(args.target_path, args.explain, args.mode)
                if args.json:
                    suggestions = suggest_remediations(explanation.diagnosis) if args.suggest_fixes else None
                    document = json_output.diagnosis_document(explanation.diagnosis, __version__,
                                                              explain=True, remediations=suggestions)
                    print(json_output.render_json(document), end="")
                else:
                    print(render_audit_explanation(explanation, verbose=args.verbose))
                    if args.suggest_fixes:
                        print("\n" + render_remediations(suggest_remediations(explanation.diagnosis)))
                return explanation.code
            audit_report = audit_target(args.target_path, args.mode)
            if args.json:
                print(json_output.render_json(json_output.audit_document(audit_report, __version__)), end="")
            else:
                print(render_audit(audit_report, verbose=args.verbose))
            return audit_report.code
        subject = resolve_subject(args.username)
        report = diagnose(args.target_path, subject, args.mode)
        if args.json:
            print(json_output.render_json(json_output.diagnosis_document(report, __version__)), end="")
        else:
            print(render_report(report, verbose=args.verbose))
        return report.code
    except (DiagnosticError, OSError) as exc:
        code = exc.code if isinstance(exc, DiagnosticError) else ExitCode.ERROR
        emit_error(str(exc), code)
        return code


if __name__ == "__main__":
    sys.exit(main())
