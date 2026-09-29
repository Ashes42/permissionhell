#!/usr/bin/env python3
"""Permission Hell v0.1: read-only Linux DAC and mount diagnostics."""

from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass, field
from enum import IntEnum
import os
import re
import stat
import sys

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


def inspect_inode(path: str, metadata: os.stat_result, subject: Subject, mode: str) -> Inode:
    return Inode(path, metadata.st_uid, metadata.st_gid, owner_name(metadata.st_uid),
                 group_name(metadata.st_gid), metadata.st_mode,
                 evaluate_permission(subject, metadata, mode))


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


def diagnose(path: str, subject: Subject, mode: str) -> Diagnosis:
    report = Diagnosis(subject, path, mode, trace_path(path, subject, mode))
    if report.trace.resolved_path is not None:
        try:
            report.mount = find_mount(report.trace.resolved_path, read_mounts())
        except DiagnosticError as exc:
            report.mount_error = str(exc)
    determine_verdict(report)
    return report


def bits(value: int) -> str:
    return "".join(letter if value & bit else "-" for bit, letter in ((4, "r"), (2, "w"), (1, "x")))


def render_report(report: Diagnosis) -> str:
    subject = report.subject
    lines = ["PERMISSION HELL v0.1", f"Diagnosing {OPERATIONS[report.mode][1]} access", "",
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
        lines.extend([f"{'PASS' if decision.allowed else 'FAIL'} {event.path!r}  {decision.permission_class}"
                      f" {bits(decision.available)}  requires x"
                      f"  UID={event.uid} GID={event.gid} mode={stat.S_IMODE(event.mode):04o}",
                      f"     {decision.reason}"])
    if not report.trace.events:
        lines.append("No parent components to traverse (or resolution could not start).")
    lines.extend(["", "TARGET INODE"])
    target = report.trace.target
    if target:
        lines.extend([f"Resolved path: {report.trace.resolved_path!r}",
                      f"Owner: {target.owner} (UID {target.uid})", f"Group: {target.group} (GID {target.gid})",
                      f"Mode: {stat.S_IMODE(target.mode):04o} ({stat.filemode(target.mode)})",
                      f"Matched class: {target.decision.permission_class}",
                      f"Required: {OPERATIONS[report.mode][1]} ({report.mode})",
                      f"Available: {bits(target.decision.available)}",
                      f"DAC: {'PERMITTED' if target.decision.allowed else 'DENIED'}",
                      target.decision.reason])
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
    label = {ExitCode.ALLOWED: "ACCESS PERMITTED", ExitCode.DENIED: "ACCESS DENIED",
             ExitCode.INPUT: "INVALID INPUT", ExitCode.ERROR: "DIAGNOSIS INCOMPLETE"}[report.code]
    lines.extend(["", label + " (v0.1 DAC + mount model)", *report.reasons, "",
                  "Scope: account database groups; debugger's mount namespace; traditional privileged root.",
                  "Not modeled: POSIX ACLs, SELinux, AppArmor, process capabilities, user namespaces,",
                  "container UID/GID mappings, NFS/SMB/FUSE rules, inode flags, or other process restrictions.",
                  "This is a read-only model, not a guarantee that an actual syscall will succeed."])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="permissionhell", description=__doc__)
    parser.add_argument("--version", action="version", version="permissionhell 0.1.0")
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("diagnose", help="Explain Linux DAC and mount access decisions")
    command.add_argument("target_path")
    command.add_argument("--as", dest="username", required=True, help="Account to evaluate")
    command.add_argument("--mode", choices=OPERATIONS, default="r")
    args = parser.parse_args(argv)
    if not sys.platform.startswith("linux"):
        print("permissionhell: unsupported platform; diagnosis requires Linux.", file=sys.stderr)
        return ExitCode.ERROR
    try:
        subject = resolve_subject(args.username)
        report = diagnose(args.target_path, subject, args.mode)
        print(render_report(report))
        return report.code
    except (DiagnosticError, OSError) as exc:
        print(f"permissionhell: {exc}", file=sys.stderr)
        return exc.code if isinstance(exc, DiagnosticError) else ExitCode.ERROR


if __name__ == "__main__":
    sys.exit(main())
