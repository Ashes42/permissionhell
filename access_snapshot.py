"""Portable access observations and offline comparisons. No authorization rules."""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import stat
import tempfile

import json_output
import process_audit


SNAPSHOT_VERSION = 1
KNOWN = {"permitted", "denied"}
VERDICTS = KNOWN | {"indeterminate", "error", "unknown", "unavailable", "invalid_input"}


class SnapshotError(ValueError):
    def __init__(self, message: str, code: int = 2):
        super().__init__(message)
        self.code = code


@dataclass
class SnapshotSubject:
    identity: dict
    name: str | None
    verdict: str
    mechanism: str | None
    blocker: dict | None
    authorization: list[dict]
    observation: dict


@dataclass
class AccessSnapshot:
    tool_version: str
    captured_at: str
    scope: str
    target: str
    requested_mode: str
    system: dict
    target_metadata: dict
    subjects: list[SnapshotSubject]
    capture_errors: list[str] = field(default_factory=list)
    snapshot_version: int = SNAPSHOT_VERSION

    @property
    def code(self) -> int:
        unknown_target = (any(self.target_metadata.get(key) is None for key in
                             ("device", "inode", "owner_uid", "group_gid", "mode", "mount")) or
                          self.target_metadata.get("acl_status") == "unavailable")
        return 3 if unknown_target or self.capture_errors or any(subject.verdict not in KNOWN for subject in self.subjects) else 0


def system_context() -> dict:
    uname = os.uname()
    try:
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip() or None
    except OSError:
        boot_id = None
    try:
        pid_namespace = os.readlink("/proc/self/ns/pid")
    except OSError:
        pid_namespace = None
    return {"hostname": uname.nodename, "kernel": uname.release, "architecture": uname.machine,
            "platform": "linux", "boot_id": boot_id, "pid_namespace": pid_namespace}


def target_metadata(path: str, engine) -> tuple[dict, list[str]]:
    """Read inode/ACL/mount metadata as an observer, not as an access check."""
    metadata = {"device": None, "inode": None, "owner_uid": None, "group_gid": None,
                "mode": None, "acl_status": "unavailable", "acl": None, "mount": None}
    errors = []
    resolved = os.path.realpath(path)
    try:
        inode = os.stat(path)
        metadata.update(device=inode.st_dev, inode=inode.st_ino, owner_uid=inode.st_uid,
                        group_gid=inode.st_gid, mode=f"{stat.S_IMODE(inode.st_mode):04o}")
    except OSError as exc:
        return metadata, [f"Target metadata unavailable: {exc}"]
    try:
        acl = engine.read_access_acl(resolved)
        if acl is not None:
            engine.validate_acl_mode(acl, inode.st_mode)
        metadata["acl_status"] = "present" if acl is not None else "absent"
        metadata["acl"] = ([{"tag": entry.tag.name.lower(), "id": entry.qualifier, "permissions": entry.permissions}
                            for entry in acl.entries] if acl is not None else None)
    except engine.ACLInspectionError as exc:
        errors.append(f"Target ACL observation unavailable: {exc}")
    try:
        mount = engine.find_mount(resolved, engine.read_mounts())
        metadata["mount"] = {"point": mount.point, "filesystem": mount.filesystem,
                             "options": sorted(mount.options), "super_options": sorted(mount.super_options)}
    except (engine.DiagnosticError, OSError) as exc:
        errors.append(f"Target mount observation unavailable: {exc}")
    return metadata, errors


def _authorization(observation: dict) -> list[dict]:
    steps = [step for step in observation.get("access_path", []) if step.get("kind") == "inode"]
    if observation.get("target_inode"):
        steps.append(observation["target_inode"])
    routes = []
    for step in steps:
        acl = step["acl"]
        routes.append({"path": step["path"], "stage": step["stage"], "mechanism": step["mechanism"],
                       "permission_class": step["permission_class"], "root_assumption": step["root_assumption"],
                       "matched_groups": [{"gid": group["gid"], "membership": group["membership"]} for group in step["matched_groups"]],
                       "acl": {"selection": acl["decision_type"],
                               "entries": [{"tag": entry["tag"], "id": entry["id"]} for entry in acl["entries"]]} if acl else None,
                       "capability": (step.get("capability_override") or {}).get("capability")})
    return routes


def _subject(observation: dict, scope: str) -> SnapshotSubject:
    if scope == "accounts":
        identity = {"uid": observation["uid"], "username": observation["username"]}
        name = observation["username"]
    else:
        process = observation.get("process") or {}
        identity = {"pid": observation["pid"], "start_time_ticks": process.get("start_time_ticks")}
        name = observation["name"]
    routes = _authorization(observation)
    blocker = observation.get("first_blocker")
    mechanism = "mount" if blocker and blocker["stage"] == "mount" else routes[-1]["mechanism"] if routes else None
    if observation["verdict"] == "permitted" and any(route["capability"] for route in routes):
        mechanism = "capability"
    return SnapshotSubject(identity, name, observation["verdict"], mechanism, blocker, routes, observation)


def capture_snapshot(target: str, mode: str = "r", *, processes=False, engine=None) -> AccessSnapshot:
    if engine is None:
        import permissionhell as engine
    if not isinstance(target, str) or not target.startswith("/") or "\0" in target or mode not in ("r", "w", "x"):
        raise SnapshotError("Snapshot requires an absolute Linux target and mode r, w or x")
    try:
        target.encode("utf-8", "surrogateescape")
        engine.inspect_audit_target(target)
    except (engine.DiagnosticError, OSError, UnicodeError) as exc:
        raise SnapshotError(str(exc), getattr(exc, "code", 2 if isinstance(exc, UnicodeError) else 3)) from exc
    scope = "processes" if processes else "accounts"
    captured_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    system = system_context()
    before, errors = target_metadata(target, engine)
    if processes:
        audit = process_audit.audit_processes(target, mode, engine=engine)
        observations = process_audit.audit_document(audit, engine.__version__)["processes"]
    else:
        audit = engine.audit_target(target, mode)
        observations = json_output.audit_document(audit, engine.__version__)["accounts"]
    if audit.failure:
        errors.append(audit.failure)
    if audit.code and not audit.failure:
        errors.append(f"Underlying {scope} audit was incomplete (exit {int(audit.code)}).")
    after, after_errors = target_metadata(target, engine)
    errors.extend(after_errors)
    if before != after:
        errors.append("Target metadata changed during capture; subject observations are not a coherent snapshot.")
    subjects = [_subject(observation, scope) for observation in observations]
    subjects.sort(key=lambda subject: (subject.identity["uid"], subject.identity["username"]) if scope == "accounts" else (subject.identity["pid"],))
    return AccessSnapshot(engine.__version__, captured_at, scope, target, mode, system, after, subjects, list(dict.fromkeys(errors)))


def snapshot_document(snapshot: AccessSnapshot) -> dict:
    return {**asdict(snapshot), "capture_exit_code": snapshot.code}


def serialize_snapshot(snapshot: AccessSnapshot) -> str:
    return json.dumps(snapshot_document(snapshot), ensure_ascii=True, indent=2, sort_keys=True, allow_nan=False) + "\n"


def _require(condition, message):
    if not condition:
        raise SnapshotError(message)


def _integer(value, maximum=None):
    return type(value) is int and value >= 0 and (maximum is None or value <= maximum)


def validate_snapshot(data: dict) -> AccessSnapshot:
    required = {"snapshot_version", "tool_version", "captured_at", "scope", "target", "requested_mode", "system",
                "target_metadata", "subjects", "capture_errors", "capture_exit_code"}
    _require(isinstance(data, dict) and required <= data.keys(), "Snapshot is missing required fields")
    _require(type(data["snapshot_version"]) is int and data["snapshot_version"] == 1, "Unsupported snapshot_version")
    _require(isinstance(data["tool_version"], str) and bool(data["tool_version"]), "Invalid tool_version")
    _require(data["scope"] in ("accounts", "processes"), "Invalid snapshot scope")
    _require(data["requested_mode"] in ("r", "w", "x"), "Invalid snapshot mode")
    _require(isinstance(data["target"], str) and data["target"].startswith("/") and "\0" not in data["target"], "Invalid target path")
    try:
        data["target"].encode("utf-8", "surrogateescape")
    except UnicodeError as exc:
        raise SnapshotError("Invalid Linux target filename encoding") from exc
    try:
        timestamp = datetime.fromisoformat(data["captured_at"].replace("Z", "+00:00"))
        _require(timestamp.utcoffset() is not None and timestamp.utcoffset().total_seconds() == 0, "Timestamp must be UTC")
    except (ValueError, TypeError, AttributeError) as exc:
        raise SnapshotError("Invalid captured_at timestamp") from exc
    system = data["system"]
    fields = {"hostname", "kernel", "architecture", "platform", "boot_id", "pid_namespace"}
    _require(isinstance(system, dict) and fields <= system.keys() and
             all(system[key] is None or isinstance(system[key], str) for key in fields), "Invalid system metadata")
    metadata = data["target_metadata"]
    fields = {"device", "inode", "owner_uid", "group_gid", "mode", "acl_status", "acl", "mount"}
    _require(isinstance(metadata, dict) and fields <= metadata.keys(), "Invalid target metadata")
    _require(all(metadata[key] is None or _integer(metadata[key]) for key in ("device", "inode", "owner_uid", "group_gid")), "Invalid target IDs")
    mode = metadata["mode"]
    _require(mode is None or isinstance(mode, str) and len(mode) == 4 and all(c in "01234567" for c in mode), "Invalid target mode")
    _require(metadata["acl_status"] in ("present", "absent", "unavailable"), "Invalid ACL status")
    acl = metadata["acl"]
    _require((isinstance(acl, list) if metadata["acl_status"] == "present" else acl is None), "Invalid ACL representation")
    for entry in acl or []:
        _require(isinstance(entry, dict) and {"tag", "id", "permissions"} <= entry.keys() and
                 isinstance(entry["tag"], str) and (entry["id"] is None or _integer(entry["id"])) and
                 _integer(entry["permissions"], 7), "Invalid ACL entry")
    mount = metadata["mount"]
    if mount is not None:
        _require(isinstance(mount, dict) and {"point", "filesystem", "options", "super_options"} <= mount.keys(), "Invalid mount metadata")
        _require(isinstance(mount["point"], str) and isinstance(mount["filesystem"], str), "Invalid mount labels")
        _require(all(isinstance(mount[key], list) and all(isinstance(option, str) for option in mount[key])
                     for key in ("options", "super_options")), "Invalid mount options")
    _require(isinstance(data["capture_errors"], list) and all(isinstance(error, str) for error in data["capture_errors"]), "Invalid capture errors")
    _require(isinstance(data["subjects"], list), "Invalid subjects list")
    subjects, seen, account_names = [], set(), set()
    for row in data["subjects"]:
        fields = {"identity", "name", "verdict", "mechanism", "blocker", "authorization", "observation"}
        _require(isinstance(row, dict) and fields <= row.keys(), "Malformed subject record")
        identity = row["identity"]
        _require(isinstance(identity, dict), "Invalid subject identity")
        if data["scope"] == "accounts":
            _require({"uid", "username"} <= identity.keys() and _integer(identity["uid"], 0xFFFFFFFE) and
                     isinstance(identity["username"], str) and bool(identity["username"]), "Invalid account identity")
            key = identity["uid"], identity["username"]
            _require(identity["username"] not in account_names, "Duplicate account name")
            account_names.add(identity["username"])
        else:
            _require({"pid", "start_time_ticks"} <= identity.keys() and _integer(identity["pid"], 0x7FFFFFFF) and identity["pid"] > 0 and
                     (identity["start_time_ticks"] is None or _integer(identity["start_time_ticks"])), "Invalid process identity")
            key = identity["pid"]
        _require(key not in seen, "Duplicate snapshot subject identity")
        seen.add(key)
        _require(isinstance(row["verdict"], str) and row["verdict"] in VERDICTS, "Invalid subject verdict")
        _require(row["name"] is None or isinstance(row["name"], str), "Invalid subject name")
        _require(row["mechanism"] is None or isinstance(row["mechanism"], str), "Invalid mechanism")
        blocker = row["blocker"]
        _require(blocker is None or isinstance(blocker, dict) and {"path", "stage", "mechanism"} <= blocker.keys() and
                 all(isinstance(blocker[key], str) for key in ("path", "stage", "mechanism")), "Invalid blocker")
        _require(isinstance(row["authorization"], list), "Invalid authorization routes")
        for route in row["authorization"]:
            fields = {"path", "stage", "mechanism", "permission_class", "root_assumption", "matched_groups", "acl", "capability"}
            _require(isinstance(route, dict) and fields <= route.keys() and
                     all(isinstance(route[key], str) for key in ("path", "stage", "mechanism", "permission_class")), "Invalid authorization route")
            _require(route["capability"] is None or isinstance(route["capability"], str), "Invalid capability label")
            _require(isinstance(route["matched_groups"], list) and all(isinstance(group, dict) and
                     {"gid", "membership"} <= group.keys() and _integer(group["gid"]) and
                     group["membership"] in ("primary", "supplementary") for group in route["matched_groups"]), "Invalid matched groups")
            _require(route["root_assumption"] is None or isinstance(route["root_assumption"], str), "Invalid root assumption")
            acl_route = route["acl"]
            _require(acl_route is None or isinstance(acl_route, dict) and {"selection", "entries"} <= acl_route.keys() and
                     isinstance(acl_route["selection"], str) and isinstance(acl_route["entries"], list) and
                     all(isinstance(entry, dict) and {"tag", "id"} <= entry.keys() and isinstance(entry["tag"], str) and
                         (entry["id"] is None or _integer(entry["id"])) for entry in acl_route["entries"]), "Invalid ACL route")
            _require(route["mechanism"] != "posix_acl" or acl_route is not None, "POSIX ACL mechanism requires an ACL route")
        _require(isinstance(row["observation"], dict), "Invalid underlying observation")
        observation = row["observation"]
        _require("verdict" not in observation or observation["verdict"] == row["verdict"], "Conflicting subject verdicts")
        _require("reasons" not in observation or isinstance(observation["reasons"], list) and
                 all(isinstance(reason, str) for reason in observation["reasons"]), "Invalid observation reasons")
        _require(all(observation.get(key) is None or isinstance(observation[key], dict) for key in ("process", "subject")), "Invalid observation identity context")
        if data["scope"] == "accounts":
            _require(all(key not in observation or observation[key] == identity[key] for key in ("uid", "username")), "Conflicting account identities")
        else:
            _require("pid" not in observation or observation["pid"] == identity["pid"], "Conflicting PIDs")
            process = observation.get("process") or {}
            _require(all(key not in process or process[key] == identity[key] for key in ("pid", "start_time_ticks")), "Conflicting process identities")
        subjects.append(SnapshotSubject(**{key: row[key] for key in fields_for_subject()}))
    snapshot = AccessSnapshot(data["tool_version"], data["captured_at"], data["scope"], data["target"], data["requested_mode"],
                              system, metadata, subjects, data["capture_errors"])
    _require(type(data["capture_exit_code"]) is int and data["capture_exit_code"] == snapshot.code, "Inconsistent capture_exit_code")
    return snapshot


def fields_for_subject():
    return ("identity", "name", "verdict", "mechanism", "blocker", "authorization", "observation")


def load_snapshot(path: str) -> AccessSnapshot:
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, f"Duplicate JSON key: {key!r}")
            result[key] = value
        return result
    def constant(value):
        raise SnapshotError(f"Invalid JSON constant: {value}")
    def finite_float(value):
        number = float(value)
        _require(math.isfinite(number), "Non-finite JSON number")
        return number
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=pairs, parse_constant=constant,
                          parse_float=finite_float)
        return validate_snapshot(data)
    except (OSError, ValueError, TypeError, RecursionError, UnicodeError) as exc:
        raise SnapshotError(f"Invalid snapshot {path!r}: {exc}") from exc


def write_snapshot(snapshot: AccessSnapshot, output: str, *, force=False) -> None:
    """Publish a complete file atomically. Hard-link publication prevents clobber races."""
    destination = os.path.abspath(output)
    if os.path.abspath(snapshot.target) == destination:
        raise SnapshotError("Snapshot output must not replace the target")
    try:
        if os.path.lexists(destination):
            if not force:
                raise SnapshotError("Output already exists; use --force to replace a snapshot file")
            destination_stat = os.lstat(destination)
            if not stat.S_ISREG(destination_stat.st_mode):
                raise SnapshotError("--force only replaces regular files, not symlinks or directories")
            try:
                target_stat = os.stat(snapshot.target)
            except FileNotFoundError:
                target_stat = None
            if target_stat and (destination_stat.st_dev, destination_stat.st_ino) == (target_stat.st_dev, target_stat.st_ino):
                raise SnapshotError("Snapshot output aliases the target")
        temporary = None
        try:
            fd, temporary = tempfile.mkstemp(prefix=".permissionhell-", suffix=".tmp", dir=os.path.dirname(destination))
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(serialize_snapshot(snapshot))
                stream.flush()
                os.fsync(stream.fileno())
            if force:
                os.replace(temporary, destination)
            else:
                os.link(temporary, destination)
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)
    except (FileExistsError, FileNotFoundError, NotADirectoryError, IsADirectoryError, ValueError) as exc:
        raise SnapshotError(f"Invalid snapshot output {output!r}: {exc}") from exc
    except OSError as exc:
        raise SnapshotError(f"Cannot write snapshot output {output!r}: {exc}", 3) from exc


@dataclass
class SnapshotChange:
    subject_type: str
    subject: dict
    change: str
    before: SnapshotSubject | None
    after: SnapshotSubject | None
    mechanism_changed: bool = False
    context_changes: dict = field(default_factory=dict)


@dataclass
class SnapshotDiff:
    before: AccessSnapshot
    after: AccessSnapshot
    changes: list[SnapshotChange]
    target_changes: dict
    warnings: list[str]
    incomplete: bool = False

    @property
    def summary(self) -> dict:
        counts = Counter(change.change for change in self.changes)
        fields = ("gained_access", "lost_access", "unchanged_permitted", "unchanged_denied", "unchanged_indeterminate",
                  "became_indeterminate", "resolved_from_indeterminate", "subject_added", "subject_removed")
        result = {key: counts[key] for key in fields}
        result.update(mechanism_changed=sum(change.mechanism_changed for change in self.changes),
                      subject_metadata_changed=sum(bool(change.context_changes) for change in self.changes),
                      target_changed=int(bool(self.target_changes)),
                      target_identity_changed=int(any(key in self.target_changes for key in ("device", "inode"))))
        return result

    @property
    def code(self) -> int:
        meaningful = bool(self.target_changes) or any(not change.change.startswith("unchanged_") or
                                                      change.mechanism_changed or change.context_changes for change in self.changes)
        return 3 if self.incomplete else 1 if meaningful else 0


def _context(subject: SnapshotSubject) -> dict:
    observation = subject.observation
    process = observation.get("process")
    return {"name": subject.name, "credentials": observation.get("subject"),
            "process": {key: value for key, value in process.items() if key not in ("pid", "start_time_ticks", "name")}
                       if isinstance(process, dict) else None}


def diff_snapshots(before: AccessSnapshot, after: AccessSnapshot) -> SnapshotDiff:
    for key in ("scope", "target", "requested_mode"):
        if getattr(before, key) != getattr(after, key):
            raise SnapshotError(f"Cannot compare snapshots with different {key}")
    warnings = []
    if before.tool_version != after.tool_version:
        warnings.append("Tool versions differ; changes in the access model may affect comparisons.")
    if before.system["hostname"] != after.system["hostname"]:
        warnings.append("Different hosts: account UID/name comparison is contextual; process identities are not equivalent.")
    process_context = all(before.system[key] and before.system[key] == after.system[key]
                          for key in ("hostname", "boot_id", "pid_namespace"))
    incomplete = bool(before.code or after.code)
    if before.scope == "processes" and not process_context:
        warnings.append("Process host/boot/PID-namespace context differs or is unavailable; processes are compared as separate identities.")
        if any(not snapshot.system[key] for snapshot in (before, after) for key in ("hostname", "boot_id", "pid_namespace")):
            incomplete = True
    def identity(subject, side):
        nonlocal incomplete
        if before.scope == "accounts":
            return subject.identity["uid"], subject.identity["username"]
        if subject.identity["start_time_ticks"] is None:
            incomplete = True
            if "Missing process start times prevent safe PID matching." not in warnings:
                warnings.append("Missing process start times prevent safe PID matching.")
            return side, subject.identity["pid"], None
        return ("shared" if process_context else side, subject.identity["pid"], subject.identity["start_time_ticks"])
    old = {identity(subject, "before"): subject for subject in before.subjects}
    new = {identity(subject, "after"): subject for subject in after.subjects}
    changes = []
    for key in sorted(old.keys() | new.keys(), key=lambda value: json.dumps(value)):
        left, right = old.get(key), new.get(key)
        mechanism_changed, context_changes = False, {}
        if left is None:
            change = "subject_added"
        elif right is None:
            change = "subject_removed"
        else:
            a, b = left.verdict, right.verdict
            if a not in KNOWN:
                change = "resolved_from_indeterminate" if b in KNOWN else "unchanged_indeterminate"
            elif b not in KNOWN:
                change = "became_indeterminate"
            elif a != b:
                change = "gained_access" if b == "permitted" else "lost_access"
            else:
                change = "unchanged_" + a
                mechanism_changed = (left.mechanism, left.authorization, left.blocker) != (right.mechanism, right.authorization, right.blocker)
            lc, rc = _context(left), _context(right)
            context_changes = {key: {"before": lc[key], "after": rc[key]} for key in lc if lc[key] != rc[key]}
        changes.append(SnapshotChange("account" if before.scope == "accounts" else "process",
                                      (right or left).identity, change, left, right, mechanism_changed, context_changes))
    if before.scope == "accounts":
        old_names = {(s.identity["uid"], s.identity["username"]) for s in before.subjects}
        new_names = {(s.identity["uid"], s.identity["username"]) for s in after.subjects}
        if any(uid == other_uid or name == other_name for uid, name in old_names - new_names for other_uid, other_name in new_names - old_names):
            warnings.append("Account name/UID changed: possible rename or UID reuse; reported as separate subjects, not access gain/loss.")
    target_changes = {key: {"before": before.target_metadata.get(key), "after": after.target_metadata.get(key)}
                      for key in sorted(before.target_metadata.keys() | after.target_metadata.keys())
                      if before.target_metadata.get(key) != after.target_metadata.get(key)}
    if "inode" in target_changes or "device" in target_changes:
        warnings.append("TARGET_CHANGED: the same path has different inode/device observations; it may refer to a different object.")
    if incomplete:
        warnings.append("Comparison includes incomplete captures or unresolved identities; known changes are retained.")
    return SnapshotDiff(before, after, changes, target_changes, warnings, incomplete)


def diff_document(diff: SnapshotDiff, version: str) -> dict:
    def header(snapshot):
        return {"captured_at": snapshot.captured_at, "tool_version": snapshot.tool_version,
                "scope": snapshot.scope, "target": snapshot.target, "requested_mode": snapshot.requested_mode,
                "system": snapshot.system, "capture_exit_code": snapshot.code, "capture_errors": snapshot.capture_errors}
    return {"schema_version": "1", "command": "diff", "tool_version": version, "before": header(diff.before),
            "after": header(diff.after), "target_changes": diff.target_changes, "summary": diff.summary,
            "warnings": diff.warnings, "exit_code": diff.code, "changes": [asdict(change) for change in diff.changes]}


def _description(subject: SnapshotSubject | None) -> str:
    if subject is None:
        return "absent"
    mechanisms = []
    for route in subject.authorization:
        if (route["stage"] != "target" and not route["capability"] and not route["acl"] and
                (not subject.blocker or subject.blocker["path"] != route["path"])):
            continue
        mechanisms.append("ROOT model" if route["root_assumption"] else route["capability"] or
                          ("ACL " + route["acl"]["selection"] if route["acl"] else route["permission_class"]))
    mechanisms = list(dict.fromkeys(mechanisms))
    text = subject.verdict.upper() + (" via " + ", ".join(mechanisms) if mechanisms else "")
    return "".join(char if char.isprintable() else char.encode("unicode_escape").decode("ascii") for char in text)


def render_diff(diff: SnapshotDiff, version: str, *, verbose=False) -> str:
    label = version[:-2] if version.endswith(".0") else version
    lines = [f"PERMISSION HELL v{label} | SNAPSHOT DIFF", f"Target: {diff.before.target!r}",
             f"Mode: {diff.before.requested_mode} | Scope: {diff.before.scope}"]
    lines.extend("Note: " + warning for warning in diff.warnings)
    for change in diff.changes:
        if not verbose and change.change.startswith("unchanged_") and not change.mechanism_changed and not change.context_changes:
            continue
        title = "MECHANISM_CHANGED" if change.mechanism_changed else "SUBJECT_METADATA_CHANGED" if change.change.startswith("unchanged_") and change.context_changes else change.change.upper()
        subject = change.after or change.before
        label = f"{subject.identity['username']!r} (UID {subject.identity['uid']})" if diff.before.scope == "accounts" else f"PID {subject.identity['pid']} {subject.name!r} (start {subject.identity['start_time_ticks']})"
        lines.extend(["", title, "  " + label, "    before: " + _description(change.before), "    after: " + _description(change.after)])
        if change.mechanism_changed:
            lines.append("    Access remains " + change.after.verdict.upper())
        if change.after and change.after.blocker:
            lines.append(f"    blocker: {change.after.blocker['path']!r} ({change.after.blocker['stage']})")
        if change.after and change.after.verdict not in KNOWN:
            lines.extend("    uncertainty: " + repr(reason) for reason in change.after.observation.get("reasons", [])[:2])
        if change.context_changes:
            lines.append("    Subject context also changed: " + ", ".join(change.context_changes))
        if verbose:
            lines.append("    Full comparison: " + json.dumps(asdict(change), ensure_ascii=True, sort_keys=True))
    if diff.target_changes:
        lines.extend(["", "TARGET METADATA CHANGES (observed together; causality is not assumed)"])
        for key, values in diff.target_changes.items():
            lines.append(f"  {key}: " + (f"{values['before']!r} -> {values['after']!r}" if verbose or key not in ("acl", "mount") else "changed"))
    lines.extend(["", "SUMMARY", "  " + "; ".join(f"{count} {key}" for key, count in diff.summary.items())])
    return "\n".join(lines)


def render_capture(snapshot: AccessSnapshot, output: str) -> str:
    label = snapshot.tool_version[:-2] if snapshot.tool_version.endswith(".0") else snapshot.tool_version
    lines = [f"PERMISSION HELL v{label} | SNAPSHOT", f"Target: {snapshot.target!r}",
             f"Mode: {snapshot.requested_mode} | Scope: {snapshot.scope}", f"Subjects captured: {len(snapshot.subjects)}",
             f"Output: {output!r}", "Capture: " + ("INCOMPLETE (partial snapshot saved)" if snapshot.code else "complete")]
    lines.extend("Note: " + error for error in snapshot.capture_errors)
    return "\n".join(lines)
