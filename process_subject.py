"""Read-only Linux process snapshots. No account-group expansion or namespace entry."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import re
from capabilities import ProcessCapabilities, CapabilityError, STATUS_FIELDS, parse_capability_fields
from idmap import IDMap, IDMapEntry, IDMapError

try:
    import pwd
    import grp
except ImportError:
    pwd = grp = None


class ProcessInspectionError(Exception):
    def __init__(self, message: str, code: int = 3):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class CredentialIDs:
    real: int
    effective: int
    saved: int | None
    filesystem: int | None

    @property
    def used(self) -> int:
        return self.effective if self.filesystem is None else self.filesystem

    @property
    def source(self) -> str:
        return "effective_fallback" if self.filesystem is None else "filesystem"


@dataclass(frozen=True)
class ProcessStatus:
    name: str | None
    uids: CredentialIDs
    gids: CredentialIDs
    supplementary_gids: tuple[int, ...]
    effective_capabilities: str | None
    capabilities: ProcessCapabilities = field(default_factory=ProcessCapabilities)


@dataclass(frozen=True)
class NamespaceObservation:
    identifier: str | None
    debugger_identifier: str | None
    matches_debugger: bool | None
    error: str | None = None


@dataclass(frozen=True)
class RootObservation:
    path: str | None
    device: int | None
    inode: int | None
    debugger_device: int | None
    debugger_inode: int | None
    matches_debugger: bool | None
    error: str | None = None
    debugger_path: str | None = None


@dataclass(frozen=True)
class ProcessSubject:
    pid: int
    start_time_ticks: int
    status: ProcessStatus
    uid_names: dict[int, str | None]
    gid_names: dict[int, str | None]
    mount_namespace: NamespaceObservation
    user_namespace: NamespaceObservation
    root: RootObservation
    uid_map: tuple[IDMapEntry, ...] | None
    gid_map: tuple[IDMapEntry, ...] | None
    notes: tuple[str, ...] = ()
    setgroups: str = "unavailable"
    overflow_uid: int | None = None
    overflow_gid: int | None = None

    @property
    def limitations(self) -> tuple[str, ...]:
        reasons = []
        for label, observation in (("mount namespace", self.mount_namespace),
                                   ("user namespace", self.user_namespace), ("root", self.root)):
            if observation.matches_debugger is False and label != "user namespace":
                reasons.append(f"PID {self.pid} has a different {label} from the debugger; "
                               "foreign namespaces/root mappings are not evaluated.")
            elif observation.matches_debugger is None:
                reasons.append(f"Cannot establish the process {label}: {observation.error}")
        return tuple(reasons)


def numeric_id(value: str) -> int:
    if not re.fullmatch(r"[0-9]{1,10}", value) or int(value) >= 0xFFFFFFFF:
        raise ProcessInspectionError(f"Malformed process credential ID: {value!r}")
    return int(value)


def parse_status(text: str) -> ProcessStatus:
    fields = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator and (key in ("Name", "Uid", "Gid", "Groups") or key in STATUS_FIELDS):
            if key in fields:
                raise ProcessInspectionError(f"Duplicate process status field: {key}")
            fields[key] = value.strip()
    def ids(key: str) -> CredentialIDs:
        if key not in fields or len(fields[key].split()) not in (2, 3, 4):
            raise ProcessInspectionError(f"Missing or malformed {key} field in process status")
        values = [numeric_id(v) for v in fields[key].split()]
        return CredentialIDs(values[0], values[1], values[2] if len(values) > 2 else None,
                             values[3] if len(values) > 3 else None)
    uids, gids = ids("Uid"), ids("Gid")
    if "Groups" not in fields:
        raise ProcessInspectionError("Missing Groups field in process status; membership is unknown")
    groups = tuple(sorted({numeric_id(v) for v in fields["Groups"].split()}))
    try:
        capabilities = parse_capability_fields(fields)
    except CapabilityError as exc:
        raise ProcessInspectionError(str(exc)) from exc
    return ProcessStatus(fields.get("Name"), uids, gids, groups, fields.get("CapEff"), capabilities)


def parse_id_map(text: str) -> tuple[IDMapEntry, ...]:
    try:
        return IDMap.parse(text).entries
    except IDMapError as exc:
        raise ProcessInspectionError(str(exc)) from exc


def parse_setgroups(text: str) -> str:
    if text.strip() not in ("allow", "deny"):
        raise ProcessInspectionError("Malformed setgroups state")
    return text.strip()


def read_setgroups(pid: int) -> str:
    try:
        return parse_setgroups(Path(f"/proc/{pid}/setgroups").read_text(encoding="ascii"))
    except OSError:
        return "unavailable"


def read_overflow_id(kind: str) -> int | None:
    try:
        return numeric_id(Path(f"/proc/sys/kernel/overflow{kind}").read_text(encoding="ascii").strip())
    except (OSError, ProcessInspectionError):
        return None


def read_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="surrogateescape")


def start_time(pid: int) -> int:
    text = read_text(f"/proc/{pid}/stat")
    prefix, separator, tail = text.rpartition(")")
    fields = tail.split()
    if not separator or not prefix.startswith(f"{pid} (") or len(fields) < 20 or not fields[19].isdigit():
        raise ProcessInspectionError(f"Malformed /proc/{pid}/stat start time")
    return int(fields[19])


def namespace(pid: int, kind: str) -> NamespaceObservation:
    observed = debugger = None
    try:
        observed = os.readlink(f"/proc/{pid}/ns/{kind}")
        debugger = os.readlink(f"/proc/self/ns/{kind}")
        if any(not re.fullmatch(rf"{kind}:\[[0-9]+\]", value) for value in (observed, debugger)):
            raise ValueError("Malformed namespace identifier")
        return NamespaceObservation(observed, debugger, observed == debugger)
    except (OSError, ValueError) as exc:
        return NamespaceObservation(observed, debugger, None, str(exc))


def process_root(pid: int) -> RootObservation:
    path = None
    try:
        path = os.readlink(f"/proc/{pid}/root")
        debugger_path = os.readlink("/proc/self/root")
        observed, debugger = os.stat(f"/proc/{pid}/root"), os.stat("/")
        same = path == debugger_path and (observed.st_dev, observed.st_ino) == (debugger.st_dev, debugger.st_ino)
        return RootObservation(path, observed.st_dev, observed.st_ino, debugger.st_dev, debugger.st_ino, same,
                               debugger_path=debugger_path)
    except OSError as exc:
        return RootObservation(path, None, None, None, None, None, str(exc))


def identity_name(identifier: int, *, group: bool = False) -> str | None:
    try:
        return grp.getgrgid(identifier).gr_name if group else pwd.getpwuid(identifier).pw_name
    except (KeyError, OSError):
        # Names are labels only, never a source of process credentials or groups.
        return None


def inspect_process(pid: int) -> ProcessSubject:
    if not isinstance(pid, int) or isinstance(pid, bool) or not 0 < pid <= 0x7FFFFFFF:
        raise ProcessInspectionError("PID must be a positive Linux process ID", 2)
    try:
        started = start_time(pid)
    except FileNotFoundError as exc:
        raise ProcessInspectionError(f"PID {pid} does not exist or is not visible in this procfs", 2) from exc
    except OSError as exc:
        raise ProcessInspectionError(f"Cannot inspect PID {pid}: {exc}") from exc
    try:
        status = parse_status(read_text(f"/proc/{pid}/status"))
        mount_ns, user_ns, root = namespace(pid, "mnt"), namespace(pid, "user"), process_root(pid)
        setgroups = read_setgroups(pid)
        overflow_uid = read_overflow_id("uid") if user_ns.matches_debugger is False else None
        overflow_gid = read_overflow_id("gid") if user_ns.matches_debugger is False else None
        notes = []
        maps = []
        for kind in ("uid", "gid"):
            try:
                maps.append(parse_id_map(read_text(f"/proc/{pid}/{kind}_map")))
            except PermissionError as exc:
                maps.append(None)
                purpose = "required for foreign identity mapping" if user_ns.matches_debugger is False else "observational only"
                notes.append(f"Cannot inspect {kind}_map ({purpose}): {exc}")
        if status.uids.filesystem is None:
            notes.append("fsuid unavailable: effective UID is the explicit filesystem-identity fallback.")
        if status.gids.filesystem is None:
            notes.append("fsgid unavailable: effective GID is the explicit filesystem-identity fallback.")
        uids = {v for v in (status.uids.real, status.uids.effective, status.uids.saved, status.uids.filesystem) if v is not None}
        gids = {v for v in (status.gids.real, status.gids.effective, status.gids.saved, status.gids.filesystem,
                           *status.supplementary_gids) if v is not None}
        uid_names = {uid: identity_name(uid) for uid in sorted(uids)}
        gid_names = {gid: identity_name(gid, group=True) for gid in sorted(gids)}
        if start_time(pid) != started or parse_status(read_text(f"/proc/{pid}/status")) != status:
            raise ProcessInspectionError(f"PID {pid} changed identity or credentials during inspection; retry")
        return ProcessSubject(pid, started, status, uid_names, gid_names, mount_ns, user_ns, root,
                              maps[0], maps[1], tuple(notes), setgroups, overflow_uid, overflow_gid)
    except OSError as exc:
        raise ProcessInspectionError(f"PID {pid} disappeared or proc metadata became inaccessible during inspection: {exc}") from exc
