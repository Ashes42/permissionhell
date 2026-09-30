"""Optional host policy queries and bounded audit evidence. Never changes policy."""
import importlib
import ctypes
import json
import math
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import time


LOG_PATHS = ("/var/log/audit/audit.log", "/var/log/kern.log", "/var/log/syslog")
LOG_LIMIT = 256 * 1024
RECENT_SECONDS = 120


def unresolved(module, reason, evidence=()):
    return {"module": module, "decision": "unresolved", "reason": reason, "evidence": list(evidence)}


def load_selinux():
    # No dependency installation, policy file parsing or guessed allow-rule search.
    try:
        return importlib.import_module("selinux")
    except ImportError:
        return NativeSELinux()


class NativeSELinux:
    """Small binding to libselinux's public ABI for isolated Python environments."""
    class av_decision(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint32) for name in
                    ("allowed", "decided", "auditallow", "auditdeny", "seqno", "flags")]

    def __init__(self):
        self.library = ctypes.CDLL("libselinux.so.1", use_errno=True)
        signatures = {
            "is_selinux_enabled": ([], ctypes.c_int),
            "security_getenforce": ([], ctypes.c_int),
            "string_to_security_class": ([ctypes.c_char_p], ctypes.c_ushort),
            "string_to_av_perm": ([ctypes.c_ushort, ctypes.c_char_p], ctypes.c_uint32),
            "security_compute_av_flags_raw": ([ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ushort,
                                               ctypes.c_uint32, ctypes.POINTER(self.av_decision)], ctypes.c_int),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.library, name)
            function.argtypes, function.restype = arguments, result

    def is_selinux_enabled(self):
        return self.library.is_selinux_enabled()

    def security_getenforce(self):
        return self.library.security_getenforce()

    def string_to_security_class(self, name):
        return self.library.string_to_security_class(name.encode("ascii"))

    def string_to_av_perm(self, cls, name):
        return self.library.string_to_av_perm(cls, name.encode("ascii"))

    def security_compute_av_flags_raw(self, source, target, cls, requested, decision):
        return self.library.security_compute_av_flags_raw(source.encode("utf-8"), target.encode("utf-8"),
                                                         cls, requested, ctypes.byref(decision))


def context(path):
    from lsm import parse_selinux
    return parse_selinux(os.getxattr(path, "security.selinux").decode("utf-8"))


def inode_identity(path):
    info = os.stat(path)
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def uint(value, maximum=0xFFFFFFFF):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("Malformed policy API integer")
    return value


def av_query(api, source, target, object_class, permissions):
    cls = uint(api.string_to_security_class(object_class), 0xFFFF)
    if not cls:
        raise ValueError("SELinux object class unavailable")
    requested = 0
    for permission in permissions:
        value = uint(api.string_to_av_perm(cls, permission))
        if not value or value & (value - 1):
            raise ValueError("SELinux permission mapping unavailable")
        requested |= value
    decision = api.av_decision()
    rc = api.security_compute_av_flags_raw(source, target, cls, requested, decision)
    if type(rc) is not int or rc != 0:
        raise ValueError("SELinux policy query failed")
    allowed, decided, flags, sequence = (uint(getattr(decision, name)) for name in ("allowed", "decided", "flags", "seqno"))
    if decided & requested != requested or flags & ~1:
        raise ValueError("Incomplete policy vector or unsupported decision flags")
    return {"allowed": bool(flags & 1 or allowed & requested == requested),
            "requested_vector": requested, "allowed_vector": allowed, "decided_vector": decided,
            "policy_sequence": sequence, "domain_permissive": bool(flags & 1)}


def query_selinux(state, diagnosis):
    """Query every supported traversal/target vector; recheck labels and sequence."""
    se = state.selinux
    if not se.process_context or not se.target_context or se.target_status != "present":
        return unresolved("selinux", "SELinux process or target context unavailable; no decision query is safe.")
    evidence = []
    try:
        api = load_selinux()
        if uint(api.is_selinux_enabled(), 1) != 1 or uint(api.security_getenforce(), 1) != 1:
            return unresolved("selinux", "Host SELinux state disagrees with the captured enforcing state.")
        steps = []
        incomplete_path = False
        for item in diagnosis.trace.events:
            if not hasattr(item, "mode"):
                incomplete_path = True  # Symlink authorization is not fully queried.
                continue
            steps.append((item, "dir", ("search",)))
        target = diagnosis.trace.target
        if target is None:
            return unresolved("selinux", "No resolved target inode for policy query.")
        if stat.S_ISREG(target.mode):
            cls = "file"
            permissions = {"r": ("open", "read"), "w": ("open", "write"), "x": ("execute",)}[diagnosis.mode]
            incomplete_path |= diagnosis.mode == "x"  # Domain/entrypoint transitions are separate.
        elif stat.S_ISDIR(target.mode):
            cls = "dir"
            permissions = {"r": ("open", "read"), "w": ("write",), "x": ("search",)}[diagnosis.mode]
            incomplete_path |= diagnosis.mode == "w"  # No create/delete operation specified.
        else:
            return unresolved("selinux", "Special inode classes are not supported by the policy query adapter.")
        steps.append((target, cls, permissions))
        observations = []
        for item, cls, permissions in steps:
            identity = inode_identity(item.path)
            if identity[2:] != (item.mode, item.uid, item.gid):
                raise ValueError("Inode metadata changed since ordinary analysis")
            label = context(item.path)
            if item is target and label != se.target_context:
                raise ValueError("Target context changed since inspection")
            vector = av_query(api, se.process_context, label, cls, permissions)
            observations.append((item.path, identity, label, cls, permissions))
            evidence.append({"source": "libselinux.security_compute_av_flags_raw", "kind": "kernel_policy_query",
                             "adapter": "ctypes" if isinstance(api, NativeSELinux) else "python_selinux",
                             "path": item.path, "process_context": se.process_context, "target_context": label,
                             "object_class": cls, "permissions": list(permissions), **vector})
        # Reacquire mappings on every query and detect policy reloads across calls.
        first = observations[0]
        last_vector = av_query(api, se.process_context, first[2], first[3], first[4])
        if any(item["policy_sequence"] != last_vector["policy_sequence"] for item in evidence):
            raise ValueError("SELinux policy changed during queries")
        if any(last_vector[key] != evidence[0][key] for key in last_vector):
            raise ValueError("SELinux decision changed during queries")
        if uint(api.security_getenforce(), 1) != 1:
            raise ValueError("SELinux enforcement changed during queries")
        for path, identity, label, _, _ in observations:
            if inode_identity(path) != identity or context(path) != label:
                raise ValueError("Inode identity or context changed during queries")
        if any(not item["allowed"] for item in evidence):
            denied = next(item for item in evidence if not item["allowed"])
            return {"module": "selinux", "decision": "denied", "evidence": evidence,
                    "reason": f"SELinux policy denies {','.join(denied['permissions'])} ({denied['object_class']}) at {denied['path']!r}."}
        if incomplete_path:
            return unresolved("selinux", "Queried vectors allow access, but symlink/exec-transition/directory-mutation checks remain unmodeled.", evidence)
        return {"module": "selinux", "decision": "allowed", "evidence": evidence,
                "reason": "SELinux kernel policy permits all modeled directory-search and target access vectors; not a syscall guarantee."}
    except (ImportError, AttributeError, OSError, UnicodeError, ValueError, TypeError, RuntimeError) as exc:
        return unresolved("selinux", f"SELinux host policy query unavailable or invalid: {exc!s}", evidence)


def parse_denial(message):
    """Parse only complete audit key/value records, never interpret log prose."""
    match = re.search(r"audit\(([0-9]+(?:\.[0-9]+)?):([0-9]+)\)", message)
    if not match or len(message) > 16384:
        return None
    try:
        timestamp = float(match[1])
        if not math.isfinite(timestamp):
            return None
        fields = {}
        for token in shlex.split(message[match.end():]):
            key, separator, value = token.partition("=")
            if separator:
                if key in fields:
                    return None
                fields[key] = value
        if fields.get("apparmor") != "DENIED":
            return None
        for name in ("profile", "name"):
            value = fields.get(name, "")
            if re.search(rf"\b{name}=[0-9A-Fa-f]+(?:\s|$)", message) and re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", value):
                value = bytes.fromhex(value).decode("utf-8")
            if not value or any(not c.isprintable() for c in value):
                return None
            fields[name] = value
        if not fields["name"].startswith("/") or not re.fullmatch(r"[0-9]+", fields.get("pid", "")):
            return None
        return {"timestamp": timestamp, "audit_id": match[2], "pid": int(fields["pid"]),
                "profile": fields["profile"], "path": fields["name"], "operation": fields.get("operation"),
                "denied_mask": fields.get("denied_mask", ""), "requested_mask": fields.get("requested_mask", "")}
    except (ValueError, UnicodeError):
        return None


def read_log_tail(path):
    # Refuse links, devices and FIFOs. Log rotation/unreadability is ordinary absence.
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise OSError("Log source is not a regular file")
        start = max(0, info.st_size - LOG_LIMIT)
        stream.seek(start)
        raw = stream.read(LOG_LIMIT)
        if start:
            raw = raw.partition(b"\n")[2]  # Never accept a truncated first record.
        return raw.decode("utf-8", errors="replace")


def read_journal():
    executable = next((path for path in ("/usr/bin/journalctl", "/bin/journalctl") if os.path.isfile(path)), None)
    if executable is None:
        raise OSError("journalctl unavailable")
    completed = subprocess.run([executable, "--no-pager", "--quiet", "-b", "--since=-2min", "-n", "200",
                                "-o", "json", "_TRANSPORT=kernel", "+", "_TRANSPORT=audit"],
                               capture_output=True, text=True, timeout=2, check=False,
                               env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    if completed.returncode != 0 or len(completed.stdout) > 4 * LOG_LIMIT:
        raise OSError("Journal unavailable, failed or exceeded output limit")
    return completed.stdout


def correlate_apparmor(state, process, diagnosis):
    """Matched logs are historical evidence, not proof of current policy denial."""
    matches, sources, errors = [], [], []
    try:
        now = time.time()
        born = now - time.clock_gettime(time.CLOCK_BOOTTIME) + process.start_time_ticks / os.sysconf("SC_CLK_TCK")
        if not math.isfinite(born) or born > now:
            raise ValueError("Process birth time unavailable")
    except (OSError, ValueError, AttributeError):
        return unresolved("apparmor", "Cannot establish process lifetime for audit correlation.")
    messages = []
    for source in LOG_PATHS:
        try:
            messages.extend((source, line) for line in read_log_tail(source).splitlines())
            sources.append(source)
        except OSError:
            errors.append(source)
    try:
        for line in read_journal().splitlines():
            record = json.loads(line)
            if not isinstance(record, dict) or record.get("_TRANSPORT") not in ("kernel", "audit") or not isinstance(record.get("MESSAGE"), str):
                continue
            messages.append(("journalctl", record["MESSAGE"]))
        sources.append("journalctl")
    except (OSError, ValueError, subprocess.TimeoutExpired):
        errors.append("journalctl")
    target = diagnosis.trace.resolved_path
    operation = {"r": {"open", "file_perm"}, "w": {"open", "file_perm"}, "x": {"exec"}}[diagnosis.mode]
    seen = set()
    for source, message in messages:
        event = parse_denial(message)
        if not event or event["pid"] != process.pid or event["profile"] != state.apparmor.profile or event["path"] != target:
            continue
        if event["operation"] not in operation or diagnosis.mode not in event["denied_mask"] or diagnosis.mode not in event["requested_mask"]:
            continue
        if not max(now - RECENT_SECONDS, born + 1) <= event["timestamp"] <= now:
            continue
        key = (event["timestamp"], event["audit_id"])
        if key in seen:
            continue
        seen.add(key)
        matches.append({"source": source, "kind": "historical_audit_correlation", **event,
                        "observed_start_time_ticks": process.start_time_ticks,
                        "limitation": "Log lacks process generation, target inode and current-policy proof; PID namespace attribution may be ambiguous."})
        if len(matches) >= 20:
            break
    reason = ("AppArmor DENIED events match PID/profile/path/operation/recent lifetime, but cannot prove the current request is denied."
              if matches else "No conclusive AppArmor denial evidence; absence of logs never proves permission.")
    return {**unresolved("apparmor", reason, matches), "readable_sources": sources, "unavailable_sources": errors}
