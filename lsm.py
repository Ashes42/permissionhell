"""Read-only LSM observations and conservative decisions; no policy interpreter.

None means unknown, never disabled. Proc attributes are read per LSM first;
the legacy shared attribute is used only when its owner is unambiguous.
"""
from dataclasses import asdict, dataclass, field, replace
import errno
import os
from pathlib import Path
import re


@dataclass(frozen=True)
class AppArmorContext:
    enabled: bool | None = None
    profile: str | None = None
    mode: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class SELinuxContext:
    enabled: bool | None = None
    enforcing: bool | None = None
    process_context: str | None = None
    target_context: str | None = None
    target_status: str = "not_inspected"
    error: str | None = None
    policy_loaded: bool | None = None


@dataclass(frozen=True)
class LSMState:
    active: tuple[str, ...] = ()
    active_status: str = "unavailable"
    apparmor: AppArmorContext = field(default_factory=AppArmorContext)
    selinux: SELinuxContext = field(default_factory=SELinuxContext)
    errors: tuple[str, ...] = ()
    malformed: tuple[str, ...] = ()


@dataclass(frozen=True)
class LSMDecision:
    status: str
    reasons: tuple[str, ...]


def parse_active(text: str) -> tuple[str, ...]:
    text = text.strip()
    if not text:
        return ()
    names = tuple(text.split(","))
    if any(not re.fullmatch(r"[a-z][a-z0-9_]*", name) for name in names) or len(set(names)) != len(names):
        raise ValueError("Malformed active LSM list")
    return names


def clean_label(text: str) -> str:
    text = text.rstrip("\x00\n")
    if not text or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in text):
        raise ValueError("Malformed security label")
    return text


def parse_apparmor(text: str) -> tuple[str, str]:
    text = clean_label(text)
    if text == "unconfined":
        return text, "unconfined"
    match = re.fullmatch(r"(.+) \((enforce|complain|kill|mixed|prompt)\)", text)
    if match:
        # Stacked profiles cannot be assumed non-enforcing from a suffix alone.
        return match[1], "unknown" if "//&" in match[1] else match[2]
    return text, "unknown"


def parse_selinux(text: str) -> str:
    text = clean_label(text)
    # The kernel exports this initial SID before the first policy load.
    # security/selinux/ss/services.c: security_sid_to_context_core().
    if text == "kernel":
        return text
    if not re.fullmatch(r"[^:\s]+:[^:\s]+:[^:\s]+(?::[^\s]+)?", text):
        raise ValueError("Malformed SELinux context")
    return text


def read_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="strict")


def read_value(path: str) -> tuple[str | None, str | None]:
    try:
        return read_text(path), None
    except (OSError, UnicodeError) as exc:
        expected = isinstance(exc, OSError) and exc.errno in (
            errno.ENOENT, errno.EACCES, errno.EPERM, errno.ENOTSUP, errno.EINVAL, errno.ENOSYS, errno.ENODEV)
        # PermissionError() fixtures (and custom readers) may not carry errno.
        expected = expected or isinstance(exc, (FileNotFoundError, PermissionError))
        return None, ("" if expected else "Inspection error: ") + f"{path}: {exc}"


def detect_system() -> LSMState:
    errors = []
    malformed = []
    raw, error = read_value("/sys/kernel/security/lsm")
    active, status = (), "unavailable"
    if raw is not None:
        try:
            active, status = parse_active(raw), "available"
        except ValueError as exc:
            error = str(exc)
            malformed.append(error)
            status = "malformed"
    if error:
        errors.append(error)
        if error.startswith("Inspection error:"):
            malformed.append(error)
    aa = "apparmor" in active if status == "available" else None
    se = "selinux" in active if status == "available" else None
    if aa is None:
        value, error = read_value("/sys/module/apparmor/parameters/enabled")
        if value is not None and value.strip() in ("Y", "N"):
            aa = value.strip() == "Y"
        elif error or value is not None:
            errors.append(error or "Malformed AppArmor enabled state")
            if value is not None:
                malformed.append("Malformed AppArmor enabled state")
            elif error.startswith("Inspection error:"):
                malformed.append(error)
    enforcing = None
    if se is not False:
        value, error = read_value("/sys/fs/selinux/enforce")
        if value is not None:
            se = True
            if value.strip() in ("0", "1"):
                enforcing = value.strip() == "1"
            else:
                errors.append("Malformed SELinux enforcement state")
                malformed.append("Malformed SELinux enforcement state")
        elif error:
            errors.append(error)
            if error.startswith("Inspection error:"):
                malformed.append(error)
        # Missing selinuxfs in a mount namespace is not evidence of inactivity.
    return LSMState(active, status, AppArmorContext(aa), SELinuxContext(se, enforcing), tuple(errors), tuple(malformed))


def process_attribute(pid: int, name: str, state: LSMState) -> tuple[str | None, str | None]:
    value, error = read_value(f"/proc/{pid}/attr/{name}/current")
    other = state.selinux.enabled if name == "apparmor" else state.apparmor.enabled
    if value is None and other is False and not set(state.active).intersection({"smack", "tomoyo"}):
        value, error = read_value(f"/proc/{pid}/attr/current")
    return value, error


def inspect_process(pid: int) -> LSMState:
    state = detect_system()
    malformed = list(state.malformed)
    aa, se = state.apparmor, state.selinux
    if aa.enabled is not False:
        raw, error = process_attribute(pid, "apparmor", state)
        if raw is not None:
            try:
                profile, mode = parse_apparmor(raw)
                aa = AppArmorContext(True, profile, mode)
            except ValueError as exc:
                error = str(exc)
                malformed.append(error)
        if error:
            aa = replace(aa, error=error)
            if error.startswith("Inspection error:"):
                malformed.append(error)
    if se.enabled is not False:
        raw, error = process_attribute(pid, "selinux", state)
        if raw is not None:
            try:
                context = parse_selinux(raw)
                se = replace(se, enabled=True, process_context=context, policy_loaded=context != "kernel")
            except ValueError as exc:
                error = str(exc)
                if se.enforcing is not False:
                    malformed.append(error)
        if error:
            se = replace(se, error=error)
            if se.enforcing is not False and error.startswith("Inspection error:"):
                malformed.append(error)
    return replace(state, apparmor=aa, selinux=se, malformed=tuple(malformed))


def inspect_target(state: LSMState, path: str) -> LSMState:
    if state.selinux.enabled is False:
        return state
    try:
        context = parse_selinux(os.getxattr(path, "security.selinux").decode("utf-8"))
        se = replace(state.selinux, target_context=context, target_status="present")
    except (OSError, AttributeError, UnicodeError, ValueError) as exc:
        code = getattr(exc, "errno", None)
        status = ("absent" if code == errno.ENODATA else "permission_denied" if code in (errno.EACCES, errno.EPERM)
                  else "unsupported" if code in (errno.ENOTSUP, errno.EOPNOTSUPP) or isinstance(exc, AttributeError)
                  else "unavailable")
        se = replace(state.selinux, target_status=status,
                     error="; ".join(filter(None, (state.selinux.error, f"Target context {status}: {exc}"))))
    return replace(state, selinux=se)


def evaluate(state: LSMState, ordinary_code: int) -> LSMDecision:
    if ordinary_code != 0:
        return LSMDecision("not_required", ("Ordinary permissions already deny access." if ordinary_code == 1
                           else "Ordinary permission analysis did not establish a permit.",))
    if state.malformed:
        return LSMDecision("error", state.malformed)
    reasons, notes = [], []
    aa, se = state.apparmor, state.selinux
    if aa.enabled is False:
        notes.append("AppArmor inactive.")
    elif aa.enabled and aa.mode in ("unconfined", "complain"):
        notes.append("AppArmor unconfined: no additional restriction modeled." if aa.mode == "unconfined"
                     else "AppArmor complain mode: informational, non-enforcing in this model.")
    else:
        reasons.append("AppArmor profile is active but policy rules are not evaluated." if aa.enabled and aa.profile
                       else "AppArmor state/profile unavailable; final authorization cannot be established.")
    if se.enabled is False:
        notes.append("SELinux inactive.")
    elif se.enabled and se.policy_loaded is False:
        notes.append("SELinux initial kernel context: policy not loaded; no policy restriction modeled.")
    elif se.enabled and se.enforcing is False:
        notes.append("SELinux permissive: would log policy denials without enforcing them.")
    else:
        reasons.append("SELinux enforcing: policy decision is not evaluated." if se.enforcing
                       else "SELinux activity/enforcement unavailable; final authorization cannot be established.")
    # These can mediate file access. Landlock availability alone does not prove
    # this task installed a ruleset; its per-task restrictions are not observable.
    relevant = set(state.active).intersection({"smack", "tomoyo", "bpf", "ipe"})
    if relevant:
        reasons.append("Active file-policy LSMs not evaluated: " + ", ".join(sorted(relevant)) + ".")
    if "landlock" in state.active:
        notes.append("Landlock available; per-task rulesets are not detected or modeled.")
    return LSMDecision("indeterminate" if reasons else "resolved", tuple(reasons + notes))


def document(state: LSMState) -> dict:
    result = asdict(state)
    for key in ("active", "errors", "malformed"):
        result[key] = list(result[key])
    return result


def decision_document(decision: LSMDecision) -> dict:
    return {"status": decision.status, "reason": " ".join(decision.reasons), "reasons": list(decision.reasons)}


def summary_lines(state: LSMState) -> list[str]:
    def enabled(value):
        return {True: "active", False: "inactive", None: "unavailable"}[value]
    aa, se = state.apparmor, state.selinux
    return ["Active LSMs: " + (", ".join(state.active) if state.active_status == "available" else state.active_status),
            f"AppArmor: {enabled(aa.enabled)}; profile={aa.profile!r}; mode={aa.mode or 'unknown'}",
            f"SELinux: {enabled(se.enabled)}; " + {True: "enforcing", False: "permissive", None: "enforcement unknown"}[se.enforcing],
            f"SELinux process context: {se.process_context!r}; target: {se.target_context!r} ({se.target_status})",
            "SELinux policy: " + {True: "loaded", False: "not loaded", None: "unknown"}[se.policy_loaded]]
