"""Versioned intended policy compared with existing effective-access observations."""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
import posixpath

import json_output
import process_audit


class PolicyError(ValueError):
    """Invalid format or input; permission evaluation has not started."""


@dataclass(frozen=True)
class SubjectPolicy:
    allow: tuple[str | int, ...] = ()
    deny: tuple[str | int, ...] = ()
    deny_others: bool = False


@dataclass(frozen=True)
class PolicyCheck:
    mode: str
    accounts: SubjectPolicy | None = None
    processes: SubjectPolicy | None = None


@dataclass(frozen=True)
class ResourcePolicy:
    path: str
    checks: tuple[PolicyCheck, ...]


@dataclass(frozen=True)
class PolicyDocument:
    resources: tuple[ResourcePolicy, ...]
    policy_version: int = 1


def _object(value, allowed: set[str], required: set[str], location: str) -> dict:
    if not isinstance(value, dict):
        raise PolicyError(f"{location}: expected an object")
    unknown, missing = set(value) - allowed, required - set(value)
    if unknown or missing:
        raise PolicyError(f"{location}: unknown keys {sorted(unknown)}; missing keys {sorted(missing)}")
    return value


def _list(value, location: str, *, nonempty: bool = False) -> list:
    if not isinstance(value, list) or (nonempty and not value):
        raise PolicyError(f"{location}: expected {'a nonempty' if nonempty else 'a'} list")
    return value


def _scope(value, domain: str, location: str) -> SubjectPolicy:
    value = _object(value, {"allow", "deny", "deny_others"}, set(), location)
    if type(value.get("deny_others", False)) is not bool:
        raise PolicyError(f"{location}.deny_others: expected boolean")
    lists = []
    for access in ("allow", "deny"):
        members = _list(value.get(access, []), location + "." + access)
        for member in members:
            if domain == "accounts":
                valid = isinstance(member, str) and bool(member) and all(c.isprintable() and not c.isspace() for c in member)
            else:
                valid = type(member) is int and 0 < member <= 0x7FFFFFFF
            if not valid:
                raise PolicyError(f"{location}.{access}: invalid {'account name' if domain == 'accounts' else 'PID'} {member!r}")
        if len(set(members)) != len(members):
            raise PolicyError(f"{location}.{access}: duplicate subject")
        lists.append(tuple(members))
    if set(lists[0]) & set(lists[1]):
        raise PolicyError(f"{location}: contradictory allow/deny declarations")
    if not any(lists) and not value.get("deny_others", False):
        raise PolicyError(f"{location}: declare allow/deny subjects or enable deny_others")
    return SubjectPolicy(*lists, value.get("deny_others", False))


def parse_policy(text: str) -> PolicyDocument:
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise PolicyError(f"Duplicate JSON key: {key!r}")
            result[key] = value
        return result
    def invalid_constant(value):
        raise PolicyError(f"Invalid JSON constant: {value}")
    try:
        data = json.loads(text, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    except (ValueError, RecursionError) as exc:
        raise PolicyError(f"Invalid policy JSON: {exc}") from exc
    data = _object(data, {"policy_version", "resources"}, {"policy_version", "resources"}, "policy")
    if type(data["policy_version"]) is not int or data["policy_version"] != 1:
        raise PolicyError("Unsupported policy_version; expected integer 1")
    resources, seen_paths = [], set()
    for index, resource in enumerate(_list(data["resources"], "resources", nonempty=True)):
        location = f"resources[{index}]"
        resource = _object(resource, {"path", "checks"}, {"path", "checks"}, location)
        path = resource["path"]
        if not isinstance(path, str) or not posixpath.isabs(path) or "\0" in path:
            raise PolicyError(f"{location}.path: expected an absolute Linux path without NUL")
        try:
            path.encode("utf-8", "surrogateescape")
        except UnicodeError as exc:
            raise PolicyError(f"{location}.path: invalid Linux filename encoding") from exc
        if path in seen_paths:
            raise PolicyError(f"{location}.path: duplicate resource; combine its checks")
        seen_paths.add(path)
        checks, seen_modes = [], set()
        for ci, check in enumerate(_list(resource["checks"], location + ".checks", nonempty=True)):
            cl = f"{location}.checks[{ci}]"
            check = _object(check, {"mode", "accounts", "processes"}, {"mode"}, cl)
            if not isinstance(check["mode"], str) or check["mode"] not in ("r", "w", "x"):
                raise PolicyError(f"{cl}.mode: expected r, w or x")
            if check["mode"] in seen_modes:
                raise PolicyError(f"{cl}: duplicate resource/mode; combine account and process scopes")
            seen_modes.add(check["mode"])
            if not (set(check) & {"accounts", "processes"}):
                raise PolicyError(f"{cl}: declare accounts and/or processes")
            checks.append(PolicyCheck(check["mode"], *(_scope(check[domain], domain, cl + "." + domain)
                                                       if domain in check else None for domain in ("accounts", "processes"))))
        resources.append(ResourcePolicy(path, tuple(checks)))
    return PolicyDocument(tuple(resources))


def load_policy(path: str) -> PolicyDocument:
    try:
        return parse_policy(Path(path).read_text(encoding="utf-8"))
    except (UnicodeError, FileNotFoundError, IsADirectoryError) as exc:
        raise PolicyError(f"Cannot load policy {path!r}: {exc}") from exc


def compare_access(expected: str, actual: str) -> str:
    if actual not in ("permitted", "denied"):
        return "indeterminate"
    if (expected == "allow") == (actual == "permitted"):
        return "match"
    return "missing_access" if expected == "allow" else "unexpected_access"


@dataclass
class DriftResult:
    subject_type: str
    subject: str | int
    expected: str | None
    actual: str
    drift: str
    extra: bool = False
    effective: dict | None = None
    reasons: list[str] = field(default_factory=list)


@dataclass
class ResourceResult:
    path: str
    mode: str
    results: list[DriftResult] = field(default_factory=list)


@dataclass(frozen=True)
class DriftSummary:
    checks: int
    matches: int
    unexpected_access: int
    missing_access: int
    indeterminate: int
    policy_errors: int
    extra_subjects: int


@dataclass
class DriftReport:
    policy_file: str
    resources: list[ResourceResult] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)

    @property
    def summary(self) -> DriftSummary:
        results = [result for resource in self.resources for result in resource.results]
        counts = Counter(result.drift for result in results)
        counts.update(error["drift"] for error in self.errors)
        return DriftSummary(len(results), counts["match"], counts["unexpected_access"], counts["missing_access"],
                            counts["indeterminate"], counts["policy_error"], sum(result.extra for result in results))

    @property
    def code(self) -> int:
        summary = self.summary
        return 2 if summary.policy_errors else 3 if summary.indeterminate else 1 if summary.unexpected_access or summary.missing_access else 0


def _failure(domain, subject, expected, message, code=3, *, extra=False) -> DriftResult:
    return DriftResult(domain, subject, expected, "unknown", "policy_error" if code == 2 else "indeterminate",
                       extra=extra, reasons=[message])


def _account_result(name, expected, diagnosis, version, *, extra=False, error=None) -> DriftResult:
    data = json_output.diagnosis_document(diagnosis, version) if diagnosis else None
    actual = data["verdict"] if data and not error else "unknown"
    drift = "policy_error" if diagnosis and diagnosis.code == 2 else compare_access(expected, actual)
    reasons = ([error] if error else []) + (data["reasons"] if data else [])
    return DriftResult("account", name, expected, actual, drift, extra, data, list(dict.fromkeys(reasons)))


def _process_result(entry, expected, version, *, extra=False) -> DriftResult:
    # Keep audit race/visibility categorization; an unavailable expected PID is
    # never a successful DENY match, even if a plain audit calls it transient.
    document = process_audit.audit_document(process_audit.ProcessAuditResult("", entries=[entry]), version)["processes"][0]
    invalid_path = bool(entry.report and entry.report.code == 2 and entry.report.inspection_kind != "not_visible")
    return DriftResult("process", entry.pid, expected, entry.verdict,
                       "policy_error" if invalid_path else compare_access(expected, entry.verdict),
                       extra, document, document.get("reasons", []))


def _evaluate_domain(resource: ResourceResult, domain: str, scope: SubjectPolicy, engine) -> None:
    declared = {subject: "allow" for subject in scope.allow}
    declared.update((subject, "deny") for subject in scope.deny)
    observed = {}
    if scope.deny_others:
        try:
            if domain == "account":
                audit = engine.audit_target(resource.path, resource.mode)
                observed = {entry.account.username: entry for entry in audit.permitted + audit.denied + audit.errors}
            else:
                audit = process_audit.audit_processes(resource.path, resource.mode, engine=engine)
                observed = {entry.pid: entry for entry in audit.entries}
            if audit.failure:
                resource.results.append(_failure("scope", domain, None, audit.failure, audit.code))
            elif audit.code and not observed:
                resource.results.append(_failure("scope", domain, None, "Subject inventory incomplete", audit.code))
        except (engine.DiagnosticError, OSError) as exc:
            resource.results.append(_failure("scope", domain, None, str(exc), getattr(exc, "code", 3)))
    subjects = [*declared, *sorted(set(observed) - set(declared))]
    for subject in subjects:
        extra = subject not in declared
        expected = declared.get(subject, "deny")
        try:
            if domain == "account":
                if subject in observed:
                    entry = observed[subject]
                    result = _account_result(subject, expected, entry.diagnosis, engine.__version__, extra=extra, error=entry.error)
                else:
                    diagnosis = engine.diagnose(resource.path, engine.resolve_subject(subject), resource.mode)
                    result = _account_result(subject, expected, diagnosis, engine.__version__)
            else:
                entry = observed.get(subject)
                if entry is None:
                    entry = process_audit.classify(engine.diagnose_process(resource.path, subject, resource.mode))
                result = _process_result(entry, expected, engine.__version__, extra=extra)
        except (engine.DiagnosticError, OSError) as exc:
            result = _failure(domain, subject, expected, str(exc), getattr(exc, "code", 3), extra=extra)
        resource.results.append(result)


def evaluate_policy(policy: PolicyDocument, policy_file: str = "<policy>", *, engine=None) -> DriftReport:
    if engine is None:
        import permissionhell as engine
    report = DriftReport(policy_file)
    for resource in policy.resources:
        preflight = None
        try:
            engine.inspect_audit_target(resource.path)
        except (engine.DiagnosticError, OSError) as exc:
            preflight = exc
        for check in resource.checks:
            result = ResourceResult(resource.path, check.mode)
            report.resources.append(result)
            for domain, scope in (("account", check.accounts), ("process", check.processes)):
                if scope is None:
                    continue
                if preflight:
                    for expected, members in (("allow", scope.allow), ("deny", scope.deny)):
                        result.results.extend(_failure(domain, subject, expected, str(preflight), getattr(preflight, "code", 3)) for subject in members)
                    if scope.deny_others:
                        result.results.append(_failure("scope", domain, None, str(preflight), getattr(preflight, "code", 3)))
                else:
                    _evaluate_domain(result, domain, scope, engine)
    return report


def check_policy_file(path: str, *, engine=None) -> DriftReport:
    try:
        policy = load_policy(path)
    except (PolicyError, OSError) as exc:
        return DriftReport(path, errors=[{"drift": "policy_error" if isinstance(exc, PolicyError) else "indeterminate", "message": str(exc)}])
    return evaluate_policy(policy, path, engine=engine)


def decision_details(result: DriftResult) -> dict:
    """Project existing decision fields without computing authorization again."""
    data = result.effective or {}
    inodes = [step for step in data.get("access_path", []) if step.get("kind") == "inode"]
    if data.get("target_inode"):
        inodes.append(data["target_inode"])
    focus = next((step for step in inodes if step.get("blocker")), None) or data.get("target_inode")
    mechanisms = [{"path": step["path"], "stage": step["stage"], "mechanism": step["mechanism"],
                   "permission_class": step["permission_class"], "matched_groups": step["matched_groups"],
                   "acl": step["acl"], "capability": (step.get("capability_override") or {}).get("capability")}
                  for step in inodes]
    blocker = data.get("first_blocker")
    mechanism = "mount" if blocker and blocker["stage"] == "mount" else focus["mechanism"] if focus else None
    if result.actual == "permitted" and any(step["mechanism"] == "capability" for step in mechanisms):
        mechanism = "capability"
    return {"mechanism": mechanism, "blocker": blocker, "mechanisms": mechanisms}


def policy_document(report: DriftReport, version: str) -> dict:
    return {"schema_version": "1", "policy_version": 1, "command": "policy-check",
            "tool": {"name": "permissionhell", "version": version}, "policy_file": report.policy_file,
            "summary": asdict(report.summary), "exit_code": report.code, "errors": list(report.errors),
            "resources": [{"path": resource.path, "mode": resource.mode,
                           "results": [{**asdict(result), **decision_details(result)} for result in resource.results]}
                          for resource in report.resources]}


def _brief(result: DriftResult) -> list[str]:
    if result.actual not in ("permitted", "denied"):
        return list(result.reasons)
    details = decision_details(result)
    lines = []
    for step in details["mechanisms"]:
        if step["stage"] != "target" and step["mechanism"] not in ("capability", "posix_acl"):
            continue
        mechanism = step["capability"] or ("ACL " + step["acl"]["decision_type"].replace("_", " ") if step["acl"] else
                                            "ROOT model" if step["mechanism"] == "root" else step["permission_class"])
        groups = ", ".join(f"{group['membership']} GID {group['gid']} {group['name']!r}" for group in step["matched_groups"])
        lines.append(f"via {mechanism}" + (f" ({groups})" if groups else "") + f" at {step['path']!r}")
    if details["blocker"]:
        blocker = details["blocker"]
        lines.append(f"blocker: {blocker['path']!r} ({blocker['stage']})")
    if result.drift in ("missing_access", "indeterminate", "policy_error"):
        lines.extend(result.reasons)
    return list(dict.fromkeys(lines))


def render_policy(report: DriftReport, version: str, *, verbose=False) -> str:
    label = version[:-2] if version.endswith(".0") else version
    lines = [f"PERMISSION HELL v{label} | POLICY CHECK", f"Policy: {report.policy_file!r}"]
    for error in report.errors:
        lines.extend([error["drift"].upper(), "  " + error["message"]])
    for resource in report.resources:
        operation = {"r": "READ", "w": "WRITE", "x": "EXECUTE/SEARCH"}[resource.mode]
        lines.extend(["", f"{resource.path!r} | {operation}"])
        for status in ("unexpected_access", "missing_access", "indeterminate", "policy_error", "match"):
            matches = [result for result in resource.results if result.drift == status]
            if not matches:
                continue
            lines.append("  " + status.upper())
            extras = [result for result in matches if result.extra and status == "match"] if not verbose else []
            for result in matches:
                if result in extras:
                    continue
                name = f"PID {result.subject}" if result.subject_type == "process" else repr(result.subject)
                if result.subject_type == "process" and result.effective and result.effective.get("name") is not None:
                    name += " " + repr(result.effective["name"])
                lines.append(f"    {result.subject_type}: {name} | expected: {(result.expected or 'scope').upper()} | actual: {result.actual.upper()}")
                lines.extend("      " + reason for reason in _brief(result))
                if verbose and result.effective:
                    lines.append("      Effective observation: " + json.dumps(result.effective, ensure_ascii=True, sort_keys=True))
            if extras:
                sample = ", ".join(str(result.subject) if result.subject_type == "process" else repr(result.subject) for result in extras[:4])
                lines.append(f"    {len(extras)} other subjects match DENY; sample: {sample}. --verbose shows all.")
    summary = report.summary
    lines.extend(["", "SUMMARY", f"  {summary.checks} comparison/scope records; {summary.extra_subjects} extra subjects evaluated",
                  f"  {summary.matches} matches; {summary.unexpected_access} unexpected access; {summary.missing_access} missing access",
                  f"  {summary.indeterminate} indeterminate; {summary.policy_errors} policy errors"])
    return "\n".join(lines)
