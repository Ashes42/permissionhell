"""Visible process inventory and presentation; permission decisions stay in the engine."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field, asdict
import os
from pathlib import Path
from typing import TYPE_CHECKING

import json_output
from process_subject import start_time, ProcessInspectionError

if TYPE_CHECKING:
    from permissionhell import ProcessDiagnosis


@dataclass
class ProcessAuditEntry:
    pid: int
    verdict: str
    report: ProcessDiagnosis | None = None
    reason: str | None = None
    transient: bool = False
    cmdline: tuple[str, ...] | None = None
    cmdline_note: str | None = None
    reason_code: str | None = None

    @property
    def name(self) -> str | None:
        return self.report.process.status.name if self.report and self.report.process else None


@dataclass(frozen=True)
class ProcessAuditSummary:
    discovered: int
    inspected: int
    permitted: int
    denied: int
    indeterminate: int
    unavailable: int
    errors: int


@dataclass
class ProcessAuditResult:
    target: str
    mode: str = "r"
    entries: list[ProcessAuditEntry] = field(default_factory=list)
    discovered: int = 0
    code: int = 0
    failure: str | None = None

    @property
    def summary(self) -> ProcessAuditSummary:
        counts = Counter(entry.verdict for entry in self.entries)
        return ProcessAuditSummary(self.discovered,
                                   sum(entry.report is not None and entry.report.process is not None for entry in self.entries),
                                   counts["permitted"], counts["denied"], counts["indeterminate"],
                                   counts["unavailable"], counts["error"])


def enumerate_pids() -> list[int]:
    """A discovery snapshot, not a claim that all host processes are visible."""
    with os.scandir("/proc") as entries:
        return sorted({int(entry.name) for entry in entries
                       if entry.name.isascii() and entry.name.isdecimal() and 0 < int(entry.name) <= 0x7FFFFFFF})


def classify(report: ProcessDiagnosis) -> ProcessAuditEntry:
    kind = report.inspection_kind
    reason = "; ".join(report.limitations) or (report.diagnosis.trace.failure if report.diagnosis else None)
    if kind in ("exited", "identity_changed"):
        # Do not attach the old snapshot to a potentially reused PID.
        return ProcessAuditEntry(report.pid, "unavailable", reason=reason, transient=True, reason_code=kind)
    if kind == "not_visible":
        # Absence can be hidepid, not an established exit. Do not call this a safe race.
        return ProcessAuditEntry(report.pid, "unavailable", reason=reason, reason_code=kind)
    if kind in ("proc_permission", "inspection_error"):
        return ProcessAuditEntry(report.pid, "error", report, reason, reason_code=kind)
    if report.indeterminate_reason == "path_context_unresolved" and report.process:
        process = report.process
        unknown = [label for label, observation in (("mount namespace", process.mount_namespace),
                   ("user namespace", process.user_namespace), ("root", process.root))
                   if observation.matches_debugger is None]
        if unknown:
            return ProcessAuditEntry(report.pid, "error", report,
                                     "Proc context unavailable: " + ", ".join(unknown) + ". See --verbose/--json for inspection errors.",
                                     reason_code="context_inspection_failed")
    if report.code in (0, 1):
        return ProcessAuditEntry(report.pid, "permitted" if report.code == 0 else "denied", report)
    if report.code == 2:
        return ProcessAuditEntry(report.pid, "error", report, reason)
    uncertain = {"path_context_unresolved", "uid_mapping_unresolved", "group_mapping_unresolved",
                 "capability_scope_unestablished", "capability_unknown", "lsm_policy_unresolved"}
    return ProcessAuditEntry(report.pid, "indeterminate" if report.indeterminate_reason in uncertain else "error", report, reason,
                             reason_code=report.indeterminate_reason)


def collect_cmdline(entry: ProcessAuditEntry) -> None:
    """Optional sensitive metadata, tied to the validated process start time."""
    if not entry.report or not entry.report.process:
        return
    expected = entry.report.process.start_time_ticks
    try:
        if start_time(entry.pid) != expected:
            raise ProcessInspectionError("PID changed before command-line inspection", kind="identity_changed")
        raw = Path(f"/proc/{entry.pid}/cmdline").read_bytes()
        if start_time(entry.pid) != expected:
            raise ProcessInspectionError("PID changed during command-line inspection", kind="identity_changed")
        entry.cmdline = tuple(value.decode("utf-8", "surrogateescape") for value in raw.rstrip(b"\0").split(b"\0")) if raw else ()
    except (FileNotFoundError, ProcessInspectionError) as exc:
        entry.report = None
        entry.reason = str(exc)
        entry.transient = isinstance(exc, FileNotFoundError) or getattr(exc, "kind", None) == "identity_changed"
        entry.verdict = "unavailable" if entry.transient else "error"
        entry.reason_code = "exited" if isinstance(exc, FileNotFoundError) else exc.kind
    except OSError as exc:
        # Optional command-line visibility does not change the access evaluation.
        entry.cmdline_note = str(exc)


def audit_processes(target: str, mode: str = "r", *, pids: list[int] | None = None,
                    include_cmdline: bool = False, engine=None) -> ProcessAuditResult:
    if engine is None:
        import permissionhell as engine
    result = ProcessAuditResult(target, mode)
    try:
        if not os.path.isabs(target):
            raise engine.DiagnosticError("Process audit requires an absolute debugger-visible target path.", engine.ExitCode.INPUT)
        engine.inspect_audit_target(target)
        if pids is not None and any(type(pid) is not int or not 0 < pid <= 0x7FFFFFFF for pid in pids):
            raise engine.DiagnosticError("PID must be a positive Linux process ID", engine.ExitCode.INPUT)
        selected = sorted(set(pids)) if pids is not None else enumerate_pids()
        result.discovered = len(selected)
        if not selected:
            raise engine.DiagnosticError("No visible processes discovered; no processes evaluated.")
    except (engine.DiagnosticError, OSError) as exc:
        result.failure, result.code = str(exc), int(getattr(exc, "code", 3))
        return result
    for pid in selected:
        try:
            report = engine.diagnose_process(target, pid, mode)
            entry = classify(report)
            if report.code == 2 and report.inspection_kind != "not_visible":
                result.code = 2
                result.failure = "Target became unresolved during the audit; partial results are retained."
            if include_cmdline:
                collect_cmdline(entry)
        except (OSError, ProcessInspectionError) as exc:
            entry = ProcessAuditEntry(pid, "error", reason=str(exc))
        result.entries.append(entry)
    if result.code != 2 and any(e.verdict in ("error", "indeterminate") or
                                (e.verdict == "unavailable" and not e.transient) for e in result.entries):
        result.code = 3
    return result


def entry_lines(entry: ProcessAuditEntry, engine) -> list[str]:
    report = entry.report
    if entry.reason:
        return [entry.reason]
    if not report or not report.diagnosis:
        return ["No complete permission observation available."]
    diagnosis = report.diagnosis
    lines = []
    identity = report.namespace_identity
    if identity and identity.same_as_debugger is False:
        lines.append(f"local fsuid {identity.fsuid.local} -> mapped UID {identity.fsuid.mapped}; "
                     f"local fsgid {identity.fsgid.local} -> mapped GID {identity.fsgid.mapped}")
    if entry.verdict == "permitted":
        lines.append(engine.audit_access_reason(diagnosis.trace.target, diagnosis.subject))
        for event in diagnosis.trace.events:
            if isinstance(event, engine.Inode) and (engine.acl_relevant(event) or
                    (event.capability_decision and event.capability_decision.applied)):
                lines.append(f"Search at {event.path!r}: {engine.audit_access_reason(event, diagnosis.subject)}")
    else:
        blocked = next((event for event in diagnosis.trace.events if isinstance(event, engine.Inode)
                        and not event.decision.allowed), None)
        if blocked is None and diagnosis.trace.target and not diagnosis.trace.target.decision.allowed:
            blocked = diagnosis.trace.target
        if blocked:
            lines.append(f"BLOCKED at {blocked.path!r}: {engine.access_summary(blocked, diagnosis.subject)}; "
                         f"missing {engine.OPERATIONS[diagnosis.mode][1] if blocked is diagnosis.trace.target else 'EXECUTE/SEARCH'}.")
            if engine.acl_relevant(blocked):
                lines.append(engine.acl_explanation(blocked))
            if blocked is diagnosis.trace.target:
                lines.extend(diagnosis.reasons[2:])  # Subsequent mount restrictions from the verdict engine.
        else:
            lines.extend(engine.concise_reasons(diagnosis))
    if report.lsm:
        import lsm
        lines.extend(lsm.summary_lines(report.lsm))
        if report.lsm_result:
            lines.extend(report.lsm_result.reasons)
    return list(dict.fromkeys(lines))


def grouping_key(entry: ProcessAuditEntry, engine):
    """Group ordinary OTHER paths or equivalent context inspection failures."""
    visibility_failure = (entry.verdict == "error" and entry.report and entry.report.process and
                          entry.report.indeterminate_reason == "path_context_unresolved")
    if visibility_failure:
        return observation_key(entry, engine)
    if entry.verdict not in ("permitted", "denied") or not entry.report or not entry.report.diagnosis:
        return None
    diagnosis = entry.report.diagnosis
    inodes = [e for e in diagnosis.trace.events if isinstance(e, engine.Inode)]
    if diagnosis.trace.target:
        inodes.append(diagnosis.trace.target)
    if not inodes or diagnosis.mount_error or diagnosis.trace.target is None:
        return None
    if any(i.decision.permission_class != "OTHER" or engine.acl_relevant(i) or
           (i.capability_decision and i.capability_decision.applied) for i in inodes):
        return None
    if entry.verdict == "denied" and diagnosis.trace.target.decision.allowed:
        return None  # Keep mount blockers individual.
    process = entry.report.process
    if not process or diagnosis.subject.uid == 0:
        return None
    # Full decision projection prevents equal short labels from hiding different
    # paths, ACL inspections, mappings, capability contexts or mount restrictions.
    return observation_key(entry, engine)


def observation_key(entry: ProcessAuditEntry, engine) -> str:
    data = json_output.process_document(entry.report, engine.__version__)
    data.pop("pid", None)
    process_data = data.pop("process")
    for key in ("pid", "name", "start_time_ticks"):
        process_data.pop(key, None)
    data["process_context"] = process_data
    return json_output.render_json(data).replace(f"/proc/{entry.pid}/", "/proc/<PID>/")


def render_audit(result: ProcessAuditResult, *, verbose: bool = False, engine=None) -> str:
    if engine is None:
        import permissionhell as engine
    lines = [f"PERMISSION HELL {engine.display_version()} | PROCESS AUDIT",
             f"Target: {result.target!r}", f"Requested: {engine.OPERATIONS[result.mode][1]}", "", "SUMMARY"]
    summary = result.summary
    lines.extend([f"  {summary.discovered} discovered/selected; {summary.inspected} snapshots inspected",
                  f"  {summary.permitted} permitted; {summary.denied} denied; {summary.indeterminate} indeterminate; "
                  f"{summary.unavailable} unavailable; {summary.errors} errors"])
    if result.failure:
        lines.append("  " + result.failure)
    for verdict in ("permitted", "indeterminate", "error", "unavailable", "denied"):
        members = [e for e in result.entries if e.verdict == verdict]
        if not members:
            continue
        lines.extend(["", verdict.upper()])
        groups = {}
        for index, entry in enumerate(members):
            key = None if verbose else grouping_key(entry, engine)
            groups.setdefault(key if key is not None else (index,), []).append(entry)
        for group in groups.values():
            entry = group[0]
            if len(group) > 1:
                lines.append(f"  {len(group)} processes with the same result")
                lines.append("    PIDs: " + ", ".join(f"{e.pid} {e.name!r}" for e in group[:5]) +
                             (f", ... +{len(group) - 5} more (--verbose shows all)" if len(group) > 5 else ""))
            else:
                lines.append(f"  PID {entry.pid} {entry.name!r}" + (" (transient)" if entry.transient else ""))
            lines.extend("    " + line for line in entry_lines(entry, engine))
            if verbose:
                if entry.cmdline is not None:
                    lines.append("    Command line (may contain secrets): " + repr(entry.cmdline))
                if entry.cmdline_note:
                    lines.append("    Command line unavailable: " + repr(entry.cmdline_note))
                if entry.report:
                    lines.extend("    " + line for line in engine.render_process_report(entry.report, verbose=True).splitlines())
    lines.extend(["", "Sequential procfs snapshot; hidden processes are not enumerated. Use process --pid PID for a deep dive."])
    return "\n".join(lines)


def audit_document(result: ProcessAuditResult, version: str) -> dict:
    document = json_output.envelope(version, "audit-processes", "audit-processes", result.target, result.mode)
    entries = []
    for entry in result.entries:
        data = json_output.process_document(entry.report, version) if entry.report else {
            "pid": entry.pid, "process": None, "subject": None, "access_path": [], "mount": None, "reasons": []}
        data.update({"name": entry.name, "verdict": entry.verdict, "transient": entry.transient,
                     "reason_code": entry.reason_code})
        if entry.reason:
            data["reasons"] = [entry.reason]
        if entry.cmdline is not None or entry.cmdline_note:
            data.update({"cmdline": list(entry.cmdline) if entry.cmdline is not None else None,
                         "cmdline_note": entry.cmdline_note})
        entries.append(data)
    document.update({"summary": asdict(result.summary), "processes": entries,
                     "exit_code": int(result.code), "verdict": "complete" if result.code == 0 else
                     "invalid_input" if result.code == 2 else "incomplete",
                     "errors": [result.failure] if result.failure else []})
    return document
