"""One-shot monitoring orchestration. Authorization and comparison live in snapshots."""
from dataclasses import dataclass, field, replace
import os

import access_snapshot as snapshots


@dataclass
class MonitorResult:
    baseline_path: str
    comparison: snapshots.SnapshotDiff
    baseline_updated: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def code(self):
        return 3 if self.errors else self.comparison.code


def validate_paths(target: str, baseline: str):
    if not baseline or "\0" in baseline:
        raise snapshots.SnapshotError("Baseline must name a file")
    if not target.startswith("/") or "\0" in target:
        raise snapshots.SnapshotError("Monitoring requires an absolute Linux target")
    if os.path.realpath(target) == os.path.realpath(baseline):
        raise snapshots.SnapshotError("Baseline must not replace or alias the analyzed target")
    try:
        if os.path.samefile(target, baseline):
            raise snapshots.SnapshotError("Baseline aliases the analyzed target")
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise snapshots.SnapshotError(f"Cannot verify baseline path safety: {exc}", 3) from exc


def initialize(target, baseline, mode="r", *, processes=False, force=False, engine=None):
    validate_paths(target, baseline)
    if os.path.lexists(baseline) and not force:
        raise snapshots.SnapshotError("Baseline already exists; use --force to replace it")
    current = snapshots.capture_snapshot(target, mode, processes=processes, engine=engine)
    # Never establish an uncertain observation as a trusted monitor baseline.
    if current.code == 0:
        snapshots.write_snapshot(current, baseline, force=force)
    return current


def check(target, baseline, *, mode=None, processes=None, engine=None):
    validate_paths(target, baseline)
    before = snapshots.load_snapshot(baseline)
    if target != before.target:
        raise snapshots.SnapshotError("Baseline target does not match requested target")
    if mode is not None and mode != before.requested_mode:
        raise snapshots.SnapshotError("Baseline mode does not match requested mode")
    if processes is not None and processes != (before.scope == "processes"):
        raise snapshots.SnapshotError("Baseline scope does not match requested scope")
    try:
        current = snapshots.capture_snapshot(target, before.requested_mode,
                                             processes=before.scope == "processes", engine=engine)
    except snapshots.SnapshotError as exc:
        raise snapshots.SnapshotError(f"Current capture unavailable: {exc}", 3) from exc
    return MonitorResult(baseline, snapshots.diff_snapshots(before, current))


def update_baseline(result):
    """Call after reporting the comparison. Incomplete results are never accepted."""
    if result.code not in (0, 1):
        return
    try:
        validate_paths(result.comparison.after.target, result.baseline_path)
        snapshots.write_snapshot(result.comparison.after, result.baseline_path, force=True)
        result.baseline_updated = True
    except snapshots.SnapshotError as exc:
        result.errors.append(str(exc))


def document(result, version):
    data = snapshots.diff_document(result.comparison, version)
    data.update(command="monitor-check", baseline={"path": result.baseline_path, **data.pop("before")},
                current=data.pop("after"), baseline_updated=result.baseline_updated,
                exit_code=result.code, errors=list(result.errors))
    return data


def init_document(current, baseline, version):
    return {"schema_version": "1", "command": "monitor-init", "tool_version": version,
            "baseline": {"path": baseline, "captured_at": current.captured_at},
            "baseline_created": current.code == 0, "exit_code": current.code,
            "snapshot": snapshots.snapshot_document(current)}


def render_init(current, baseline):
    text = snapshots.render_capture(current, baseline).replace("| SNAPSHOT", "| MONITOR BASELINE", 1)
    return text.replace("\nOutput:", "\nBaseline:").replace("INCOMPLETE (partial snapshot saved)", "INCOMPLETE (baseline not written)")


def render_check(result, version, *, verbose=False, ignore_process_churn=False):
    diff = result.comparison
    priority = {"gained_access": 0, "lost_access": 1, "became_indeterminate": 2}
    def rank(change):
        return priority.get(change.change, 3 if change.mechanism_changed or change.context_changes else
                            6 if change.change in ("subject_added", "subject_removed") else 4)
    changes = sorted(diff.changes, key=rank)
    hidden = 0
    if ignore_process_churn and diff.before.scope == "processes" and not verbose:
        hidden = sum(c.change in ("subject_added", "subject_removed") for c in changes)
        changes = [c for c in changes if c.change not in ("subject_added", "subject_removed")]
    # Reuse the established before/after reasoning renderer; filtering is display only.
    churn = [c for c in changes if c.change in ("subject_added", "subject_removed")]
    primary = [c for c in changes if c.change not in ("subject_added", "subject_removed")]
    text = snapshots.render_diff(replace(diff, changes=primary), version, verbose=verbose)
    text = text.split("\nSUMMARY\n", 1)[0].replace("| SNAPSHOT DIFF", "| ACCESS MONITOR", 1)
    if churn:
        tail = snapshots.render_diff(replace(diff, changes=churn, target_changes={}, warnings=[]), version, verbose=verbose)
        text += "\n" + "\n".join(tail.split("\nSUMMARY\n", 1)[0].splitlines()[3:])
    lines = [text, "", f"Baseline: {diff.before.captured_at} ({result.baseline_path!r})",
             f"Current:  {diff.after.captured_at}"]
    if diff.code == 0:
        lines.append("No meaningful access changes since baseline.")
    else:
        lines.append("INCOMPLETE COMPARISON" if diff.code == 3 else "CHANGES DETECTED")
    if hidden:
        lines.append(f"{hidden} process additions/removals hidden; counts, JSON and exit code include churn.")
    lines.extend(["SUMMARY", "  " + "; ".join(f"{count} {name}" for name, count in diff.summary.items() if count),
                  "Baseline updated." if result.baseline_updated else "Baseline unchanged."])
    lines.extend("Error: " + error for error in result.errors)
    return "\n".join(lines)
