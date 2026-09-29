"""Schema 1 JSON projections of collected results; no filesystem or identity I/O.

Human renderers are deliberately not used. Null denotes unavailable/not-applicable
data; an unknown observation is never turned into a permission denial.
"""

from __future__ import annotations

import json
import stat
from idmap import namespace_identity
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from permissionhell import Diagnosis, Inode, Subject, AuditReport, RemediationSuggestion, ProcessDiagnosis
    from process_subject import ProcessSubject


SCHEMA_VERSION = "1"
VERDICTS = {0: "permitted", 1: "denied", 2: "invalid_input", 3: "error"}


def permissions(value: int | None) -> dict | None:
    if value is None:
        return None
    return {"bits": value, "symbolic": "".join(c if value & b else "-" for b, c in ((4, "r"), (2, "w"), (1, "x")))}


def error_data(message: str, code: int, stage: str) -> dict:
    return {"kind": "invalid_input" if code == 2 else "diagnostic_error", "stage": stage, "message": message}


def envelope(version: str, command: str, mode: str, path: str, requested_mode: str) -> dict:
    return {"schema_version": SCHEMA_VERSION, "tool": {"name": "permissionhell", "version": version},
            "command": command, "mode": mode, "requested_mode": requested_mode, "target_path": path}


def subject_data(subject: Subject) -> dict:
    unknown_gid = subject.namespace_identity is not None and not subject.namespace_identity.fsgid.mapped_ok
    return {"username": subject.username, "uid": subject.uid, "primary_gid": None if unknown_gid else subject.primary_gid,
            "primary_group": None if unknown_gid else subject.primary_group,
            "supplementary_groups": [{"gid": gid, "name": name}
                                     for gid, name in zip(subject.supplementary_gids, subject.supplementary_groups)]}


def inode_data(inode: Inode, subject: Subject, stage: str, blocker: bool = False) -> dict:
    decision, match = inode.decision, inode.acl_match
    acl = None
    if inode.acl and inode.acl.extended and match:
        acl = {"decision_type": match.selection.lower().replace(" ", "_"),
               "matched_user_ids": [e.qualifier for e in match.entries if e.tag.name == "USER"],
               "matched_group_ids": [inode.gid if e.tag.name == "GROUP_OBJ" else e.qualifier
                                     for e in match.entries if e.tag.name in ("GROUP_OBJ", "GROUP")],
               "entries": [{"tag": e.tag.name.lower(), "id": e.qualifier,
                            "permissions": permissions(e.permissions)} for e in match.entries],
               "group_union": permissions(match.specified) if match.selection == "GROUP" else None,
               "specified_permissions": permissions(match.specified), "mask": permissions(match.mask),
               "effective_permissions": permissions(match.effective),
               "mask_reduced_requested_rights": bool(match.specified & match.required & ~match.effective),
               "result": "permitted" if match.allowed else "denied"}
    gids = acl["matched_group_ids"] if acl else ([inode.gid] if decision.permission_class == "GROUP" else [])
    names = {subject.primary_gid: subject.primary_group,
             **dict(zip(subject.supplementary_gids, subject.supplementary_groups))}
    groups = [{"gid": gid, "name": names.get(gid),
               "membership": "primary" if gid == subject.primary_gid else "supplementary"} for gid in gids]
    kind = "directory" if stat.S_ISDIR(inode.mode) else "regular_file" if stat.S_ISREG(inode.mode) else "other"
    result = {"kind": "inode", "inode_type": kind, "stage": stage, "path": inode.path,
            "result": "permitted" if decision.allowed else "denied", "blocker": blocker,
            "required_permission": permissions(decision.required),
            "mechanism": "capability" if inode.capability_decision and inode.capability_decision.applied else
                         "root" if subject.uid == 0 and not subject.process_identity else "posix_acl" if acl else "unix_dac",
            "permission_class": decision.permission_class,
            "effective_permissions": permissions(decision.available), "root_override": decision.root_override,
            "root_assumption": "traditional_privileged_uid_0" if subject.uid == 0 and not subject.process_identity else None,
            "owner": {"username": inode.owner, "uid": inode.uid}, "group": {"name": inode.group, "gid": inode.gid},
            "mode": {"bits": stat.S_IMODE(inode.mode), "octal": f"{stat.S_IMODE(inode.mode):04o}",
                     "symbolic": stat.filemode(inode.mode)},
            "matched_groups": groups, "acl": acl, "reason": decision.reason}
    if inode.base_decision:
        capability = inode.capability_decision
        result.update({"base_result": "permitted" if inode.base_decision.allowed else "denied",
                       "base_mechanism": "posix_acl" if acl else "unix_dac",
                       "capability_override": {"capability": capability.capability if capability else None,
                                               "applied": capability.applied if capability else False,
                                               "reason": capability.reason if capability else "Capability scope/result unresolved"}})
        if capability is None:
            result["result"] = "unknown"
    if subject.namespace_identity:
        result["identity_used"] = {"uid": subject.uid, "gid": subject.namespace_identity.fsgid.mapped,
                                   "supplementary_gids": list(subject.supplementary_gids),
                                   "source": "same_user_namespace" if subject.namespace_identity.same_as_debugger else "mapped_foreign_user_namespace",
                                   "local_fsuid": subject.namespace_identity.fsuid.local,
                                   "local_fsgid": subject.namespace_identity.fsgid.local,
                                   "unresolved_groups": subject.uncertain_groups}
    return result


def diagnosis_data(report: Diagnosis) -> dict:
    """Preserve ordered observations and the verdict engine's mount reasons."""
    events, first_blocker, errors = [], None, []
    for event in report.trace.events:
        if hasattr(event, "destination"):
            events.append({"kind": "symlink", "path": event.path, "destination": event.destination})
        else:
            blocking = not event.decision.allowed and first_blocker is None
            step = inode_data(event, report.subject, "traversal", blocking)
            events.append(step)
            if blocking:
                first_blocker = {"stage": "traversal", "path": event.path, "mechanism": step["mechanism"]}
    target = report.trace.target
    target_data = inode_data(target, report.subject, "target", not target.decision.allowed and first_blocker is None) if target else None
    if target_data and target_data["blocker"]:
        first_blocker = {"stage": "target", "path": target.path, "mechanism": target_data["mechanism"]}
    # determine_verdict stores target denial as two reasons, followed by mount
    # restrictions. Use its decision, not another ro/noexec evaluator.
    mount_reasons = (report.reasons[2:] if target and not target.decision.allowed else report.reasons)
    mount_reasons = list(mount_reasons) if report.code == 1 and not report.trace.failure else []
    mount = report.mount
    mount_result = "not_evaluated"
    if report.mount_error:
        mount_result = "unknown"
        errors.append(error_data(report.mount_error, 3, "mount"))
    elif mount and not report.trace.failure:
        mount_result = "denied" if mount_reasons else "permitted"
    mount_blocker = bool(mount_reasons) and first_blocker is None
    if mount_blocker:
        first_blocker = {"stage": "mount", "path": mount.point, "mechanism": "mount"}
    mount_data = {"result": mount_result, "blocker": mount_blocker,
                  "mount_point": mount.point if mount else None, "filesystem": mount.filesystem if mount else None,
                  "options": sorted(mount.options) if mount else [],
                  "super_options": sorted(mount.super_options) if mount else [],
                  "read_only": mount.readonly if mount else None,
                  "noexec": "noexec" in mount.options if mount else None, "reasons": mount_reasons}
    if report.trace.failure and report.trace.code in (2, 3):
        errors.append(error_data(report.trace.failure, report.trace.code, "path"))
        if report.trace.error_kind:
            errors[-1]["reason_code"] = report.trace.error_kind
    if report.code in (2, 3) and not errors:
        errors.extend(error_data(reason, report.code, "diagnosis") for reason in report.reasons)
    result = {"subject": subject_data(report.subject), "resolved_target_path": report.trace.resolved_path,
            "access_path": events, "target_inode": target_data, "mount": mount_data,
            "first_blocker": first_blocker, "verdict": VERDICTS[report.code], "exit_code": int(report.code),
            "reasons": list(report.reasons), "errors": errors}
    if report.trace.partial_inode:
        result["unresolved_inode"] = inode_data(report.trace.partial_inode, report.subject, "inspection")
    return result


def remediation_data(suggestions: list[RemediationSuggestion]) -> list[dict]:
    return [{"category": s.category.lower().replace("-", "_").replace(" ", "_"),
             "title": s.title, "commands": list(s.commands), "effect": s.effect, "caveats": list(s.caveats)}
            for s in suggestions]


def diagnosis_document(report: Diagnosis, version: str, *, explain: bool = False,
                       remediations: list[RemediationSuggestion] | None = None) -> dict:
    result = envelope(version, "audit" if explain else "diagnose", "explain" if explain else "diagnose",
                      report.requested_path, report.mode)
    result.update(diagnosis_data(report))
    if remediations is not None:
        result["remediations"] = remediation_data(remediations)
    return result


def audit_document(report: AuditReport, version: str) -> dict:
    result = envelope(version, "audit", "audit", report.requested_path, report.mode)
    accounts = []
    for account in sorted(report.permitted + report.denied + report.errors,
                          key=lambda item: (item.account.username, item.account.uid)):
        data = diagnosis_data(account.diagnosis) if account.diagnosis else {
            "subject": None, "resolved_target_path": None, "access_path": [], "target_inode": None,
            "mount": None, "first_blocker": None, "verdict": "error", "exit_code": 3, "reasons": [], "errors": []}
        if account.error and not any(e["message"] == account.error for e in data["errors"]):
            data["errors"].append(error_data(account.error, data["exit_code"], "account"))
        focus = next((step for step in data["access_path"] if step.get("blocker")), None) or data["target_inode"]
        data.update({"username": account.account.username, "uid": account.account.uid,
                     "primary_gid": account.account.primary_gid,
                     "mechanism": "mount" if data["first_blocker"] and data["first_blocker"]["stage"] == "mount"
                                  else focus["mechanism"] if focus else None,
                     "effective_permissions": focus["effective_permissions"] if focus else None,
                     "blocker_path": data["first_blocker"]["path"] if data["first_blocker"] else None})
        data["decision"] = ({"stage": focus["stage"], "mechanism": focus["mechanism"],
                             "permission_class": focus["permission_class"],
                             "required_permission": focus["required_permission"],
                             "effective_permissions": focus["effective_permissions"],
                             "root_override": focus["root_override"], "acl": focus["acl"]} if focus else None)
        accounts.append(data)
    result.update({"account_source": "/etc/passwd", "account_scope": "explicit_local_accounts_including_service_accounts",
                   "totals": {"permitted": len(report.permitted), "denied": len(report.denied), "errors": len(report.errors)},
                   "accounts": accounts, "verdict": "complete" if report.code == 0 else "invalid_input" if report.code == 2 else "incomplete",
                   "exit_code": int(report.code),
                   "errors": [error_data(report.failure, report.code, "audit")] if report.failure else []})
    return result


def error_document(version: str, command: str, mode: str, path: str, requested_mode: str,
                   username: str | None, message: str, code: int, stage: str = "request") -> dict:
    result = envelope(version, command, mode, path, requested_mode)
    result.update({"requested_username": username, "subject": None, "verdict": VERDICTS[code],
                   "exit_code": int(code), "errors": [error_data(message, code, stage)]})
    return result


def capabilities_data(sets) -> dict:
    names = ("effective", "permitted", "inheritable", "bounding", "ambient")
    result = {name: list(getattr(sets, name).names) if getattr(sets, name) is not None else None for name in names}
    result["unknown_bits"] = sorted({bit for name in names if getattr(sets, name) is not None
                                     for bit in getattr(sets, name).unknown_bits})
    result["unknown_bits_by_set"] = {name: list(getattr(sets, name).unknown_bits) if getattr(sets, name) is not None else None
                                     for name in names}
    result["hex_masks"] = {name: format(getattr(sets, name).mask, "x") if getattr(sets, name) is not None else None for name in names}
    result["modeled_capabilities"] = ["CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH"]
    return result


def process_subject_data(process: ProcessSubject) -> dict:
    status = process.status
    def credentials(ids, names):
        return {key: {"id": getattr(ids, key), "name": names.get(getattr(ids, key))}
                for key in ("real", "effective", "saved", "filesystem")}
    def namespace(observation):
        return {"identifier": observation.identifier, "debugger_identifier": observation.debugger_identifier,
                "matches_debugger": observation.matches_debugger, "error": observation.error}
    def mappings(entries):
        return [{"inside": e.inside, "outside": e.outside, "length": e.length} for e in entries] if entries is not None else None
    root = process.root
    identity = namespace_identity(process)
    def translated(value):
        entry = value.matched_range
        return {"observed": value.observed, "local": value.local, "mapped": value.mapped, "mapped_ok": value.mapped_ok,
                "direction": value.direction, "reason": value.reason,
                "matched_range": {"inside": entry.inside, "outside": entry.outside, "length": entry.length} if entry else None}
    return {"pid": process.pid, "name": status.name, "start_time_ticks": process.start_time_ticks,
            "credentials": {"uids": credentials(status.uids, process.uid_names),
                            "gids": credentials(status.gids, process.gid_names),
                            "supplementary_groups": [{"gid": g, "name": process.gid_names.get(g)} for g in status.supplementary_gids]},
            "credential_id_namespace": "debugger_user_namespace",
            "user_namespace": {"same_as_debugger": identity.same_as_debugger,
                               "uid_map": mappings(process.uid_map), "gid_map": mappings(process.gid_map),
                               "setgroups": process.setgroups,
                               "outside_column_namespace": ("parent" if identity.same_as_debugger is True else
                                                            "debugger" if identity.same_as_debugger is False else None)},
            "filesystem_identity": {"uid": identity.fsuid.mapped, "gid": identity.fsgid.mapped,
                                    "uid_source": status.uids.source, "gid_source": status.gids.source,
                                    "supplementary_gids": [g.mapped for g in identity.supplementary if g.mapped_ok],
                                    "fsuid": translated(identity.fsuid), "fsgid": translated(identity.fsgid),
                                    "supplementary_groups": [translated(g) for g in identity.supplementary]},
            "namespaces": {"mount": namespace(process.mount_namespace), "user": namespace(process.user_namespace)},
            "root": {"path": root.path, "device": root.device, "inode": root.inode,
                     "debugger_path": root.debugger_path, "debugger_device": root.debugger_device,
                     "debugger_inode": root.debugger_inode, "matches_debugger": root.matches_debugger, "error": root.error},
            "uid_map": mappings(process.uid_map), "gid_map": mappings(process.gid_map),
            "maps_used_for_authorization": identity.same_as_debugger is False, "effective_capabilities": status.effective_capabilities,
            "capabilities": capabilities_data(status.capabilities),
            "capabilities_used_for_authorization": status.capabilities.effective is not None and identity.same_as_debugger is True and not process.limitations,
            "notes": list(process.notes)}


def process_document(report: ProcessDiagnosis, version: str) -> dict:
    result = envelope(version, "process", "process", report.requested_path, report.mode)
    if report.diagnosis:
        result.update(diagnosis_data(report.diagnosis))
    else:
        result.update({"subject": None, "resolved_target_path": None, "access_path": [], "target_inode": None,
                       "mount": None, "first_blocker": None, "reasons": list(report.limitations), "errors": []})
    result.update({"pid": report.pid, "process": process_subject_data(report.process) if report.process else None,
                   "path_context": "debugger_absolute_path_root_and_mount_namespace",
                   "limitations": list(report.limitations),
                   "indeterminate_reason": report.indeterminate_reason,
                   "model_limitations": ["Only effective CAP_DAC_OVERRIDE and CAP_DAC_READ_SEARCH affect r/w/x; LSM policies remain unmodeled.",
                                         "Live UID 0 has no implicit bypass. Non-identity or unknown namespace maps cannot authorize capability bypasses.",
                                         "Foreign user IDs are validated in the debugger's namespace; foreign capability scope is not established.",
                                         "Foreign mount namespaces and roots are not entered or translated.",
                                         "Snapshots are not atomic; no guarantee of actual syscall success.",
                                         "Process remediation is not supported."],
                   "verdict": "indeterminate" if report.code == 3 else VERDICTS[report.code], "exit_code": int(report.code)})
    result["errors"].extend(error_data(message, report.code, "process") for message in report.limitations)
    return result


def render_json(document: dict) -> str:
    # ASCII escapes safely preserve control characters and surrogateescaped Linux
    # filenames without emitting terminal controls or failing stdout encoding.
    return json.dumps(document, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
