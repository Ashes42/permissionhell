"""Pure graph projections of collected diagnoses. No filesystem I/O or permission evaluation."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json

import json_output


GRAPH_VERSION = "1"
STATUSES = {"pass", "fail", "override", "neutral", "indeterminate", "unavailable", "error"}
RESULT_STATUS = {"permitted": "pass", "denied": "fail", "indeterminate": "indeterminate",
                 "unknown": "indeterminate", "error": "error", "invalid_input": "error",
                 "not_evaluated": "neutral", "unavailable": "unavailable"}


@dataclass(frozen=True)
class GraphNode:
    id: str
    type: str
    label: str
    status: str = "neutral"
    metadata: dict = field(default_factory=dict)


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    type: str


@dataclass
class AccessGraph:
    result: str
    exit_code: int
    target: str
    requested_mode: str
    tool_version: str
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    spine: list[str] = field(default_factory=list)

    def add_node(self, node: GraphNode) -> None:
        if node.status not in STATUSES:
            raise ValueError(f"Invalid graph status: {node.status}")
        if any(existing.id == node.id for existing in self.nodes):
            raise ValueError(f"Duplicate graph node ID: {node.id}")
        self.nodes.append(node)

    def add_edge(self, source: str, target: str, kind: str) -> None:
        ids = {node.id for node in self.nodes}
        if source not in ids or target not in ids:
            raise ValueError("Graph edge endpoints must exist")
        edge = GraphEdge(source, target, kind)
        if edge not in self.edges:
            self.edges.append(edge)

    def append(self, node: GraphNode, edge_type: str = "results_in") -> str:
        self.add_node(node)
        if self.spine:
            self.add_edge(self.spine[-1], node.id, edge_type)
        self.spine.append(node.id)
        return node.id


def build_account_graph(report, version: str) -> AccessGraph:
    data = json_output.diagnosis_document(report, version)
    _observed_acls(data, report)
    return build_graph(data)


def build_process_graph(report, version: str) -> AccessGraph:
    data = json_output.process_document(report, version)
    if report.diagnosis:
        _observed_acls(data, report.diagnosis)
    return build_graph(data)


def _observed_acls(data: dict, diagnosis) -> None:
    """Retain already collected unmatched ACL entries for full graph inspection."""
    pairs = list(zip(data["access_path"], diagnosis.trace.events))
    pairs.extend(((data.get("target_inode"), diagnosis.trace.target),
                  (data.get("unresolved_inode"), diagnosis.trace.partial_inode)))
    for step, inode in pairs:
        if step and inode and step["kind"] == "inode":
            step["acl_inspection_note"] = inode.acl_note
            step["observed_acl_entries"] = ([{"tag": entry.tag.name.lower(), "id": entry.qualifier,
                                              "permissions": json_output.permissions(entry.permissions)} for entry in inode.acl.entries]
                                            if inode.acl else None)


def build_graph(data: dict) -> AccessGraph:
    """Consume the existing structured schema, never human renderer output."""
    graph = AccessGraph(data["verdict"], data["exit_code"], data["target_path"],
                        data["requested_mode"], data["tool"]["version"])
    process, subject = data.get("process"), data.get("subject")
    if "pid" in data:
        graph.append(GraphNode(f"process:{data['pid']}", "process",
                               f"PID {data['pid']} {process['name']!r}" if process else f"PID {data['pid']} (not inspected)",
                               "neutral" if process else "unavailable", process or {}))
    else:
        username = subject["username"] if subject else data.get("requested_username")
        graph.append(GraphNode("subject:user", "user", f"User {username!r}", metadata=subject or {}))
    identity_id = None
    if process:
        namespace = process["user_namespace"]
        same = namespace["same_as_debugger"]
        graph.append(GraphNode("namespace:user", "namespace",
                               "Same user namespace; IDs interpreted directly" if same is True else
                               "Foreign user namespace; debugger-visible mappings" if same is False else "User namespace unknown",
                               "neutral" if same is not None else "indeterminate", namespace))
        identity = process["filesystem_identity"]
        if same is False:
            graph.append(GraphNode("identity:local", "filesystem_identity",
                                   f"Local fsuid {identity['fsuid']['local']}, fsgid {identity['fsgid']['local']}",
                                   metadata=identity), "maps_to")
        identity_id = graph.append(GraphNode("identity:filesystem", "filesystem_identity",
                                  f"{'Mapped ' if same is False else ''}fsuid {identity['uid'] if identity['uid'] is not None else 'unmapped'}, "
                                  f"fsgid {identity['gid'] if identity['gid'] is not None else 'unmapped'} (debugger view)",
                                  "neutral" if identity["uid"] is not None else "indeterminate", identity), "maps_to")
        for name, metadata in (("capabilities", process["capabilities"]), ("namespaces", process["namespaces"]),
                               ("root", process["root"]), ("credentials", process["credentials"])):
            node_id = f"context:{name}"
            graph.add_node(GraphNode(node_id, "context", name, metadata={"detail": True, "data": metadata}))
            graph.add_edge(identity_id, node_id, "constrained_by" if name in ("namespaces", "root") else "has_context")
    elif subject:
        identity_id = graph.append(GraphNode("identity:filesystem", "filesystem_identity",
                                             f"UID {subject['uid']}, primary GID {subject['primary_gid']}", metadata=subject), "maps_to")
    if subject and identity_id:
        for index, group in enumerate(subject["supplementary_groups"]):
            node_id = f"identity:group:{index}"
            graph.add_node(GraphNode(node_id, "supplementary_group", f"Supplementary GID {group['gid']} {group['name']!r}",
                                     metadata={"detail": True, **group}))
            graph.add_edge(identity_id, node_id, "member_of")

    steps = list(data.get("access_path", []))
    if data.get("target_inode"):
        steps.append(data["target_inode"])
    if data.get("unresolved_inode"):
        steps.append(data["unresolved_inode"])
    for index, step in enumerate(steps):
        prefix = f"step:{index}"
        if step["kind"] == "symlink":
            graph.append(GraphNode(prefix + ":link", "symlink", f"{step['path']!r} -> {step['destination']!r}",
                                   metadata=step), "resolves_to")
            continue
        _inode(graph, step, prefix, identity_id)

    mount = data.get("mount")
    if mount and mount["result"] != "not_evaluated":
        options = "unknown" if mount["read_only"] is None else "ro" if mount["read_only"] else "rw"
        if mount["noexec"]:
            options += ", noexec"
        graph.append(GraphNode("mount:target", "mount", f"Mount {mount['mount_point']!r}: {options}",
                               RESULT_STATUS[mount["result"]], mount), "constrained_by")
    if data.get("errors") or data.get("limitations"):
        status = "indeterminate" if graph.result == "indeterminate" else "error"
        reasons = data.get("limitations") or [error["message"] for error in data["errors"]]
        graph.append(GraphNode("inspection:incomplete", "blocker", "; ".join(reasons), status,
                               {"errors": data.get("errors", []), "reason_code": data.get("indeterminate_reason"),
                                "blocker": graph.result in ("indeterminate", "error", "invalid_input")}))
    operation = {"r": "READ", "w": "WRITE", "x": "EXECUTE/SEARCH"}[graph.requested_mode]
    graph.append(GraphNode("decision:final", "decision", f"{operation} {graph.result.upper()}",
                           RESULT_STATUS[graph.result], {"reasons": data.get("reasons", []), "exit_code": graph.exit_code}))
    return graph


def _inode(graph: AccessGraph, step: dict, prefix: str, identity_id: str | None) -> None:
    acl = step["acl"]
    capability = step.get("capability_override")
    base_result = step.get("base_result", step["result"])
    overridden = bool(capability and capability["applied"])
    root = bool(step["root_assumption"])
    # Collapse only ordinary OTHER search passes, never ACL/root/capability paths.
    collapse = (step["stage"] == "traversal" and step["result"] == "permitted" and not acl and
                not overridden and not root and step["permission_class"] == "OTHER")
    presentation = {"step": prefix, "path": step["path"], "collapse_safe": collapse,
                    "collapse_signature": [step["permission_class"], step["effective_permissions"]["bits"]]}
    kind = "directory" if (step["stage"] == "traversal" or
                           step["stage"] == "inspection" and step["inode_type"] == "directory") else "target"
    graph.append(GraphNode(prefix + ":path", kind,
                          f"{step['path']!r} ({'search' if kind == 'directory' else 'target'})",
                          "neutral", {**step, **presentation, "blocker": False}), "traverses" if kind == "directory" else "resolves_to")
    if kind == "target":
        graph.append(GraphNode(prefix + ":owner", "ownership",
                               f"Owner UID {step['owner']['uid']}; GID {step['group']['gid']}; mode {step['mode']['octal']}",
                               metadata={**presentation, "owner": step["owner"], "group": step["group"], "mode": step["mode"]}))
    selected = step["permission_class"]
    if step["matched_groups"]:
        groups = step["matched_groups"]
        group_id = graph.append(GraphNode(prefix + ":groups", "group",
                              "Matched " + ", ".join(f"{g['membership']} GID {g['gid']} {g['name']!r}" for g in groups),
                              metadata={**presentation, "groups": groups}), "member_of")
        if identity_id:
            graph.add_edge(identity_id, group_id, "member_of")
    if acl:
        entries = ", ".join(f"{entry['tag']}:{entry['id'] if entry['id'] is not None else ''}:{entry['permissions']['symbolic']}"
                            for entry in acl["entries"])
        selected_id = graph.append(GraphNode(prefix + ":acl", "acl", f"ACL {acl['decision_type'].replace('_', ' ').upper()}: {entries}",
                                             metadata={**presentation, **acl}), "selects")
        if identity_id:
            graph.add_edge(identity_id, selected_id, "selects")
        if acl["group_union"] is not None:
            graph.append(GraphNode(prefix + ":union", "acl", f"Matched group union: {acl['group_union']['symbolic']}",
                                   metadata={**presentation, "permissions": acl["group_union"]}))
        if acl["mask"] is not None:
            graph.append(GraphNode(prefix + ":mask", "acl", f"ACL mask: {acl['mask']['symbolic']}" +
                                   (" (removes requested permission)" if acl["mask_reduced_requested_rights"] else ""),
                                   metadata={**presentation, "mask": acl["mask"],
                                             "reduced_requested_rights": acl["mask_reduced_requested_rights"]}), "constrained_by")
        label = f"Effective ACL {acl['effective_permissions']['symbolic']}: {base_result.upper()}"
    elif root:
        label = "ROOT: traditional privileged UID 0; non-directory execute requires an execute bit"
    else:
        comparison = "UID matches owner" if selected == "OWNER" else "matching owning GID" if selected == "GROUP" else "no owner or group match"
        label = f"{comparison} -> {selected} {step['effective_permissions']['symbolic']}: {base_result.upper()}"
    base_id = graph.append(GraphNode(prefix + ":base", "decision", label,
                           "override" if root and step["root_override"] else RESULT_STATUS[base_result],
                           {**presentation, "blocker": step["blocker"] and not overridden,
                            "required_permission": step["required_permission"], "reason": step["reason"],
                            "base_result": base_result, "root_assumption": step["root_assumption"]}),
                           "grants" if base_result == "permitted" else "denies")
    if identity_id and not acl and not step["matched_groups"]:
        graph.add_edge(identity_id, base_id, "selects")
    if overridden:
        graph.append(GraphNode(prefix + ":capability", "capability", capability["capability"] + " overrides base denial",
                               "override", {**presentation, **capability}), "overrides")
        graph.append(GraphNode(prefix + ":effective", "decision", "Effective access PERMITTED", "pass", presentation), "grants")
    elif step["result"] == "unknown":
        graph.append(GraphNode(prefix + ":capability", "capability", "Capability scope/result unresolved",
                               "indeterminate", {**presentation, **(capability or {})}), "constrained_by")


def graph_document(graph: AccessGraph) -> dict:
    return {"schema_version": "1", "graph_version": GRAPH_VERSION, "command": "graph",
            "tool": {"name": "permissionhell", "version": graph.tool_version},
            "target_path": graph.target, "requested_mode": graph.requested_mode,
            "result": graph.result, "exit_code": graph.exit_code,
            "nodes": [asdict(node) for node in graph.nodes],
            "edges": [{"from": edge.source, "to": edge.target, "type": edge.type} for edge in graph.edges],
            "spine": list(graph.spine)}


def serialize_graph_json(graph: AccessGraph) -> str:
    return json_output.render_json(graph_document(graph))


def _safe_label(value: str) -> str:
    """Keep labels single-line and inert even with hostile Linux names."""
    return "".join(char if char.isprintable() else char.encode("unicode_escape").decode("ascii") for char in value)


def render_terminal_graph(graph: AccessGraph, verbose: bool = False) -> str:
    version = graph.tool_version[:-2] if graph.tool_version.endswith(".0") else graph.tool_version
    lines = [f"PERMISSION HELL v{version} | ACCESS GRAPH", f"Target: {graph.target!r}", ""]
    lookup = {node.id: node for node in graph.nodes}
    nodes = [lookup[key] for key in graph.spine]
    index = 0
    while index < len(nodes):
        node = nodes[index]
        if not verbose and node.metadata.get("collapse_safe"):
            signature, paths = node.metadata["collapse_signature"], []
            while index < len(nodes) and nodes[index].metadata.get("collapse_safe") and nodes[index].metadata["collapse_signature"] == signature:
                if nodes[index].type == "directory":
                    paths.append(nodes[index].metadata["path"])
                index += 1
            lines.append("[PASS] Traversal: " + " -> ".join(repr(path) for path in paths) + f" ({len(paths)} search components)")
        else:
            marker = " <-- BLOCKER" if node.metadata.get("blocker") else ""
            lines.append(f"[{node.status.upper()}] {_safe_label(node.label)}{marker}")
            if verbose:
                lines.append("    details: " + json.dumps(node.metadata, ensure_ascii=True, sort_keys=True))
                for edge in graph.edges:
                    child = lookup[edge.target]
                    if edge.source == node.id and child.id not in graph.spine:
                        lines.append(f"    +-- {edge.type}: {_safe_label(child.label)}")
                        lines.append("        " + json.dumps(child.metadata, ensure_ascii=True, sort_keys=True))
            index += 1
        if index < len(nodes):
            lines.append("  |\n  v")
    return "\n".join(lines)


def _dot_string(value: str) -> str:
    # DOT's quoted strings accept escaped quotes/backslashes; render controls as
    # visible escape text, not JSON-only \u escapes or literal terminal controls.
    return '"' + _safe_label(value).replace('\\', '\\\\').replace('"', '\\"') + '"'


def serialize_graph_dot(graph: AccessGraph) -> str:
    lines = ["digraph permissionhell {", "  rankdir=TB;"]
    for node in graph.nodes:
        label = f"[{node.status.upper()}] {node.label}" + (" <-- BLOCKER" if node.metadata.get("blocker") else "")
        lines.append(f"  {_dot_string(node.id)} [label={_dot_string(label)}, shape=box];")
    for edge in graph.edges:
        lines.append(f"  {_dot_string(edge.source)} -> {_dot_string(edge.target)} [label={_dot_string(edge.type)}];")
    lines.append("}")
    return "\n".join(lines) + "\n"
