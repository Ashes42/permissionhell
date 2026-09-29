"""Graph projections preserve engine decisions without fresh inspection or evaluation."""
import contextlib
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import access_graph as ag
import permissionhell as ph
import process_subject as ps
import json_output as jo
from test_permissionhell import SUBJECT, ROOT
from test_audit_rendering import account_result
from test_capabilities import evaluate, process_with
from test_idmap import evaluate as mapped_evaluate, foreign
from test_posix_acl import make_acl


def account(subject=SUBJECT, **kwargs):
    return ag.build_account_graph(account_result(subject, **kwargs).diagnosis, ph.__version__)


def process(**kwargs):
    return ag.build_process_graph(evaluate(**kwargs), ph.__version__)


def labels(graph):
    return "\n".join(node.label for node in graph.nodes)


class ModelTests(unittest.TestCase):
    def test_node_creation(self):
        node = ag.GraphNode("test", "subject", "alice")
        self.assertEqual(node.status, "neutral")
        self.assertEqual(node.metadata, {})

    def test_edge_creation(self):
        graph = ag.AccessGraph("permitted", 0, "/file", "r", "1.1.0")
        graph.add_node(ag.GraphNode("a", "user", "alice"))
        graph.add_node(ag.GraphNode("b", "decision", "permitted", "pass"))
        graph.add_edge("a", "b", "grants")
        self.assertEqual(graph.edges, [ag.GraphEdge("a", "b", "grants")])

    def test_duplicate_id_rejected(self):
        graph = account()
        with self.assertRaises(ValueError):
            graph.add_node(graph.nodes[0])

    def test_missing_endpoint_rejected(self):
        graph = account()
        with self.assertRaises(ValueError):
            graph.add_edge("missing", "decision:final", "grants")

    def test_bad_status_rejected(self):
        with self.assertRaises(ValueError):
            account().add_node(ag.GraphNode("bad", "target", "bad", "maybe"))

    def test_unique_ids_and_all_endpoints_exist(self):
        graph = process(mask=2)
        ids = [node.id for node in graph.nodes]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(edge.source in ids and edge.target in ids for edge in graph.edges))

    def test_deterministic_ordering_and_serialization(self):
        diagnosis = account_result(SUBJECT).diagnosis
        first = ag.build_account_graph(diagnosis, ph.__version__)
        second = ag.build_account_graph(diagnosis, ph.__version__)
        self.assertEqual(ag.serialize_graph_json(first), ag.serialize_graph_json(second))
        self.assertEqual(ag.serialize_graph_dot(first), ag.serialize_graph_dot(second))

    def test_graph_construction_has_no_io_or_permission_evaluation(self):
        diagnosis = account_result(SUBJECT).diagnosis
        with patch("builtins.open", side_effect=AssertionError("I/O")), \
                patch.object(ph, "evaluate_permission", side_effect=AssertionError("reevaluation")), \
                patch.object(ph, "render_report", side_effect=AssertionError("human scraping")):
            self.assertEqual(ag.build_account_graph(diagnosis, ph.__version__).result, "permitted")

    def test_repeated_path_visits_unique(self):
        diagnosis = account_result(SUBJECT).diagnosis
        diagnosis.trace.events.append(diagnosis.trace.events[0])
        graph = ag.build_account_graph(diagnosis, ph.__version__)
        directories = [node for node in graph.nodes if node.type == "directory"]
        self.assertEqual(len(directories), 3)
        self.assertEqual(len({node.id for node in directories}), 3)


class DACTests(unittest.TestCase):
    def test_owner_permit(self):
        graph = account(replace(SUBJECT, uid=9000))
        self.assertIn("UID matches owner -> OWNER", labels(graph))
        self.assertEqual(graph.result, "permitted")

    def test_owner_denial_no_fallback(self):
        graph = account(replace(SUBJECT, uid=9000), target_mode=0o044)
        self.assertIn("OWNER ---: DENIED", labels(graph))
        self.assertEqual(graph.result, "denied")

    def test_primary_group_path(self):
        graph = account(replace(SUBJECT, primary_gid=500), target_mode=0o640)
        self.assertIn("primary GID 500", labels(graph))
        self.assertIn("GROUP r--: PERMITTED", labels(graph))
        self.assertTrue(any(edge.type == "member_of" for edge in graph.edges))

    def test_supplementary_group_path(self):
        graph = account(replace(SUBJECT, supplementary_gids=(500,), supplementary_groups=("media",)), target_mode=0o640)
        self.assertIn("supplementary GID 500", labels(graph))
        self.assertEqual(graph.result, "permitted")

    def test_other_permit(self):
        self.assertIn("OTHER r--: PERMITTED", labels(account()))

    def test_other_denial(self):
        graph = account(target_mode=0o600)
        self.assertIn("OTHER ---: DENIED", labels(graph))
        self.assertEqual(graph.exit_code, 1)

    def test_root_assumption_explicit(self):
        graph = account(ROOT, target_mode=0)
        self.assertTrue(any(node.status == "override" and "ROOT" in node.label for node in graph.nodes))
        self.assertEqual(graph.result, "permitted")

    def test_root_execute_denied_without_execute_bits(self):
        graph = account(ROOT, target_mode=0, mode="x")
        self.assertEqual(graph.result, "denied")
        self.assertIn("execute requires an execute bit", labels(graph))


class ACLTests(unittest.TestCase):
    def test_named_user_chain(self):
        graph = account(acl=make_acl(users=((1001, 6),), mask=4))
        text = labels(graph)
        self.assertIn("user:1001:rw-", text)
        self.assertIn("ACL mask: r--", text)
        self.assertIn("Effective ACL r--: PERMITTED", text)

    def test_acl_mask_denial(self):
        graph = account(mode="w", acl=make_acl(users=((1001, 6),), mask=4))
        self.assertIn("removes requested permission", labels(graph))
        self.assertIn("Effective ACL r--: DENIED", labels(graph))
        self.assertTrue(any(node.metadata.get("blocker") for node in graph.nodes))

    def test_named_group(self):
        graph = account(acl=make_acl(groups=((200, 4),), mask=4))
        self.assertIn("group:200:r--", labels(graph))
        self.assertIn("supplementary GID 200", labels(graph))

    def test_group_union_before_mask(self):
        graph = process(acl=make_acl(groups=((700, 4), (800, 2)), mask=4))
        text = labels(graph)
        self.assertIn("Matched group union: rw-", text)
        self.assertLess(text.index("Matched group union"), text.index("ACL mask"))
        self.assertEqual(graph.result, "permitted")

    def test_full_acl_includes_unmatched_observations(self):
        graph = account(acl=make_acl(users=((1001, 4), (3333, 6)), mask=4))
        target = next(node for node in graph.nodes if node.type == "target")
        self.assertIn(3333, [entry["id"] for entry in target.metadata["observed_acl_entries"]])
        self.assertNotIn("user:3333", ag.render_terminal_graph(graph))
        self.assertIn("3333", ag.render_terminal_graph(graph, verbose=True))


class TraversalTests(unittest.TestCase):
    def test_all_pass_order(self):
        graph = account()
        self.assertEqual([node.metadata["path"] for node in graph.nodes if node.type == "directory"], ["/", "/data"])

    def test_directory_blocker(self):
        graph = account(parent_mode=0)
        text = ag.render_terminal_graph(graph)
        self.assertIn("BLOCKER", text)
        self.assertEqual(graph.result, "denied")
        blockers = [node for node in graph.nodes if node.metadata.get("blocker")]
        self.assertEqual(len(blockers), 1)
        self.assertEqual(blockers[0].metadata["path"], "/data")
        self.assertFalse(any(node.type == "target" for node in graph.nodes))

    def test_compact_traversal(self):
        self.assertIn("Traversal: '/' -> '/data' (2 search components)", ag.render_terminal_graph(account()))

    def test_verbose_expands_components(self):
        text = ag.render_terminal_graph(account(), verbose=True)
        self.assertNotIn("Traversal:", text)
        self.assertIn("'/' (search)", text)
        self.assertIn("'/data' (search)", text)

    def test_acl_traversal_never_collapsed(self):
        diagnosis = account_result(SUBJECT).diagnosis
        acl_report = account_result(SUBJECT, acl=make_acl(users=((1001, 5),), mask=5)).diagnosis
        inode = replace(acl_report.trace.target, path="/data", decision=replace(acl_report.trace.target.decision, required=1))
        diagnosis.trace.events[-1] = inode
        text = ag.render_terminal_graph(ag.build_account_graph(diagnosis, ph.__version__))
        self.assertIn("'/data' (search)", text)
        self.assertIn("ACL NAMED USER", text)

    def test_symlink_edge(self):
        diagnosis = account_result(SUBJECT).diagnosis
        diagnosis.trace.events.insert(1, ph.Symlink("/link", "/data"))
        graph = ag.build_account_graph(diagnosis, ph.__version__)
        self.assertIn("'/link' -> '/data'", ag.render_terminal_graph(graph))
        self.assertTrue(any(edge.type == "resolves_to" for edge in graph.edges))


class CapabilityAndMountTests(unittest.TestCase):
    def test_override_chain_preserves_base_denial(self):
        graph = process(mask=2)
        nodes = {node.id: node for node in graph.nodes}
        override = next(node for node in graph.nodes if node.type == "capability" and node.status == "override")
        incoming = next(edge for edge in graph.edges if edge.target == override.id)
        self.assertEqual(incoming.type, "overrides")
        self.assertEqual(nodes[incoming.source].status, "fail")
        self.assertFalse(nodes[incoming.source].metadata["blocker"])
        self.assertEqual(graph.result, "permitted")

    def test_read_search_override(self):
        self.assertIn("CAP_DAC_READ_SEARCH overrides", labels(process(mask=4)))

    def test_mount_after_capability(self):
        graph = process(mask=2, mode="w", readonly=True)
        self.assertEqual(graph.result, "denied")
        self.assertEqual([node.id for node in graph.nodes if node.metadata.get("blocker")], ["mount:target"])
        self.assertIn("[OVERRIDE] CAP_DAC_OVERRIDE", ag.render_terminal_graph(graph))
        self.assertIn("[FAIL] Mount '/'", ag.render_terminal_graph(graph))

    def test_rw_mount_pass(self):
        mount = next(node for node in account().nodes if node.type == "mount")
        self.assertEqual(mount.status, "pass")
        self.assertIn("rw", mount.label)

    def test_readonly_write_denied(self):
        graph = account(target_mode=0o666, mode="w", readonly=True)
        self.assertEqual(graph.result, "denied")
        self.assertTrue(next(node for node in graph.nodes if node.type == "mount").metadata["blocker"])

    def test_noexec_execute_denied(self):
        graph = process(mask=2, permissions=1, mode="x", noexec=True)
        self.assertEqual(graph.result, "denied")
        self.assertIn("noexec", labels(graph))

    def test_unknown_capability_scope_preserves_base(self):
        graph = ag.build_process_graph(mapped_evaluate(foreign(capability=2)), ph.__version__)
        self.assertEqual(graph.result, "indeterminate")
        self.assertIn("OTHER ---: DENIED", labels(graph))
        self.assertTrue(any(node.type == "capability" and node.status == "indeterminate" for node in graph.nodes))
        self.assertFalse(any(node.type == "decision" and node.metadata.get("blocker") for node in graph.nodes))

    def test_unknown_capability_at_directory_not_labeled_target(self):
        graph = ag.build_process_graph(evaluate(process=foreign(capability=2), parent_permissions=0), ph.__version__)
        self.assertEqual(graph.result, "indeterminate")
        self.assertTrue(any(node.type == "directory" and node.metadata["path"] == "/data" for node in graph.nodes))
        self.assertFalse(any(node.type == "target" for node in graph.nodes))


class ProcessNamespaceTests(unittest.TestCase):
    def test_process_and_fsids(self):
        graph = process(permissions=4)
        self.assertEqual(graph.nodes[0].id, "process:42")
        self.assertIn("fsuid 9000, fsgid 500", labels(graph))

    def test_local_to_mapped_chain(self):
        graph = ag.build_process_graph(mapped_evaluate(), ph.__version__)
        self.assertIn("Local fsuid 0, fsgid 0", labels(graph))
        self.assertIn("Mapped fsuid 100000, fsgid 100000", labels(graph))
        self.assertIn(ag.GraphEdge("identity:local", "identity:filesystem", "maps_to"), graph.edges)
        self.assertIn("Owner UID 0", labels(graph))
        self.assertIn("OTHER ---", labels(graph))

    def test_mapped_group(self):
        graph = ag.build_process_graph(mapped_evaluate(group=100010, permissions=0o640), ph.__version__)
        self.assertIn("supplementary GID 100010", labels(graph))
        self.assertEqual(graph.result, "permitted")

    def test_unmapped_identity(self):
        graph = ag.build_process_graph(mapped_evaluate(foreign(uid=200000)), ph.__version__)
        self.assertIn("fsuid unmapped", labels(graph))
        self.assertEqual(graph.result, "indeterminate")

    def test_same_namespace_no_local_mapping_node(self):
        graph = process(permissions=4)
        self.assertNotIn("identity:local", [node.id for node in graph.nodes])
        self.assertIn("Same user namespace; IDs interpreted directly", labels(graph))

    def test_foreign_mount_no_fabricated_target(self):
        observed = replace(foreign(), mount_namespace=ps.NamespaceObservation("mnt:[9]", "mnt:[1]", False))
        graph = ag.build_process_graph(mapped_evaluate(observed), ph.__version__)
        self.assertEqual(graph.result, "indeterminate")
        self.assertFalse(any(node.type == "target" for node in graph.nodes))

    def test_capability_sets_context_in_verbose(self):
        graph = process(mask=2)
        self.assertIn("context:capabilities", [node.id for node in graph.nodes])
        self.assertIn("CAP_DAC_OVERRIDE", ag.render_terminal_graph(graph, verbose=True))


class ExportAndCLITests(unittest.TestCase):
    def test_json_schema_nodes_edges_result(self):
        graph = account()
        data = json.loads(ag.serialize_graph_json(graph))
        self.assertEqual(data["schema_version"], "1")
        self.assertEqual(data["graph_version"], "1")
        self.assertEqual(data["command"], "graph")
        self.assertEqual(data["result"], "permitted")
        self.assertTrue(data["nodes"])
        self.assertTrue(data["edges"])

    def test_dot_valid_quoted_endpoints(self):
        graph = process(mask=2)
        dot = ag.serialize_graph_dot(graph)
        self.assertTrue(dot.startswith("digraph permissionhell {\n"))
        self.assertTrue(dot.endswith("}\n"))
        self.assertEqual(dot.count("shape=box"), len(graph.nodes))
        for edge in graph.edges:
            self.assertIn(f'"{edge.source}" -> "{edge.target}"', dot)
        self.assertIn("[OVERRIDE]", dot)

    def test_dot_quotes_backslashes_controls(self):
        graph = account()
        graph.add_node(ag.GraphNode('malicious"id', "target", 'a"; }\\\n\x1b[31m'))
        dot = ag.serialize_graph_dot(graph)
        self.assertIn('"malicious\\"id"', dot)
        self.assertIn('a\\"; }\\\\\\\\n\\\\x1b[31m', dot)
        self.assertNotIn("\x1b", dot)

    def test_surrogate_name_safe_json_and_terminal(self):
        graph = account(replace(SUBJECT, username="bad\udcff\x1bname"))
        ag.serialize_graph_json(graph).encode("utf-8")
        ag.serialize_graph_dot(graph).encode("utf-8")
        ag.render_terminal_graph(graph).encode("utf-8")

    def test_terminal_arrows_blocker_and_status(self):
        text = ag.render_terminal_graph(account(target_mode=0))
        self.assertIn("  |\n  v", text)
        self.assertIn("<-- BLOCKER", text)
        self.assertIn("READ DENIED", text)

    def test_account_cli_json_reuses_engine(self):
        diagnosis = account_result(SUBJECT).diagnosis
        with patch.object(ph.sys, "platform", "linux"), patch.object(ph, "resolve_subject", return_value=SUBJECT), \
                patch.object(ph, "diagnose", return_value=diagnosis) as run, contextlib.redirect_stdout(io.StringIO()) as output:
            code = ph.main(["graph", "/data/file", "--as", "alice", "--json"])
        run.assert_called_once_with("/data/file", SUBJECT, "r")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["graph_version"], "1")

    def test_process_cli_dot_reuses_engine(self):
        report = evaluate(2)
        with patch.object(ph.sys, "platform", "linux"), patch.object(ph, "diagnose_process", return_value=report) as run, \
                contextlib.redirect_stdout(io.StringIO()) as output, patch.object(subprocess, "run", side_effect=AssertionError("Graphviz execution")):
            code = ph.main(["graph", "/data/file", "--pid", "42", "--dot"])
        run.assert_called_once_with("/data/file", 42, "r")
        self.assertEqual(code, 0)
        self.assertTrue(output.getvalue().startswith("digraph"))

    def test_unknown_user_exports_graph_error(self):
        with patch.object(ph.sys, "platform", "linux"), patch.object(ph, "resolve_subject", side_effect=ph.DiagnosticError("No such user", ph.ExitCode.INPUT)), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            code = ph.main(["graph", "/data/file", "--as", "missing", "--json"])
        data = json.loads(output.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(data["result"], "invalid_input")
        self.assertEqual(data["nodes"][-1]["status"], "error")

    def test_unsupported_platform_error_graph(self):
        with patch.object(ph.sys, "platform", "win32"), contextlib.redirect_stdout(io.StringIO()) as output:
            code = ph.main(["graph", "/data/file", "--as", "alice", "--json"])
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(output.getvalue())["result"], "error")

    def test_selectors_and_formats_exclusive(self):
        for options in ([], ["--as", "a", "--pid", "42"], ["--as", "a", "--json", "--dot"]):
            with self.subTest(options=options), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                ph.main(["graph", "/file", *options])
            self.assertEqual(error.exception.code, 2)

    def test_process_relative_path_stays_invalid(self):
        with patch.object(ph.sys, "platform", "linux"), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(ph.main(["graph", "relative", "--pid", "42", "--json"]), 2)
        self.assertEqual(json.loads(output.getvalue())["result"], "invalid_input")

    def test_json_full_even_if_terminal_compact(self):
        graph = account()
        ag.render_terminal_graph(graph)
        self.assertEqual(len([node for node in json.loads(ag.serialize_graph_json(graph))["nodes"] if node["type"] == "directory"]), 2)

    def test_account_error_result(self):
        diagnosis = account_result(SUBJECT).diagnosis
        diagnosis.mount = None
        diagnosis.mount_error = "mountinfo unavailable"
        diagnosis.reasons.clear()
        ph.determine_verdict(diagnosis)
        graph = ag.build_account_graph(diagnosis, ph.__version__)
        self.assertEqual(graph.result, "error")
        self.assertEqual(graph.nodes[-1].status, "error")


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux integration")
class IntegrationTests(unittest.TestCase):
    def test_process_graph_json_entrypoint(self):
        with tempfile.NamedTemporaryFile() as target:
            result = subprocess.run([sys.executable, str(Path(ph.__file__)), "graph", target.name, "--pid", str(os.getpid()), "--json"],
                                    capture_output=True, text=True)
        data = json.loads(result.stdout)
        self.assertEqual(data["graph_version"], "1")
        self.assertEqual(data["exit_code"], result.returncode)
        self.assertIn(f"process:{os.getpid()}", [node["id"] for node in data["nodes"]])
