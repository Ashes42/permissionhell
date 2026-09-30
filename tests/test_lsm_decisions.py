"""Host policy and log adapters are always mocked; no active LSM is required."""
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

import access_graph as graph
import access_monitor as monitor
import access_snapshot as snapshots
import json_output
import lsm
import lsm_policy as policy
import permissionhell as ph
import process_audit
from test_capabilities import evaluate, process_with
from test_lsm import state, report
from test_policy_drift import process_run
from test_access_snapshot import processes


class FakeSELinux:
    def __init__(self, deny=False, flags=0):
        self.deny = deny
        self.flags = flags
        self.calls = []

    def is_selinux_enabled(self):
        return 1

    def security_getenforce(self):
        return 1

    def string_to_security_class(self, name):
        return {"dir": 1, "file": 2}[name]

    def string_to_av_perm(self, cls, name):
        return {"search": 1, "open": 2, "read": 4, "write": 8, "execute": 16}[name]

    def av_decision(self):
        return SimpleNamespace()

    def security_compute_av_flags_raw(self, source, target, cls, requested, result):
        self.calls.append((source, target, cls, requested))
        result.allowed = 0 if self.deny and cls == 2 else 0xFFFFFFFF
        result.decided = 0xFFFFFFFF
        result.flags = self.flags
        result.seqno = 9
        return 0


def query(api=None, security=None, diagnosis=None):
    api = api or FakeSELinux()
    security = security or state(enforcing=True)
    diagnosis = diagnosis or evaluate(permissions=4).diagnosis
    nodes = {item.path: item for item in [*diagnosis.trace.events, diagnosis.trace.target] if hasattr(item, "mode")}
    def identity(path):
        item = nodes[path]
        return 1, 2, item.mode, item.uid, item.gid
    with patch.object(policy, "load_selinux", return_value=api), \
            patch.object(policy, "context", return_value=security.selinux.target_context or "u:r:target_t:s0"), \
            patch.object(policy, "inode_identity", side_effect=identity):
        return policy.query_selinux(security, diagnosis)


def labeled_state():
    security = state(enforcing=True)
    return replace(security, selinux=replace(security.selinux, target_context="u:r:target_t:s0", target_status="present"))


def layer(denied=False):
    return {"module": "selinux", "decision": "denied" if denied else "allowed",
            "reason": "SELinux kernel policy denies read." if denied else "SELinux kernel policy permits modeled access.",
            "evidence": [{"kind": "kernel_policy_query", "source": "libselinux.security_compute_av_flags_raw",
                          "path": "/data/file", "object_class": "file", "permissions": ["open", "read"],
                          "process_context": "u:r:task_t:s0", "target_context": "u:r:target_t:s0", "allowed": not denied}]}


def resolved_report(denied=False, security=None, permissions=4):
    with patch.object(policy, "query_selinux", return_value=layer(denied)):
        return report(security or state(enforcing=True), permissions=permissions)


class SELinuxTests(unittest.TestCase):
    def test_python_binding_preferred(self):
        api = FakeSELinux()
        with patch.object(policy.importlib, "import_module", return_value=api), patch.object(policy, "NativeSELinux") as native:
            self.assertIs(policy.load_selinux(), api)
        native.assert_not_called()

    def test_native_fallback_does_not_install(self):
        with patch.object(policy.importlib, "import_module", side_effect=ImportError), \
                patch.object(policy, "NativeSELinux", return_value="native"):
            self.assertEqual(policy.load_selinux(), "native")

    def test_native_abi_wrapper(self):
        library = Mock()
        library.is_selinux_enabled.return_value = 1
        library.security_getenforce.return_value = 1
        library.string_to_security_class.return_value = 2
        library.string_to_av_perm.return_value = 4
        def compute(source, target, cls, requested, pointer):
            self.assertEqual((source, target, cls, requested), (b"u:r:a:s0", b"u:r:b:s0", 2, 4))
            pointer._obj.allowed = pointer._obj.decided = 0xFFFFFFFF
            pointer._obj.seqno = 1
            return 0
        library.security_compute_av_flags_raw.side_effect = compute
        with patch.object(policy.ctypes, "CDLL", return_value=library):
            native = policy.NativeSELinux()
        self.assertTrue(policy.av_query(native, "u:r:a:s0", "u:r:b:s0", "file", ["read"])["allowed"])
        self.assertEqual(len(library.security_compute_av_flags_raw.argtypes), 5)

    def test_both_host_bindings_absent(self):
        with patch.object(policy.importlib, "import_module", side_effect=ImportError), \
                patch.object(policy.ctypes, "CDLL", side_effect=OSError("not found")), self.assertRaises(OSError):
            policy.load_selinux()

    def test_inactive_stays_resolved(self):
        self.assertEqual(lsm.evaluate(state(), 0).status, "resolved")

    def test_permissive_does_not_query(self):
        with patch.object(policy, "query_selinux") as query_api:
            self.assertEqual(report(state(enforcing=False)).code, 0)
        query_api.assert_not_called()

    def test_enforcing_permit(self):
        result = query(security=labeled_state())
        self.assertEqual(result["decision"], "allowed")
        self.assertEqual([e["object_class"] for e in result["evidence"]], ["dir", "dir", "file"])
        self.assertEqual(result["evidence"][-1]["permissions"], ["open", "read"])

    def test_enforcing_deny(self):
        result = query(FakeSELinux(deny=True), labeled_state())
        self.assertEqual(result["decision"], "denied")
        self.assertFalse(result["evidence"][-1]["allowed"])

    def test_write_vector(self):
        result = query(security=labeled_state(), diagnosis=evaluate(mode="w", permissions=6).diagnosis)
        self.assertEqual(result["decision"], "allowed")
        self.assertEqual(result["evidence"][-1]["permissions"], ["open", "write"])

    def test_missing_tooling(self):
        with patch.object(policy, "load_selinux", side_effect=ImportError("not installed")):
            result = policy.query_selinux(labeled_state(), evaluate(permissions=4).diagnosis)
        self.assertEqual(result["decision"], "unresolved")
        self.assertIn("not installed", result["reason"])

    def test_missing_api(self):
        self.assertEqual(query(object(), labeled_state())["decision"], "unresolved")

    def test_target_context_unavailable(self):
        with patch.object(policy, "load_selinux") as load:
            result = policy.query_selinux(state(enforcing=True), evaluate(permissions=4).diagnosis)
        self.assertEqual(result["decision"], "unresolved")
        load.assert_not_called()

    def test_process_context_unavailable(self):
        security = labeled_state()
        security = replace(security, selinux=replace(security.selinux, process_context=None))
        self.assertEqual(query(security=security)["decision"], "unresolved")

    def test_per_domain_permissive(self):
        result = query(FakeSELinux(deny=True, flags=1), labeled_state())
        self.assertEqual(result["decision"], "allowed")
        self.assertTrue(result["evidence"][-1]["domain_permissive"])

    def test_unknown_flags_unresolved(self):
        self.assertEqual(query(FakeSELinux(flags=128), labeled_state())["decision"], "unresolved")

    def test_failed_query_unresolved(self):
        api = FakeSELinux()
        api.security_compute_av_flags_raw = lambda *args: -1
        self.assertEqual(query(api, labeled_state())["decision"], "unresolved")

    def test_malformed_api_output(self):
        for field, value in (("allowed", "yes"), ("flags", -1), ("seqno", True), ("decided", 0)):
            api = FakeSELinux()
            original = api.security_compute_av_flags_raw
            def bad(*args):
                original(*args)
                setattr(args[-1], field, value)
                return 0
            api.security_compute_av_flags_raw = bad
            with self.subTest(field=field):
                self.assertEqual(query(api, labeled_state())["decision"], "unresolved")

    def test_class_mapping_missing(self):
        api = FakeSELinux()
        api.string_to_security_class = lambda name: 0
        self.assertEqual(query(api, labeled_state())["decision"], "unresolved")

    def test_permission_mapping_missing(self):
        api = FakeSELinux()
        api.string_to_av_perm = lambda cls, name: 0
        self.assertEqual(query(api, labeled_state())["decision"], "unresolved")

    def test_policy_reload_unresolved(self):
        api = FakeSELinux()
        original = api.security_compute_av_flags_raw
        def changing(*args):
            original(*args)
            args[-1].seqno = len(api.calls)
            return 0
        api.security_compute_av_flags_raw = changing
        self.assertEqual(query(api, labeled_state())["decision"], "unresolved")

    def test_enforcement_changed(self):
        api = FakeSELinux()
        with patch.object(api, "security_getenforce", side_effect=[1, 0]):
            self.assertEqual(query(api, labeled_state())["decision"], "unresolved")

    def test_host_disabled(self):
        api = FakeSELinux()
        api.is_selinux_enabled = lambda: 0
        self.assertEqual(query(api, labeled_state())["decision"], "unresolved")

    def test_execute_allow_not_complete(self):
        result = query(security=labeled_state(), diagnosis=evaluate(mode="x", permissions=1).diagnosis)
        self.assertEqual(result["decision"], "unresolved")

    def test_execute_deny_resolves(self):
        result = query(FakeSELinux(deny=True), labeled_state(), evaluate(mode="x", permissions=1).diagnosis)
        self.assertEqual(result["decision"], "denied")

    def test_symlink_allow_not_complete(self):
        diagnosis = evaluate(permissions=4).diagnosis
        diagnosis.trace.events.append(ph.Symlink("/alias", "/data/file"))
        self.assertEqual(query(security=labeled_state(), diagnosis=diagnosis)["decision"], "unresolved")

    def test_special_inode_unresolved(self):
        diagnosis = evaluate(permissions=4).diagnosis
        diagnosis.trace.target = replace(diagnosis.trace.target, mode=stat.S_IFSOCK | 4)
        self.assertEqual(query(security=labeled_state(), diagnosis=diagnosis)["decision"], "unresolved")

    def test_changed_target_label(self):
        security = labeled_state()
        diagnosis = evaluate(permissions=4).diagnosis
        with patch.object(policy, "load_selinux", return_value=FakeSELinux()), \
                patch.object(policy, "context", return_value="u:r:new_t:s0"), \
                patch.object(policy, "inode_identity", side_effect=lambda path: (1, 2,
                    stat.S_IFREG | 4 if path == "/data/file" else stat.S_IFDIR | 0o755, 555, 666)):
            self.assertEqual(policy.query_selinux(security, diagnosis)["decision"], "unresolved")

    def test_metadata_disappearance(self):
        with patch.object(policy, "load_selinux", return_value=FakeSELinux()), \
                patch.object(policy, "inode_identity", side_effect=FileNotFoundError("gone")):
            result = policy.query_selinux(labeled_state(), evaluate(permissions=4).diagnosis)
        self.assertEqual(result["decision"], "unresolved")

    def test_dac_denial_does_not_query(self):
        with patch.object(policy, "query_selinux") as backend:
            self.assertEqual(resolved_report(permissions=0).code, 1)
        backend.assert_not_called()


LOG = 'type=AVC msg=audit(999990.0:12): apparmor="DENIED" operation="open" profile="p" name="/data/file" pid=42 requested_mask="r" denied_mask="r"'


def correlate(lines=LOG, journal="", process=None):
    with patch.object(policy, "read_log_tail", return_value=lines), patch.object(policy, "read_journal", return_value=journal), \
            patch.object(policy.time, "time", return_value=1000000), \
            patch.object(policy.time, "clock_gettime", return_value=1000), patch.object(policy.os, "sysconf", return_value=100):
        return policy.correlate_apparmor(state("p (enforce)"), process or process_with(), evaluate(permissions=4).diagnosis)


class AppArmorTests(unittest.TestCase):
    def test_unconfined_no_collection(self):
        with patch.object(policy, "correlate_apparmor") as logs:
            self.assertEqual(report(state("unconfined")).code, 0)
        logs.assert_not_called()

    def test_matching_denial_is_historical_evidence(self):
        result = correlate()
        self.assertEqual(result["decision"], "unresolved")
        self.assertEqual(len(result["evidence"]), 1)
        self.assertEqual(result["evidence"][0]["kind"], "historical_audit_correlation")

    def test_wrong_pid(self):
        self.assertEqual(correlate(LOG.replace("pid=42", "pid=43"))["evidence"], [])

    def test_wrong_profile(self):
        self.assertEqual(correlate(LOG.replace('profile="p"', 'profile="other"'))["evidence"], [])

    def test_wrong_path(self):
        self.assertEqual(correlate(LOG.replace("/data/file", "/data/other"))["evidence"], [])

    def test_wrong_operation(self):
        self.assertEqual(correlate(LOG.replace('operation="open"', 'operation="capable"'))["evidence"], [])

    def test_wrong_permission(self):
        self.assertEqual(correlate(LOG.replace('denied_mask="r"', 'denied_mask="w"'))["evidence"], [])

    def test_stale(self):
        self.assertEqual(correlate(LOG.replace("999990.0", "999800.0"))["evidence"], [])

    def test_future(self):
        self.assertEqual(correlate(LOG.replace("999990.0", "1000001.0"))["evidence"], [])

    def test_pid_reuse_event_precedes_birth(self):
        self.assertEqual(correlate(process=replace(process_with(), start_time_ticks=99999))["evidence"], [])

    def test_no_readable_logs(self):
        with patch.object(policy, "read_log_tail", side_effect=PermissionError()), patch.object(policy, "read_journal", side_effect=OSError()):
            result = policy.correlate_apparmor(state("p (enforce)"), process_with(), evaluate(permissions=4).diagnosis)
        self.assertEqual(result["decision"], "unresolved")
        self.assertEqual(len(result["unavailable_sources"]), 4)

    def test_empty_logs_not_allow(self):
        self.assertEqual(correlate("")["decision"], "unresolved")

    def test_journal_record(self):
        result = correlate("", json.dumps({"_TRANSPORT": "kernel", "MESSAGE": LOG}))
        self.assertEqual(result["evidence"][0]["source"], "journalctl")

    def test_untrusted_journal_transport(self):
        result = correlate("", json.dumps({"_TRANSPORT": "stdout", "MESSAGE": LOG}))
        self.assertEqual(result["evidence"], [])

    def test_malformed_journal(self):
        self.assertEqual(correlate("", "{bad")["decision"], "unresolved")

    def test_parse_hex_path(self):
        message = LOG.replace('name="/data/file"', "name=" + b"/data/file".hex())
        self.assertEqual(policy.parse_denial(message)["path"], "/data/file")

    def test_quoted_hex_profile_not_decoded(self):
        self.assertEqual(policy.parse_denial(LOG.replace('profile="p"', 'profile="face"'))["profile"], "face")

    def test_malformed_logs(self):
        for message in (LOG + " pid=42", LOG.replace('name="/data/file"', 'name="unterminated'),
                        LOG.replace('apparmor="DENIED"', 'apparmor="ALLOWED"'), LOG.replace("audit(999990.0:12)", "audit(bad)"),
                        LOG.replace("/data/file", "/data/\x1bfile"), "x" * 17000):
            with self.subTest(message=message[:60]):
                self.assertIsNone(policy.parse_denial(message))

    def test_file_tail_regular_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "log"
            path.write_bytes(b"x" * (policy.LOG_LIMIT + 100) + b"\n" + LOG.encode())
            self.assertEqual(policy.read_log_tail(str(path)), LOG)

    def test_symlink_log_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "log"
            path.write_text(LOG)
            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                policy.read_log_tail(str(link))

    def test_journal_invocation_bounded_no_shell(self):
        with patch.object(policy.os.path, "isfile", return_value=True), \
                patch.object(policy.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="")) as command:
            self.assertEqual(policy.read_journal(), "")
        self.assertEqual(command.call_args.kwargs["timeout"], 2)
        self.assertNotIn("shell", command.call_args.kwargs)
        self.assertIn("-n", command.call_args.args[0])

    def test_journal_failure_and_oversized_output(self):
        for value in (SimpleNamespace(returncode=1, stdout=""), SimpleNamespace(returncode=0, stdout="x" * (4 * policy.LOG_LIMIT + 1))):
            with self.subTest(value=value.returncode), patch.object(policy.os.path, "isfile", return_value=True), \
                    patch.object(policy.subprocess, "run", return_value=value), self.assertRaises(OSError):
                policy.read_journal()


class PropagationTests(unittest.TestCase):
    def test_process_permit(self):
        result = resolved_report()
        self.assertEqual(result.code, 0)
        self.assertEqual(result.lsm_result.status, "resolved")

    def test_process_deny_separate_from_base(self):
        result = resolved_report(True)
        self.assertEqual(result.code, 1)
        self.assertEqual(result.diagnosis.code, 0)
        self.assertEqual(result.lsm_result.status, "denied")

    def test_selinux_permit_does_not_override_apparmor(self):
        result = resolved_report(security=state("p (enforce)", True))
        self.assertEqual(result.code, 3)

    def test_selinux_deny_sufficient_with_apparmor_unknown(self):
        result = resolved_report(True, state("p (enforce)", True))
        self.assertEqual(result.code, 1)

    def test_graph_resolved_deny(self):
        result = graph.build_process_graph(resolved_report(True), ph.__version__)
        self.assertEqual(result.result, "denied")
        self.assertEqual(next(n.status for n in result.nodes if n.type == "lsm"), "fail")

    def test_graph_resolved_allow(self):
        result = graph.build_process_graph(resolved_report(), ph.__version__)
        self.assertEqual(next(n.status for n in result.nodes if n.type == "lsm"), "pass")

    def test_json_evidence_and_effective_blocker(self):
        data = json.loads(json_output.render_json(json_output.process_document(resolved_report(True), ph.__version__)))
        self.assertEqual(data["schema_version"], "1")
        self.assertEqual(data["ordinary_verdict"], "permitted")
        self.assertEqual(data["verdict"], "denied")
        self.assertIsNone(data["first_blocker"])
        self.assertEqual(data["effective_blocker"]["stage"], "lsm")
        self.assertEqual(data["lsm_result"]["layer_results"][0]["evidence"][0]["kind"], "kernel_policy_query")

    def test_human_evidence(self):
        text = ph.render_process_report(resolved_report(True), verbose=True)
        self.assertIn("RESULT: DENIED", text)
        self.assertIn("libselinux.security_compute_av_flags_raw", text)
        self.assertIn("mount result: PERMITTED", text)

    def test_audit_classification(self):
        self.assertEqual(process_audit.classify(resolved_report(True)).verdict, "denied")
        self.assertEqual(process_audit.classify(resolved_report()).verdict, "permitted")

    def test_policy_allow_resolved(self):
        self.assertEqual(process_run(report=resolved_report()).summary.matches, 1)

    def test_policy_deny_resolved(self):
        self.assertEqual(process_run("deny", resolved_report(True)).summary.matches, 1)

    def test_snapshot_roundtrip_denial(self):
        before = processes([resolved_report(True)])
        loaded = snapshots.validate_snapshot(json.loads(snapshots.serialize_snapshot(before)))
        self.assertEqual(loaded.subjects[0].mechanism, "selinux")
        self.assertEqual(loaded.subjects[0].blocker["stage"], "lsm")
        self.assertEqual(snapshots.diff_snapshots(before, loaded).code, 0)

    def test_monitor_reuses_gained_access(self):
        diff = snapshots.diff_snapshots(processes([resolved_report(True)]), processes([resolved_report()]))
        result = monitor.MonitorResult("baseline.json", diff)
        self.assertEqual(result.code, 1)
        self.assertEqual(diff.summary["gained_access"], 1)

    def test_backend_within_process_revalidation(self):
        observed = replace(process_with(), lsm=state(enforcing=True))
        ordinary = evaluate(permissions=4).diagnosis
        with patch.object(ph, "inspect_process", side_effect=[observed, replace(observed, start_time_ticks=999)]), \
                patch.object(ph, "diagnose", return_value=ordinary), patch.object(lsm, "inspect_target", return_value=labeled_state()), \
                patch.object(policy, "query_selinux", return_value=layer(True)):
            result = ph.diagnose_process("/data/file", 42)
        self.assertEqual(result.code, 3)
        self.assertIsNone(result.lsm_result)


if __name__ == "__main__":
    unittest.main()
