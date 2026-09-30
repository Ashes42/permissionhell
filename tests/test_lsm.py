"""Kernel-interface fixtures and LSM propagation through the existing engines."""
import contextlib
from dataclasses import replace
import errno
import io
import json
import os
import sys
import unittest
from unittest.mock import patch

import access_graph as graph
import access_snapshot as snap
import json_output as jo
import lsm
import lsm_policy
import permissionhell as ph
import process_audit as pa
import process_subject as ps
from test_capabilities import evaluate, process_with
from test_policy_drift import process_run
from test_access_snapshot import processes


def state(profile=None, enforcing=None, *, active=None):
    aa = lsm.AppArmorContext(False)
    se = lsm.SELinuxContext(False)
    names = []
    if profile is not None:
        name, mode = lsm.parse_apparmor(profile)
        aa = lsm.AppArmorContext(True, name, mode)
        names.append("apparmor")
    if enforcing is not None:
        se = lsm.SELinuxContext(True, enforcing, "user_u:user_r:user_t:s0", policy_loaded=True)
        names.append("selinux")
    return lsm.LSMState(tuple(names if active is None else active), "available", aa, se)


def report(security=None, *, permissions=4, **kwargs):
    observed = replace(process_with(kwargs.pop("mask", 0)), lsm=security or state())
    with patch.object(lsm.os, "getxattr", return_value=b"system_u:object_r:data_t:s0\0"), \
            patch.object(lsm_policy, "load_selinux", side_effect=ImportError("No fixture policy backend")), \
            patch.object(lsm_policy, "read_log_tail", side_effect=PermissionError("Fixture logs unavailable")), \
            patch.object(lsm_policy, "read_journal", side_effect=PermissionError("Fixture journal unavailable")):
        return evaluate(process=observed, permissions=permissions, **kwargs)


def kernel_read(files):
    def read(path):
        value = files.get(path, FileNotFoundError(errno.ENOENT, "not visible"))
        if isinstance(value, Exception):
            raise value
        return value
    return patch.object(lsm, "read_text", side_effect=read)


class ParsingTests(unittest.TestCase):
    def test_empty_active(self):
        self.assertEqual(lsm.parse_active("\n"), ())

    def test_apparmor_active(self):
        self.assertEqual(lsm.parse_active("apparmor\n"), ("apparmor",))

    def test_selinux_active(self):
        self.assertEqual(lsm.parse_active("selinux"), ("selinux",))

    def test_stack_preserves_order(self):
        self.assertEqual(lsm.parse_active("lockdown,capability,landlock,yama,apparmor"),
                         ("lockdown", "capability", "landlock", "yama", "apparmor"))

    def test_malformed_active(self):
        for raw in ("apparmor,", "a,,b", "a,a", "a b", "A", "a\x00"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                lsm.parse_active(raw)

    def test_unconfined(self):
        self.assertEqual(lsm.parse_apparmor("unconfined\n"), ("unconfined", "unconfined"))

    def test_enforce(self):
        self.assertEqual(lsm.parse_apparmor("usr.sbin.nginx (enforce)\n"), ("usr.sbin.nginx", "enforce"))

    def test_complain(self):
        self.assertEqual(lsm.parse_apparmor("snap.foo.bar (complain)"), ("snap.foo.bar", "complain"))

    def test_unfamiliar_profile_is_unknown(self):
        self.assertEqual(lsm.parse_apparmor("profile (future-mode)")[1], "unknown")

    def test_stacked_complain_not_assumed_safe(self):
        self.assertEqual(lsm.parse_apparmor("a//&b (complain)")[1], "unknown")

    def test_malformed_attribute(self):
        for raw in ("", "\x00", "profile\nother", "a\x1b[2J"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                lsm.parse_apparmor(raw)

    def test_selinux_mls_context(self):
        self.assertEqual(lsm.parse_selinux("u:r:t:s0:c1,c2\0"), "u:r:t:s0:c1,c2")

    def test_selinux_initial_context(self):
        self.assertEqual(lsm.parse_selinux("kernel\0"), "kernel")

    def test_malformed_selinux(self):
        for raw in ("foo", "u::t:s0", "u:r:t:\nother", "u:r:t s0"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                lsm.parse_selinux(raw)


class DetectionTests(unittest.TestCase):
    def detect(self, files, pid=None):
        with kernel_read(files):
            return lsm.detect_system() if pid is None else lsm.inspect_process(pid)

    def test_empty_registry_proves_supported_inactive(self):
        result = self.detect({"/sys/kernel/security/lsm": ""})
        self.assertFalse(result.apparmor.enabled)
        self.assertFalse(result.selinux.enabled)

    def test_missing_sources_unknown(self):
        result = self.detect({})
        self.assertIsNone(result.apparmor.enabled)
        self.assertIsNone(result.selinux.enabled)
        self.assertEqual(result.active_status, "unavailable")

    def test_apparmor_enabled_fallback(self):
        result = self.detect({"/sys/module/apparmor/parameters/enabled": "Y\n"})
        self.assertTrue(result.apparmor.enabled)

    def test_apparmor_disabled_fallback(self):
        self.assertFalse(self.detect({"/sys/module/apparmor/parameters/enabled": "N"}).apparmor.enabled)

    def test_malformed_enabled(self):
        result = self.detect({"/sys/module/apparmor/parameters/enabled": "maybe"})
        self.assertTrue(result.malformed)

    def test_enforcing(self):
        result = self.detect({"/sys/kernel/security/lsm": "selinux", "/sys/fs/selinux/enforce": "1"})
        self.assertTrue(result.selinux.enforcing)

    def test_permissive(self):
        result = self.detect({"/sys/kernel/security/lsm": "selinux", "/sys/fs/selinux/enforce": "0"})
        self.assertFalse(result.selinux.enforcing)

    def test_unreadable_enforce_preserves_enabled(self):
        result = self.detect({"/sys/kernel/security/lsm": "selinux", "/sys/fs/selinux/enforce": PermissionError("hidden")})
        self.assertTrue(result.selinux.enabled)
        self.assertIsNone(result.selinux.enforcing)

    def test_malformed_enforce(self):
        result = self.detect({"/sys/kernel/security/lsm": "selinux", "/sys/fs/selinux/enforce": "2"})
        self.assertEqual(lsm.evaluate(result, 0).status, "error")

    def test_malformed_registry(self):
        result = self.detect({"/sys/kernel/security/lsm": "a,,b"})
        self.assertEqual(result.active_status, "malformed")
        self.assertEqual(lsm.evaluate(result, 0).status, "error")

    def test_apparmor_module_attribute(self):
        result = self.detect({"/sys/kernel/security/lsm": "apparmor",
                              "/proc/42/attr/apparmor/current": "service (enforce)"}, 42)
        self.assertEqual(result.apparmor.profile, "service")

    def test_legacy_apparmor_attribute(self):
        result = self.detect({"/sys/kernel/security/lsm": "apparmor",
                              "/proc/42/attr/current": "unconfined"}, 42)
        self.assertEqual(result.apparmor.mode, "unconfined")

    def test_unreadable_attribute(self):
        result = self.detect({"/sys/kernel/security/lsm": "apparmor",
                              "/proc/42/attr/current": PermissionError("hidden")}, 42)
        self.assertIn("hidden", result.apparmor.error)
        self.assertEqual(lsm.evaluate(result, 0).status, "indeterminate")

    def test_malformed_attribute_error(self):
        result = self.detect({"/sys/kernel/security/lsm": "apparmor",
                              "/proc/42/attr/apparmor/current": "\x00"}, 42)
        self.assertEqual(lsm.evaluate(result, 0).status, "error")

    def test_shared_attribute_not_assigned_to_two_modules(self):
        result = self.detect({"/sys/kernel/security/lsm": "apparmor,selinux",
                              "/proc/42/attr/current": "unconfined"}, 42)
        self.assertIsNone(result.apparmor.profile)
        self.assertIsNone(result.selinux.process_context)

    def test_stacked_module_attributes(self):
        result = self.detect({"/sys/kernel/security/lsm": "apparmor,selinux",
                              "/sys/fs/selinux/enforce": "0",
                              "/proc/42/attr/apparmor/current": "service (enforce)",
                              "/proc/42/attr/selinux/current": "u:r:t:s0"}, 42)
        self.assertEqual(result.apparmor.profile, "service")
        self.assertEqual(result.selinux.process_context, "u:r:t:s0")
        self.assertEqual(lsm.evaluate(result, 0).status, "indeterminate")

    def test_initial_selinux_policy_not_loaded(self):
        result = self.detect({"/sys/module/apparmor/parameters/enabled": "N",
                              "/proc/42/attr/current": "kernel\0"}, 42)
        self.assertFalse(result.selinux.policy_loaded)
        self.assertIsNone(result.selinux.enforcing)
        self.assertEqual(lsm.evaluate(result, 0).status, "resolved")

    def test_target_context(self):
        with patch.object(os, "getxattr", return_value=b"u:object_r:t:s0\0") as reader:
            result = lsm.inspect_target(state(enforcing=True), "/file")
        reader.assert_called_once_with("/file", "security.selinux")
        self.assertEqual(result.selinux.target_context, "u:object_r:t:s0")
        self.assertEqual(result.selinux.target_status, "present")

    def test_target_absent(self):
        with patch.object(os, "getxattr", side_effect=OSError(errno.ENODATA, "absent")):
            result = lsm.inspect_target(state(enforcing=True), "/file")
        self.assertEqual(result.selinux.target_status, "absent")
        self.assertEqual(lsm.evaluate(result, 0).status, "indeterminate")

    def test_target_permission_denied(self):
        for code in (errno.EACCES, errno.EPERM):
            with self.subTest(code=code), patch.object(os, "getxattr", side_effect=OSError(code, "denied")):
                result = lsm.inspect_target(state(enforcing=True), "/file")
            self.assertEqual(result.selinux.target_status, "permission_denied")

    def test_target_unsupported(self):
        with patch.object(os, "getxattr", side_effect=OSError(errno.ENOTSUP, "unsupported")):
            result = lsm.inspect_target(state(enforcing=True), "/file")
        self.assertEqual(result.selinux.target_status, "unsupported")

    def test_target_malformed(self):
        with patch.object(os, "getxattr", return_value=b"bad\xff"):
            result = lsm.inspect_target(state(enforcing=True), "/file")
        self.assertEqual(result.selinux.target_status, "unavailable")

    def test_no_apparmor_inode_label(self):
        with patch.object(os, "getxattr") as reader:
            lsm.inspect_target(state("unconfined"), "/file")
        reader.assert_not_called()

    def test_permissive_malformed_description_does_not_poison(self):
        result = self.detect({"/sys/kernel/security/lsm": "selinux", "/sys/fs/selinux/enforce": "0",
                              "/proc/42/attr/selinux/current": "bad context"}, 42)
        self.assertIsNotNone(result.selinux.error)
        self.assertEqual(lsm.evaluate(result, 0).status, "resolved")

    def test_required_kernel_io_error(self):
        result = self.detect({"/sys/kernel/security/lsm": OSError(errno.EIO, "I/O error")})
        self.assertEqual(lsm.evaluate(result, 0).status, "error")
        self.assertEqual(lsm.evaluate(result, 1).status, "not_required")

    def test_bad_utf8_kernel_data(self):
        result = self.detect({"/sys/kernel/security/lsm": UnicodeError("invalid encoding")})
        self.assertEqual(lsm.evaluate(result, 0).status, "error")


class DecisionTests(unittest.TestCase):
    def test_no_active_lsm_permit(self):
        self.assertEqual(report().code, 0)

    def test_enforcing_apparmor_permit_unresolved(self):
        result = report(state("service (enforce)"))
        self.assertEqual(result.code, 3)
        self.assertEqual(result.diagnosis.code, 0)
        self.assertEqual(result.indeterminate_reason, "lsm_policy_unresolved")

    def test_enforcing_apparmor_denial_preserved(self):
        self.assertEqual(report(state("service (enforce)"), permissions=0).code, 1)

    def test_unknown_lsm_denial_preserved(self):
        self.assertEqual(report(lsm.LSMState(), permissions=0).code, 1)

    def test_unconfined_permit(self):
        self.assertEqual(report(state("unconfined")).code, 0)

    def test_complain_permit(self):
        self.assertEqual(report(state("service (complain)")).code, 0)

    def test_enforcing_selinux_unresolved(self):
        self.assertEqual(report(state(enforcing=True)).code, 3)

    def test_enforcing_selinux_denial_preserved(self):
        self.assertEqual(report(state(enforcing=True), permissions=0).code, 1)

    def test_permissive_selinux_permit(self):
        self.assertEqual(report(state(enforcing=False)).code, 0)

    def test_apparmor_enforce_selinux_permissive(self):
        self.assertEqual(report(state("p (enforce)", False)).code, 3)

    def test_apparmor_unconfined_selinux_enforcing(self):
        self.assertEqual(report(state("unconfined", True)).code, 3)

    def test_yama_lockdown_do_not_poison(self):
        self.assertEqual(report(state(active=("yama", "lockdown", "capability"))).code, 0)

    def test_unknown_names_listed_not_assumed_file_denier(self):
        result = report(state(active=("future_lsm", "another_lsm")))
        self.assertEqual(result.code, 0)
        self.assertIn("future_lsm", ph.render_process_report(result))

    def test_unmodeled_file_lsms(self):
        for name in ("smack", "tomoyo", "bpf", "ipe"):
            with self.subTest(name=name):
                self.assertEqual(report(state(active=(name,))).code, 3)

    def test_landlock_availability_is_not_task_confinement(self):
        result = report(state(active=("landlock",)))
        self.assertEqual(result.code, 0)
        self.assertIn("not detected", " ".join(result.lsm_result.reasons))

    def test_capability_cannot_bypass_lsm(self):
        result = report(state("p (enforce)"), mask=2, permissions=0)
        self.assertEqual(result.diagnosis.code, 0)
        self.assertEqual(result.code, 3)

    def test_mount_denial_preserved(self):
        result = report(state("p (enforce)"), permissions=6, mode="w", readonly=True)
        self.assertEqual(result.code, 1)

    def test_parent_denial_preserved(self):
        self.assertEqual(report(state("p (enforce)"), parent_permissions=0).code, 1)

    def test_malformed_lsm_error_without_losing_dac(self):
        result = report(replace(state(), malformed=("Malformed state",)))
        self.assertEqual(result.diagnosis.code, 0)
        self.assertEqual(result.code, 3)
        self.assertEqual(pa.classify(result).verdict, "error")
        self.assertEqual(jo.process_document(result, ph.__version__)["verdict"], "error")

    def test_malformed_lsm_cannot_poison_denial(self):
        self.assertEqual(report(replace(state(), malformed=("bad",)), permissions=0).code, 1)

    def test_unavailable_state_cannot_prove_permit(self):
        self.assertEqual(report(lsm.LSMState()).code, 3)

    def test_changed_profile_discards_permit(self):
        before = replace(process_with(), lsm=state("unconfined"))
        after = replace(before, lsm=state("p (enforce)"))
        ordinary = evaluate(permissions=4).diagnosis
        with patch.object(ph, "inspect_process", side_effect=[before, after]), \
                patch.object(ph, "diagnose", return_value=ordinary):
            result = ph.diagnose_process("/data/file", 42)
        self.assertEqual(result.code, 3)
        self.assertEqual(result.inspection_kind, "identity_changed")
        self.assertIsNone(result.diagnosis)
        self.assertEqual(pa.classify(result).verdict, "unavailable")

    def test_changed_enforcement_discards_permit(self):
        before = replace(process_with(), lsm=state(enforcing=False))
        after = replace(before, lsm=state(enforcing=True))
        ordinary = evaluate(permissions=4).diagnosis
        with patch.object(ph, "inspect_process", side_effect=[before, after]), \
                patch.object(ph, "diagnose", return_value=ordinary), patch.object(lsm, "inspect_target", side_effect=lambda s, p: s):
            result = ph.diagnose_process("/data/file", 42)
        self.assertEqual(result.inspection_kind, "identity_changed")
        self.assertEqual(result.code, 3)


class ProjectionTests(unittest.TestCase):
    def test_human_section_and_ordinary_result(self):
        text = ph.render_process_report(report(state("nginx (enforce)")))
        self.assertIn("\nLSM\n", text)
        self.assertIn("profile='nginx'", text)
        self.assertIn("RESULT: INDETERMINATE", text)
        self.assertIn("mount result: PERMITTED", text)

    def test_verbose_observation_errors(self):
        text = ph.render_process_report(report(replace(state(), errors=("hidden interface",))), True)
        self.assertIn("hidden interface", text)

    def test_json_additive_schema(self):
        data = json.loads(jo.render_json(jo.process_document(report(state("nginx (enforce)", False)), ph.__version__)))
        self.assertEqual(data["schema_version"], "1")
        self.assertEqual(data["lsm"]["active"], ["apparmor", "selinux"])
        self.assertEqual(data["lsm"]["apparmor"]["profile"], "nginx")
        self.assertEqual(data["lsm"]["apparmor"]["mode"], "enforce")
        self.assertFalse(data["lsm"]["selinux"]["enforcing"])
        self.assertEqual(data["lsm"]["selinux"]["target_context"], "system_u:object_r:data_t:s0")
        self.assertEqual(data["lsm_result"]["status"], "indeterminate")
        self.assertEqual(data["ordinary_verdict"], "permitted")
        self.assertEqual(data["verdict"], "indeterminate")
        self.assertEqual(data["exit_code"], 3)
        self.assertEqual(data["errors"], [])

    def test_process_cli_exit(self):
        with patch.object(ph, "diagnose_process", return_value=report(state("p (enforce)"))), \
                patch.object(ph.sys, "platform", "linux"), contextlib.redirect_stdout(io.StringIO()) as output:
            code = ph.main(["process", "/data/file", "--pid", "42", "--json"])
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(output.getvalue())["lsm_result"]["status"], "indeterminate")

    def test_mixed_audit(self):
        reports = [report(state("unconfined")), report(state("p (enforce)")), report(lsm.LSMState()),
                   report(state(enforcing=False)), report(state(enforcing=True), permissions=0)]
        reports = [replace(r, pid=n + 42) for n, r in enumerate(reports)]
        with patch.object(ph, "inspect_audit_target"), patch.object(pa, "enumerate_pids", return_value=[r.pid for r in reports]), \
                patch.object(ph, "diagnose_process", side_effect=reports):
            audit = pa.audit_processes("/data/file", engine=ph)
        self.assertEqual(audit.summary.permitted, 2)
        self.assertEqual(audit.summary.indeterminate, 2)
        self.assertEqual(audit.summary.denied, 1)
        self.assertEqual(audit.code, 3)
        text = pa.render_audit(audit, engine=ph)
        self.assertIn("unconfined", text)
        self.assertIn("enforce", text)
        self.assertIn("permissive", text)
        self.assertEqual(len(pa.audit_document(audit, ph.__version__)["processes"]), 5)

    def test_policy_expected_allow_unresolved(self):
        result = process_run(report=report(state("p (enforce)")))
        self.assertEqual(result.summary.indeterminate, 1)
        self.assertEqual(result.summary.matches, 0)
        self.assertEqual(result.code, 3)

    def test_policy_expected_deny_unresolved_no_match(self):
        self.assertEqual(process_run("deny", report(state("p (enforce)"))).summary.matches, 0)

    def test_policy_expected_deny_dac_denied_matches(self):
        self.assertEqual(process_run("deny", report(lsm.LSMState(), permissions=0)).summary.matches, 1)

    def test_graph_enforcing_lsm_node(self):
        data = graph.build_process_graph(report(state("p (enforce)")), ph.__version__)
        nodes = [node for node in data.nodes if node.type == "lsm"]
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0].status, "indeterminate")
        self.assertEqual(data.result, "indeterminate")
        self.assertIn("p", graph.serialize_graph_dot(data))

    def test_graph_unconfined(self):
        data = graph.build_process_graph(report(state("unconfined")), ph.__version__)
        self.assertEqual(data.result, "permitted")
        self.assertIn("unconfined", graph.render_terminal_graph(data))

    def test_graph_permissive(self):
        data = graph.build_process_graph(report(state(enforcing=False)), ph.__version__)
        self.assertEqual(data.result, "permitted")
        self.assertIn("permissive", graph.render_terminal_graph(data))

    def test_snapshot_lsm_roundtrip(self):
        capture = processes([report(state("p (enforce)", True))])
        data = json.loads(snap.serialize_snapshot(capture))
        loaded = snap.validate_snapshot(data)
        self.assertEqual(loaded.subjects[0].observation["lsm"]["apparmor"]["profile"], "p")
        self.assertEqual(loaded.code, 3)

    def test_lsm_roundtrip_has_no_spurious_context_diff(self):
        capture = processes([report(state("unconfined"))])
        loaded = snap.validate_snapshot(json.loads(snap.serialize_snapshot(capture)))
        self.assertEqual(snap.diff_snapshots(capture, loaded).code, 0)
        self.assertEqual(jo.process_document(report(state()), ph.__version__)["lsm"]["active"], [])

    def test_snapshot_profile_diff(self):
        before = processes([report(state("a (complain)"))])
        after = processes([report(state("b (complain)"))])
        result = snap.diff_snapshots(before, after)
        self.assertEqual(result.code, 1)
        self.assertIn("lsm", result.changes[0].context_changes)

    def test_snapshot_selinux_context_diff(self):
        before_state = state(enforcing=False)
        after_state = replace(before_state, selinux=replace(before_state.selinux, process_context="u:r:other_t:s0"))
        result = snap.diff_snapshots(processes([report(before_state)]), processes([report(after_state)]))
        self.assertEqual(result.code, 1)
        self.assertTrue(result.changes[0].context_changes)

    def test_snapshot_enforcement_diff(self):
        result = snap.diff_snapshots(processes([report(state(enforcing=False))]), processes([report(state(enforcing=True))]))
        self.assertEqual(result.code, 3)
        self.assertEqual(result.changes[0].change, "became_indeterminate")

    def test_account_models_do_not_inspect_lsm(self):
        from test_audit_rendering import account_result
        from test_permissionhell import SUBJECT
        with patch.object(lsm, "detect_system", side_effect=AssertionError("account LSM lookup")):
            self.assertEqual(account_result(SUBJECT).diagnosis.code, 0)


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux kernel interfaces")
class IntegrationTests(unittest.TestCase):
    def test_current_process_observation_read_only(self):
        with patch.object(os, "setxattr", side_effect=AssertionError("mutation")), \
                patch.object(os, "chmod", side_effect=AssertionError("mutation")), \
                patch.object(os, "kill", side_effect=AssertionError("signal")):
            observed = ps.inspect_process(os.getpid())
        self.assertIsInstance(observed.lsm, lsm.LSMState)
        self.assertIn(lsm.evaluate(observed.lsm, 0).status, ("resolved", "indeterminate", "error"))

    def test_registry_when_available(self):
        try:
            raw = lsm.read_text("/sys/kernel/security/lsm")
        except OSError as exc:
            self.skipTest(f"LSM registry unavailable: {exc}")
        self.assertIsInstance(lsm.parse_active(raw), tuple)

    def test_current_attribute_when_available(self):
        try:
            raw = lsm.read_text("/proc/self/attr/current")
        except OSError as exc:
            self.skipTest(f"Current security attribute unavailable: {exc}")
        self.assertTrue(lsm.clean_label(raw))


if __name__ == "__main__":
    unittest.main()
