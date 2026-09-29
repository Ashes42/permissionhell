"""One-shot monitor orchestration, file safety, presentation and live integration."""
import contextlib
import copy
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import access_monitor as monitor
import access_snapshot as snap
import permissionhell as ph
from test_access_snapshot import accounts, processes
from test_capabilities import evaluate
from test_idmap import evaluate as mapped_evaluate, foreign
from test_process_audit import failed
from test_lsm import report, state


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / "baseline.json")
        self.before = accounts()

    def save(self, before=None):
        snap.write_snapshot(before or self.before, self.path, force=True)

    def check(self, current=None, before=None, **kwargs):
        self.save(before)
        with patch.object(snap, "capture_snapshot", return_value=current or self.before):
            return monitor.check("/data/file", self.path, **kwargs)

    def cli(self, command, *flags, current=None):
        with patch.object(ph.sys, "platform", "linux"), patch.object(snap, "capture_snapshot", return_value=current or self.before), \
                contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            code = ph.main([command, "/data/file", "--baseline", self.path, *flags])
        return code, out.getvalue(), err.getvalue()

    def test_init_account_snapshot(self):
        code, text, _ = self.cli("monitor-init")
        self.assertEqual(code, 0)
        self.assertIn("MONITOR BASELINE", text)
        self.assertEqual(snap.load_snapshot(self.path).scope, "accounts")

    def test_init_process_snapshot(self):
        code, _, _ = self.cli("monitor-init", "--processes", current=processes())
        self.assertEqual(code, 0)
        self.assertEqual(snap.load_snapshot(self.path).scope, "processes")

    def test_init_refuses_existing(self):
        self.save()
        previous = Path(self.path).read_bytes()
        self.assertEqual(self.cli("monitor-init")[0], 2)
        self.assertEqual(Path(self.path).read_bytes(), previous)

    def test_init_force(self):
        self.save()
        current = accounts(target_mode=0)
        self.assertEqual(self.cli("monitor-init", "--force", current=current)[0], 0)
        self.assertEqual(snap.load_snapshot(self.path).subjects[0].verdict, "denied")

    def test_init_incomplete_not_written(self):
        current = processes([failed("exited")])
        code, text, _ = self.cli("monitor-init", "--processes", current=current)
        self.assertEqual(code, 3)
        self.assertFalse(Path(self.path).exists())
        self.assertIn("baseline not written", text)

    def test_incomplete_force_preserves_old(self):
        self.save()
        previous = Path(self.path).read_bytes()
        self.assertEqual(self.cli("monitor-init", "--force", current=processes([failed("exited")]))[0], 3)
        self.assertEqual(Path(self.path).read_bytes(), previous)

    def test_init_json(self):
        code, text, _ = self.cli("monitor-init", "--json")
        data = json.loads(text)
        self.assertEqual(code, 0)
        self.assertTrue(data["baseline_created"])
        snap.validate_snapshot(data["snapshot"])

    def test_target_collision(self):
        with self.assertRaises(snap.SnapshotError):
            monitor.initialize(self.path, self.path)

    def test_hardlink_collision(self):
        self.save()
        target = str(Path(self.tmp.name) / "target")
        os.link(self.path, target)
        with self.assertRaisesRegex(snap.SnapshotError, "alias"):
            monitor.check(target, self.path)

    def test_symlink_collision(self):
        self.save()
        target = str(Path(self.tmp.name) / "target")
        os.symlink(self.path, target)
        with self.assertRaisesRegex(snap.SnapshotError, "alias"):
            monitor.initialize(target, self.path, force=True)

    def test_force_symlink_output_refused(self):
        other = Path(self.tmp.name) / "other"
        other.write_text("preserve")
        os.symlink(other, self.path)
        self.assertEqual(self.cli("monitor-init", "--force")[0], 2)
        self.assertEqual(other.read_text(), "preserve")

    def test_invalid_empty_baseline(self):
        with self.assertRaises(snap.SnapshotError):
            monitor.initialize("/data/file", "")

    def test_relative_target_rejected(self):
        with self.assertRaises(snap.SnapshotError):
            monitor.check("relative", self.path)

    def test_no_change_permit(self):
        self.assertEqual(self.check().code, 0)

    def test_no_change_deny(self):
        denied = accounts(target_mode=0)
        self.assertEqual(self.check(denied, denied).code, 0)

    def test_gained(self):
        result = self.check(before=accounts(target_mode=0))
        self.assertEqual(result.code, 1)
        self.assertEqual(result.comparison.summary["gained_access"], 1)

    def test_lost(self):
        result = self.check(accounts(target_mode=0))
        self.assertEqual(result.code, 1)
        self.assertEqual(result.comparison.summary["lost_access"], 1)

    def test_mechanism_changed(self):
        current = copy.deepcopy(self.before)
        current.subjects[0].mechanism = "posix_acl"
        result = self.check(current)
        self.assertEqual(result.code, 1)
        self.assertEqual(result.comparison.summary["mechanism_changed"], 1)

    def test_target_metadata_changes(self):
        for key, value in (("mode", "0600"), ("owner_uid", 55), ("group_gid", 56), ("acl", []),
                           ("mount", {"point": "/", "filesystem": "ext4", "options": ["ro"], "super_options": ["ro"]}),
                           ("inode", 123), ("device", 456)):
            current = copy.deepcopy(self.before)
            current.target_metadata[key] = value
            with self.subTest(key=key):
                self.assertEqual(self.check(current).code, 1)

    def test_malformed_baseline(self):
        Path(self.path).write_text("{bad")
        self.assertEqual(self.cli("monitor-check", "--update-baseline")[0], 2)
        self.assertEqual(Path(self.path).read_text(), "{bad")

    def test_unsupported_version(self):
        data = snap.snapshot_document(self.before)
        data["snapshot_version"] = 999
        Path(self.path).write_text(json.dumps(data))
        self.assertEqual(self.cli("monitor-check")[0], 2)

    def test_incompatible_scope(self):
        self.save()
        self.assertEqual(self.cli("monitor-check", "--processes")[0], 2)

    def test_incompatible_mode(self):
        self.save()
        self.assertEqual(self.cli("monitor-check", "--mode", "w")[0], 2)

    def test_incompatible_target_before_capture(self):
        self.save()
        with patch.object(snap, "capture_snapshot") as capture, self.assertRaises(snap.SnapshotError):
            monitor.check("/other", self.path)
        capture.assert_not_called()

    def test_mode_scope_inherited(self):
        before = replace(processes([evaluate(permissions=2, mode="w")]), requested_mode="w")
        self.save(before)
        with patch.object(snap, "capture_snapshot", return_value=before) as capture:
            monitor.check("/data/file", self.path)
        self.assertEqual(capture.call_args.args, ("/data/file", "w"))
        self.assertTrue(capture.call_args.kwargs["processes"])

    def test_check_no_implicit_update(self):
        self.save()
        previous = Path(self.path).read_bytes()
        self.assertEqual(self.cli("monitor-check", current=accounts(target_mode=0))[0], 1)
        self.assertEqual(Path(self.path).read_bytes(), previous)

    def test_explicit_update_then_no_change(self):
        self.save()
        current = accounts(target_mode=0)
        code, text, _ = self.cli("monitor-check", "--update-baseline", current=current)
        self.assertEqual(code, 1)
        self.assertIn("LOST_ACCESS", text)
        self.assertIn("updated atomically", text)
        self.assertEqual(self.cli("monitor-check", current=current)[0], 0)

    def test_no_change_explicit_update(self):
        self.save()
        current = replace(self.before, captured_at="2026-09-30T12:00:00Z")
        self.assertEqual(self.cli("monitor-check", "--update-baseline", current=current)[0], 0)
        self.assertEqual(snap.load_snapshot(self.path).captured_at, current.captured_at)

    def test_no_update_on_incomplete(self):
        before = processes()
        self.save(before)
        previous = Path(self.path).read_bytes()
        code, text, _ = self.cli("monitor-check", "--update-baseline", current=processes([failed("exited")]))
        self.assertEqual(code, 3)
        self.assertEqual(Path(self.path).read_bytes(), previous)
        self.assertIn("not performed", text)

    def test_atomic_replace_failure_preserves_baseline(self):
        result = self.check(accounts(target_mode=0))
        previous = Path(self.path).read_bytes()
        with patch.object(snap.os, "replace", side_effect=OSError("replace failed")):
            monitor.update_baseline(result)
        self.assertFalse(result.baseline_updated)
        self.assertEqual(result.code, 3)
        self.assertEqual(Path(self.path).read_bytes(), previous)
        self.assertEqual(list(Path(self.tmp.name).glob(".permissionhell-*")), [])

    def test_json_update_flag(self):
        self.save()
        code, text, _ = self.cli("monitor-check", "--json", "--update-baseline")
        data = json.loads(text)
        self.assertEqual(code, 0)
        self.assertTrue(data["baseline_updated"])
        self.assertEqual(data["baseline"]["path"], self.path)
        self.assertIn("captured_at", data["baseline"])
        self.assertIn("captured_at", data["current"])
        self.assertIsInstance(data["changes"], list)
        self.assertIn("summary", data)
        self.assertEqual(data["schema_version"], "1")

    def test_json_failed_update_retains_comparison(self):
        self.save()
        with patch.object(snap.os, "replace", side_effect=OSError("failure")):
            code, text, _ = self.cli("monitor-check", "--json", "--update-baseline", current=accounts(target_mode=0))
        data = json.loads(text)
        self.assertEqual(code, 3)
        self.assertFalse(data["baseline_updated"])
        self.assertEqual(data["summary"]["lost_access"], 1)
        self.assertTrue(data["errors"])

    def test_human_report_before_write(self):
        self.save()
        output = io.StringIO()
        def writer(*args, **kwargs):
            self.assertIn("LOST_ACCESS", output.getvalue())
        with patch.object(snap, "capture_snapshot", return_value=accounts(target_mode=0)), \
                patch.object(snap, "write_snapshot", side_effect=writer), contextlib.redirect_stdout(output):
            self.assertEqual(ph.main(["monitor-check", "/data/file", "--baseline", self.path, "--update-baseline"]), 1)

    def test_no_change_output(self):
        text = monitor.render_check(self.check(), ph.__version__)
        self.assertIn("No meaningful access changes since baseline.", text)
        self.assertNotIn("UNCHANGED_PERMITTED", text)

    def test_verbose_contains_unchanged_reasoning(self):
        text = monitor.render_check(self.check(), ph.__version__, verbose=True)
        self.assertIn("UNCHANGED_PERMITTED", text)
        self.assertIn("Full comparison", text)

    def test_target_identity_warning(self):
        current = copy.deepcopy(self.before)
        current.target_metadata["inode"] = 99
        self.assertIn("TARGET_CHANGED", monitor.render_check(self.check(current), ph.__version__))

    def test_process_gained(self):
        result = self.check(processes([evaluate(permissions=4)]), processes([evaluate()]))
        self.assertEqual(result.code, 1)
        self.assertEqual(result.comparison.summary["gained_access"], 1)

    def test_process_lost(self):
        result = self.check(processes([evaluate()]), processes([evaluate(permissions=4)]))
        self.assertEqual(result.code, 1)
        self.assertEqual(result.comparison.summary["lost_access"], 1)

    def test_pid_reuse_is_churn(self):
        observed = evaluate(permissions=4)
        changed = replace(observed, process=replace(observed.process, start_time_ticks=999))
        result = self.check(processes([changed]), processes([observed]))
        self.assertEqual(result.comparison.summary["subject_added"], 1)
        self.assertEqual(result.comparison.summary["subject_removed"], 1)
        self.assertEqual(result.comparison.summary["gained_access"], 0)
        self.assertEqual(result.code, 1)

    def test_churn_filter_only_hides_text(self):
        observed = evaluate(permissions=4)
        added = replace(observed, pid=43, process=replace(observed.process, pid=43))
        result = self.check(processes([observed, added]), processes([observed]))
        text = monitor.render_check(result, ph.__version__, ignore_process_churn=True)
        self.assertNotIn("SUBJECT_ADDED", text)
        self.assertIn("1 process additions/removals hidden", text)
        self.assertEqual(len(monitor.document(result, ph.__version__)["changes"]), 2)
        self.assertEqual(result.code, 1)

    def test_process_removed(self):
        result = self.check(processes([]), processes([evaluate(permissions=4)]))
        self.assertEqual(result.comparison.summary["subject_removed"], 1)

    def test_namespace_uncertainty(self):
        current = processes([mapped_evaluate(foreign(capability=2))])
        self.assertEqual(self.check(current, processes()).code, 3)

    def test_lsm_uncertainty(self):
        result = self.check(processes([report(state("p (enforce)"))]), processes([report(state("unconfined"))]))
        self.assertEqual(result.code, 3)
        self.assertEqual(result.comparison.summary["became_indeterminate"], 1)

    def test_apparmor_profile_change(self):
        result = self.check(processes([report(state("b (complain)"))]), processes([report(state("a (complain)"))]))
        self.assertEqual(result.code, 1)
        self.assertIn("lsm", result.comparison.changes[0].context_changes)

    def test_selinux_enforcement_change(self):
        self.assertEqual(self.check(processes([report(state(enforcing=True))]), processes([report(state(enforcing=False))])).code, 3)

    def test_unsupported_platform(self):
        with patch.object(ph.sys, "platform", "win32"), contextlib.redirect_stdout(io.StringIO()) as output:
            code = ph.main(["monitor-check", "/file", "--baseline", self.path, "--json"])
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(output.getvalue())["command"], "monitor-check")

    def test_current_capture_disappears_no_update(self):
        self.save()
        previous = Path(self.path).read_bytes()
        with patch.object(snap, "capture_snapshot", side_effect=snap.SnapshotError("target disappeared", 2)), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            code = ph.main(["monitor-check", "/data/file", "--baseline", self.path, "--update-baseline", "--json"])
        self.assertEqual(code, 3)
        self.assertFalse(json.loads(output.getvalue())["baseline_updated"])
        self.assertEqual(Path(self.path).read_bytes(), previous)

    def test_invalid_baseline_does_not_capture(self):
        Path(self.path).write_text("bad")
        with patch.object(snap, "capture_snapshot") as capture, self.assertRaises(snap.SnapshotError):
            monitor.check("/data/file", self.path)
        capture.assert_not_called()

    def test_incomplete_old_baseline_not_updated(self):
        before = processes([failed("exited")])
        result = self.check(processes(), before)
        old = Path(self.path).read_bytes()
        monitor.update_baseline(result)
        self.assertEqual(result.code, 3)
        self.assertFalse(result.baseline_updated)
        self.assertEqual(Path(self.path).read_bytes(), old)

    def test_selinux_context_change(self):
        before = state(enforcing=False)
        after = replace(before, selinux=replace(before.selinux, process_context="u:r:other_t:s0"))
        result = self.check(processes([report(after)]), processes([report(before)]))
        self.assertEqual(result.code, 1)
        self.assertTrue(result.comparison.changes[0].context_changes)

    def test_fsync_failure_cannot_replace(self):
        result = self.check(accounts(target_mode=0))
        old = Path(self.path).read_bytes()
        with patch.object(snap.os, "fsync", side_effect=OSError("sync failed")):
            monitor.update_baseline(result)
        self.assertEqual(result.code, 3)
        self.assertFalse(result.baseline_updated)
        self.assertEqual(Path(self.path).read_bytes(), old)

    def test_successful_replacement_is_atomic(self):
        result = self.check(accounts(target_mode=0))
        real_replace = os.replace
        with patch.object(snap.os, "replace", wraps=real_replace) as replace_file:
            monitor.update_baseline(result)
        replace_file.assert_called_once()
        self.assertEqual(replace_file.call_args.args[1], os.path.abspath(self.path))
        self.assertTrue(result.baseline_updated)

    def test_filter_keeps_gained_and_all_json(self):
        denied = evaluate()
        allowed = evaluate(permissions=4)
        added = replace(allowed, pid=43, process=replace(allowed.process, pid=43))
        result = self.check(processes([allowed, added]), processes([denied]))
        text = monitor.render_check(result, ph.__version__, ignore_process_churn=True)
        self.assertIn("GAINED_ACCESS", text)
        self.assertNotIn("SUBJECT_ADDED", text)
        self.assertEqual(len(monitor.document(result, ph.__version__)["changes"]), 2)

    def test_verbose_overrides_churn_filter(self):
        result = self.check(processes([]), processes())
        text = monitor.render_check(result, ph.__version__, verbose=True, ignore_process_churn=True)
        self.assertIn("SUBJECT_REMOVED", text)
        self.assertIn("start_time_ticks", text)

    def test_target_metadata_precedes_churn(self):
        before = processes()
        current = processes([])
        current.target_metadata["inode"] = 123
        text = monitor.render_check(self.check(current, before), ph.__version__)
        self.assertLess(text.index("TARGET METADATA CHANGES"), text.index("SUBJECT_REMOVED"))


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux monitoring integration")
class IntegrationTests(unittest.TestCase):
    def test_real_account_baseline_change_update(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o755)
            target = Path(directory) / "resource"
            baseline = str(Path(directory) / "baseline.json")
            target.write_text("test-owned fixture")
            target.chmod(0o600)
            before = monitor.initialize(str(target), baseline)
            self.assertEqual(before.code, 0)
            target.chmod(0o644)
            result = monitor.check(str(target), baseline)
            self.assertEqual(result.code, 1)
            self.assertGreater(result.comparison.summary["gained_access"], 0)
            monitor.update_baseline(result)
            self.assertTrue(result.baseline_updated)
            self.assertEqual(monitor.check(str(target), baseline).code, 0)
            self.assertEqual(target.read_text(), "test-owned fixture")
            self.assertEqual(target.stat().st_mode & 0o777, 0o644)


if __name__ == "__main__":
    unittest.main()
