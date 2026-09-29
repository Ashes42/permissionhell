"""Portable capture, identity-safe offline diff, validation and atomic publication."""
import contextlib
import copy
from dataclasses import replace
from datetime import datetime
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import access_snapshot as snap
import permissionhell as ph
import process_audit as pa
from test_permissionhell import SUBJECT
from test_audit_rendering import account_result, report_for
from test_capabilities import evaluate
from test_idmap import evaluate as mapped_evaluate, foreign
from test_posix_acl import make_acl
from test_process_audit import failed


SYSTEM = {"hostname": "testhost", "kernel": "test-kernel", "architecture": "x86_64", "platform": "linux",
          "boot_id": "boot-one", "pid_namespace": "pid:[1]"}
METADATA = {"device": 1, "inode": 2, "owner_uid": 9000, "group_gid": 500, "mode": "0644",
            "acl_status": "absent", "acl": None,
            "mount": {"point": "/", "filesystem": "ext4", "options": ["rw"], "super_options": ["rw"]}}


def accounts(results=None, **kwargs):
    audit = report_for(results if results is not None else [account_result(SUBJECT, **kwargs)])
    with patch.object(ph, "inspect_audit_target"), patch.object(ph, "audit_target", return_value=audit), \
            patch.object(snap, "target_metadata", return_value=(copy.deepcopy(METADATA), [])), \
            patch.object(snap, "system_context", return_value=copy.deepcopy(SYSTEM)):
        return snap.capture_snapshot("/data/file", audit.mode, engine=ph)


def processes(reports=None):
    reports = reports if reports is not None else [evaluate(permissions=4)]
    audit = pa.ProcessAuditResult("/data/file", entries=[pa.classify(report) for report in reports], discovered=len(reports))
    with patch.object(ph, "inspect_audit_target"), patch.object(pa, "audit_processes", return_value=audit), \
            patch.object(snap, "target_metadata", return_value=(copy.deepcopy(METADATA), [])), \
            patch.object(snap, "system_context", return_value=copy.deepcopy(SYSTEM)):
        return snap.capture_snapshot("/data/file", processes=True, engine=ph)


class CaptureTests(unittest.TestCase):
    def test_account_capture_format(self):
        capture = accounts()
        self.assertEqual(capture.scope, "accounts")
        self.assertEqual(capture.tool_version, ph.__version__)
        self.assertEqual(capture.snapshot_version, 1)
        self.assertEqual(capture.subjects[0].identity, {"uid": 1001, "username": "alice"})
        self.assertEqual(capture.subjects[0].verdict, "permitted")
        self.assertIsNotNone(datetime.fromisoformat(capture.captured_at.replace("Z", "+00:00")).tzinfo)

    def test_process_capture_credentials_and_identity(self):
        capture = processes([evaluate(2)])
        subject = capture.subjects[0]
        self.assertEqual(subject.identity, {"pid": 42, "start_time_ticks": 123})
        self.assertEqual(subject.mechanism, "capability")
        self.assertIn("capabilities", subject.observation["process"])
        self.assertIn("filesystem_identity", subject.observation["process"])
        self.assertIn("user_namespace", subject.observation["process"])

    def test_deterministic_subject_order(self):
        capture = accounts([account_result(replace(SUBJECT, username="z", uid=2000)),
                            account_result(replace(SUBJECT, username="b", uid=1001)), account_result(SUBJECT)])
        self.assertEqual([subject.name for subject in capture.subjects], ["alice", "b", "z"])
        first = evaluate(permissions=4)
        second = replace(first, pid=3, process=replace(first.process, pid=3))
        self.assertEqual([subject.identity["pid"] for subject in processes([first, second]).subjects], [3, 42])

    def test_snapshot_serialization_stable(self):
        capture = accounts()
        self.assertEqual(snap.serialize_snapshot(capture), snap.serialize_snapshot(capture))
        self.assertEqual(snap.snapshot_document(snap.validate_snapshot(json.loads(snap.serialize_snapshot(capture)))), snap.snapshot_document(capture))

    def test_target_metadata_acl_and_mount(self):
        acl = make_acl(owner=6, users=((1001, 4),), mask=4, other=4)
        metadata = os.stat_result((0o100644, 7, 8, 1, 9000, 500, 0, 0, 0, 0))
        mount = ph.parse_mountinfo("24 1 8:1 / / ro,noexec - ext4 /dev/sda1 ro\n")[0]
        with patch.object(snap.os, "stat", return_value=metadata), patch.object(snap.os.path, "realpath", return_value="/resolved"), \
                patch.object(ph, "read_access_acl", return_value=acl) as reader, patch.object(ph, "read_mounts", return_value=[mount]):
            data, errors = snap.target_metadata("/link", ph)
        reader.assert_called_once_with("/resolved")
        self.assertEqual((data["inode"], data["device"]), (7, 8))
        self.assertEqual(data["acl_status"], "present")
        self.assertIn({"tag": "user", "id": 1001, "permissions": 4}, data["acl"])
        self.assertEqual(data["mount"]["options"], ["noexec", "ro"])
        self.assertEqual(errors, [])

    def test_target_acl_unavailable_not_absent(self):
        with tempfile.NamedTemporaryFile() as target, patch.object(ph, "read_access_acl", side_effect=ph.ACLInspectionError("ACL hidden")), \
                patch.object(ph, "read_mounts", side_effect=ph.DiagnosticError("mount hidden")):
            data, errors = snap.target_metadata(target.name, ph)
        self.assertEqual(data["acl_status"], "unavailable")
        self.assertEqual(len(errors), 2)

    def test_target_changes_during_capture_incomplete(self):
        after = {**METADATA, "inode": 99}
        audit = report_for([account_result(SUBJECT)])
        with patch.object(ph, "inspect_audit_target"), patch.object(ph, "audit_target", return_value=audit), \
                patch.object(snap, "system_context", return_value=SYSTEM), \
                patch.object(snap, "target_metadata", side_effect=[(METADATA, []), (after, [])]):
            capture = snap.capture_snapshot("/data/file")
        self.assertEqual(capture.code, 3)
        self.assertIn("changed during capture", capture.capture_errors[0])
        self.assertEqual(capture.target_metadata["inode"], 99)

    def test_transient_process_preserved_incomplete(self):
        capture = processes([failed("exited")])
        self.assertEqual(capture.subjects[0].verdict, "unavailable")
        self.assertIsNone(capture.subjects[0].identity["start_time_ticks"])
        self.assertEqual(capture.code, 3)

    def test_denied_is_complete_capture(self):
        self.assertEqual(accounts(target_mode=0).code, 0)

    def test_invalid_target_and_mode(self):
        for target, mode in (("relative", "r"), ("/file\0", "r"), ("/file", "rw")):
            with self.assertRaises(snap.SnapshotError) as error:
                snap.capture_snapshot(target, mode)
            self.assertEqual(error.exception.code, 2)

    def test_missing_target_refuses_capture(self):
        with patch.object(ph, "inspect_audit_target", side_effect=ph.DiagnosticError("missing", ph.ExitCode.INPUT)), \
                self.assertRaises(snap.SnapshotError) as error:
            snap.capture_snapshot("/missing")
        self.assertEqual(error.exception.code, 2)

    def test_process_capture_does_not_request_command_lines(self):
        audit = pa.ProcessAuditResult("/data/file", entries=[pa.classify(evaluate(permissions=4))])
        with patch.object(ph, "inspect_audit_target"), patch.object(snap, "target_metadata", return_value=(METADATA, [])), \
                patch.object(snap, "system_context", return_value=SYSTEM), patch.object(pa, "audit_processes", return_value=audit) as runner:
            capture = snap.capture_snapshot("/data/file", processes=True)
        self.assertFalse(runner.call_args.kwargs.get("include_cmdline", False))
        self.assertNotIn("cmdline", capture.subjects[0].observation)


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.data = snap.snapshot_document(accounts())

    def test_unsupported_version(self):
        for version in (2, True, "1", None):
            self.data["snapshot_version"] = version
            with self.assertRaises(snap.SnapshotError):
                snap.validate_snapshot(self.data)

    def test_missing_required_fields(self):
        for key in self.data:
            bad = {k: v for k, v in self.data.items() if k != key}
            with self.subTest(key=key), self.assertRaises(snap.SnapshotError):
                snap.validate_snapshot(bad)

    def test_invalid_scope_mode_target_timestamp(self):
        for key, value in (("scope", "all"), ("requested_mode", "rw"), ("target", "relative"),
                           ("captured_at", "yesterday"), ("captured_at", "2026-09-29T12:00:00")):
            with self.subTest(key=key), self.assertRaises(snap.SnapshotError):
                snap.validate_snapshot({**self.data, key: value})

    def test_malformed_subject(self):
        for rows in ({}, [None], [{}], [{**self.data["subjects"][0], "identity": {"username": "alice"}}],
                     [{**self.data["subjects"][0], "verdict": "maybe"}], [self.data["subjects"][0]] * 2):
            with self.subTest(rows=rows), self.assertRaises(snap.SnapshotError):
                snap.validate_snapshot({**self.data, "subjects": rows})

    def test_process_required_identity(self):
        data = snap.snapshot_document(processes())
        for identity in ({"pid": 42}, {"pid": True, "start_time_ticks": 12}, {"pid": 42, "start_time_ticks": -1}):
            data["subjects"][0]["identity"] = identity
            with self.assertRaises(snap.SnapshotError):
                snap.validate_snapshot(data)

    def test_conflicting_observation_identity(self):
        data = snap.snapshot_document(processes())
        data["subjects"][0]["observation"]["process"]["start_time_ticks"] = 321
        with self.assertRaisesRegex(snap.SnapshotError, "Conflicting process"):
            snap.validate_snapshot(data)

    def test_acl_route_validation(self):
        for acl in ([], {}, {"selection": "named_user", "entries": ["bad"]}):
            data = copy.deepcopy(self.data)
            data["subjects"][0]["authorization"][-1]["acl"] = acl
            with self.assertRaises(snap.SnapshotError):
                snap.validate_snapshot(data)

    def test_capture_code_consistency(self):
        self.data["capture_exit_code"] = 3
        with self.assertRaisesRegex(snap.SnapshotError, "Inconsistent"):
            snap.validate_snapshot(self.data)

    def test_malformed_json_no_traceback(self):
        for text in ("{", "null", '[]', '{"snapshot_version":NaN}', '{"x":1,"x":2}', '{"x":1e999}'):
            with patch.object(snap.Path, "read_text", return_value=text), self.assertRaises(snap.SnapshotError):
                snap.load_snapshot("bad.json")

    def test_bad_nested_render_fields_rejected(self):
        data = copy.deepcopy(self.data)
        data["subjects"][0]["observation"]["reasons"] = 42
        with self.assertRaises(snap.SnapshotError):
            snap.validate_snapshot(data)


class FileOutputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / "snapshot.json"
        self.capture = accounts()

    def test_valid_roundtrip(self):
        snap.write_snapshot(self.capture, str(self.output))
        self.assertEqual(snap.snapshot_document(snap.load_snapshot(str(self.output))), snap.snapshot_document(self.capture))
        self.assertEqual(list(Path(self.temp.name).glob(".permissionhell-*")), [])

    def test_existing_refused(self):
        self.output.write_text("old")
        with self.assertRaises(snap.SnapshotError) as error:
            snap.write_snapshot(self.capture, str(self.output))
        self.assertEqual(error.exception.code, 2)
        self.assertEqual(self.output.read_text(), "old")

    def test_force_replaces_regular_file(self):
        self.output.write_text("old")
        snap.write_snapshot(self.capture, str(self.output), force=True)
        self.assertEqual(json.loads(self.output.read_text())["snapshot_version"], 1)

    def test_invalid_destination(self):
        with self.assertRaises(snap.SnapshotError) as error:
            snap.write_snapshot(self.capture, str(self.output / "missing"))
        self.assertEqual(error.exception.code, 2)

    def test_force_failure_preserves_old_file_and_cleans_temp(self):
        self.output.write_text("old")
        with patch.object(snap.os, "replace", side_effect=OSError("interrupted publication")), self.assertRaises(snap.SnapshotError):
            snap.write_snapshot(self.capture, str(self.output), force=True)
        self.assertEqual(self.output.read_text(), "old")
        self.assertEqual(list(Path(self.temp.name).glob(".permissionhell-*")), [])

    def test_no_clobber_race(self):
        original = os.link
        def raced(source, target):
            Path(target).write_text("concurrent writer")
            original(source, target)
        with patch.object(snap.os, "link", side_effect=raced), self.assertRaises(snap.SnapshotError):
            snap.write_snapshot(self.capture, str(self.output))
        self.assertEqual(self.output.read_text(), "concurrent writer")
        self.assertEqual(list(Path(self.temp.name).glob(".permissionhell-*")), [])

    def test_target_cannot_be_output_even_with_force(self):
        self.output.write_text("target contents")
        self.capture.target = str(self.output)
        with self.assertRaises(snap.SnapshotError):
            snap.write_snapshot(self.capture, str(self.output), force=True)
        self.assertEqual(self.output.read_text(), "target contents")

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux links")
    def test_target_hardlink_alias_refused(self):
        target = Path(self.temp.name) / "target"
        target.write_text("contents")
        os.link(target, self.output)
        self.capture.target = str(target)
        with self.assertRaises(snap.SnapshotError):
            snap.write_snapshot(self.capture, str(self.output), force=True)
        self.assertEqual(target.read_text(), "contents")

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux symlinks")
    def test_force_symlink_refused(self):
        target = Path(self.temp.name) / "target"
        target.write_text("contents")
        self.output.symlink_to(target)
        with self.assertRaises(snap.SnapshotError):
            snap.write_snapshot(self.capture, str(self.output), force=True)
        self.assertEqual(target.read_text(), "contents")

    def test_fsync_failure_does_not_publish(self):
        with patch.object(snap.os, "fsync", side_effect=OSError("disk error")), self.assertRaises(snap.SnapshotError):
            snap.write_snapshot(self.capture, str(self.output))
        self.assertFalse(self.output.exists())
        self.assertEqual(list(Path(self.temp.name).iterdir()), [])

    def test_incomplete_capture_saved_with_status(self):
        capture = processes([failed("exited")])
        snap.write_snapshot(capture, str(self.output))
        loaded = snap.load_snapshot(str(self.output))
        self.assertEqual(loaded.code, 3)
        self.assertEqual(loaded.subjects[0].verdict, "unavailable")


class AccountDiffTests(unittest.TestCase):
    def test_unchanged_permit(self):
        before = accounts()
        diff = snap.diff_snapshots(before, copy.deepcopy(before))
        self.assertEqual(diff.summary["unchanged_permitted"], 1)
        self.assertEqual(diff.code, 0)

    def test_unchanged_deny(self):
        before = accounts(target_mode=0)
        self.assertEqual(snap.diff_snapshots(before, copy.deepcopy(before)).summary["unchanged_denied"], 1)

    def test_gained_access(self):
        diff = snap.diff_snapshots(accounts(target_mode=0o600), accounts())
        self.assertEqual(diff.summary["gained_access"], 1)
        self.assertEqual(diff.code, 1)

    def test_lost_access_with_parent_blocker(self):
        diff = snap.diff_snapshots(accounts(), accounts(parent_mode=0))
        self.assertEqual(diff.summary["lost_access"], 1)
        self.assertIn("blocker: '/data'", snap.render_diff(diff, ph.__version__))

    def test_added_removed(self):
        before = accounts()
        after = accounts([account_result(replace(SUBJECT, username="bob", uid=2000))])
        diff = snap.diff_snapshots(before, after)
        self.assertEqual((diff.summary["subject_added"], diff.summary["subject_removed"]), (1, 1))

    def test_name_rename_conservative(self):
        diff = snap.diff_snapshots(accounts(), accounts([account_result(replace(SUBJECT, username="renamed"))]))
        self.assertEqual(diff.summary["gained_access"], 0)
        self.assertEqual(diff.summary["subject_added"], 1)
        self.assertTrue(any("rename" in warning for warning in diff.warnings))

    def test_uid_reassignment_conservative(self):
        diff = snap.diff_snapshots(accounts(), accounts([account_result(replace(SUBJECT, uid=2000))]))
        self.assertEqual(diff.summary["lost_access"], 0)
        self.assertEqual(diff.summary["subject_removed"], 1)

    def test_mechanism_change_not_access_gain(self):
        diff = snap.diff_snapshots(accounts(acl=make_acl(users=((1001, 4),), mask=4)), accounts())
        self.assertEqual(diff.summary["mechanism_changed"], 1)
        self.assertEqual(diff.summary["unchanged_permitted"], 1)
        self.assertEqual(diff.summary["gained_access"], 0)
        self.assertIn("MECHANISM_CHANGED", snap.render_diff(diff, ph.__version__))

    def test_group_membership_context_change(self):
        diff = snap.diff_snapshots(accounts(), accounts([account_result(replace(SUBJECT, supplementary_gids=(300,), supplementary_groups=("new",)))]))
        self.assertEqual(diff.summary["subject_metadata_changed"], 1)
        self.assertEqual(diff.code, 1)

    def test_timestamp_and_tool_version_only_ignored(self):
        before = accounts()
        after = copy.deepcopy(before)
        after.captured_at = "2027-01-01T00:00:00Z"
        after.tool_version = "1.3.1"
        self.assertEqual(snap.diff_snapshots(before, after).code, 0)

    def test_cross_host_accounts_warn_but_compare(self):
        before = accounts(target_mode=0)
        after = accounts()
        after.system["hostname"] = "another-host"
        diff = snap.diff_snapshots(before, after)
        self.assertEqual(diff.summary["gained_access"], 1)
        self.assertTrue(any("Different hosts" in warning for warning in diff.warnings))


class ProcessDiffTests(unittest.TestCase):
    def test_same_pid_start_matches(self):
        before = processes()
        self.assertEqual(snap.diff_snapshots(before, copy.deepcopy(before)).summary["unchanged_permitted"], 1)

    def test_pid_reuse_is_remove_add(self):
        before = processes()
        after = copy.deepcopy(before)
        after.subjects[0].identity["start_time_ticks"] = 999
        after.subjects[0].observation["process"]["start_time_ticks"] = 999
        diff = snap.diff_snapshots(before, after)
        self.assertEqual(diff.summary["subject_added"], 1)
        self.assertEqual(diff.summary["subject_removed"], 1)
        self.assertEqual(diff.summary["gained_access"], 0)

    def test_process_removed_added(self):
        before = processes()
        empty = copy.deepcopy(before)
        empty.subjects = []
        self.assertEqual(snap.diff_snapshots(before, empty).summary["subject_removed"], 1)
        self.assertEqual(snap.diff_snapshots(empty, before).summary["subject_added"], 1)

    def test_process_gained_and_lost(self):
        before, after = processes([evaluate()]), processes([evaluate(permissions=4)])
        self.assertEqual(snap.diff_snapshots(before, after).summary["gained_access"], 1)
        self.assertEqual(snap.diff_snapshots(after, before).summary["lost_access"], 1)

    def test_became_indeterminate_and_resolved(self):
        known = processes()
        unknown = processes([mapped_evaluate(foreign(capability=2))])
        self.assertEqual(snap.diff_snapshots(known, unknown).summary["became_indeterminate"], 1)
        self.assertEqual(snap.diff_snapshots(unknown, known).summary["resolved_from_indeterminate"], 1)
        self.assertEqual(snap.diff_snapshots(unknown, known).code, 3)

    def test_capability_mechanism_change(self):
        before = processes([evaluate(acl=make_acl(users=((9000, 4),), mask=4))])
        after = processes([evaluate(2)])
        diff = snap.diff_snapshots(before, after)
        self.assertEqual(diff.summary["mechanism_changed"], 1)
        self.assertEqual(diff.summary["unchanged_permitted"], 1)
        self.assertIn("CAP_DAC_OVERRIDE", snap.render_diff(diff, ph.__version__))

    def test_cross_host_boot_namespace_never_match(self):
        before = processes()
        for field in ("hostname", "boot_id", "pid_namespace"):
            after = copy.deepcopy(before)
            after.system[field] = "different"
            diff = snap.diff_snapshots(before, after)
            self.assertEqual(diff.summary["subject_added"], 1)
            self.assertEqual(diff.summary["subject_removed"], 1)

    def test_missing_context_incomplete(self):
        before = processes()
        after = copy.deepcopy(before)
        after.system["boot_id"] = None
        self.assertEqual(snap.diff_snapshots(before, after).code, 3)

    def test_missing_start_time_no_pid_only_match(self):
        before = processes([failed("exited")])
        diff = snap.diff_snapshots(before, copy.deepcopy(before))
        self.assertEqual(diff.summary["subject_removed"], 1)
        self.assertEqual(diff.summary["subject_added"], 1)
        self.assertEqual(diff.code, 3)


class TargetAndOutputTests(unittest.TestCase):
    def test_target_metadata_changes(self):
        before = accounts()
        for field, value in (("mode", "0640"), ("owner_uid", 23), ("group_gid", 24), ("inode", 99), ("device", 10),
                             ("acl", [{"tag": "user", "id": 44, "permissions": 4}]),
                             ("mount", {**METADATA["mount"], "options": ["noexec", "ro"]})):
            after = copy.deepcopy(before)
            after.target_metadata[field] = value
            diff = snap.diff_snapshots(before, after)
            self.assertIn(field, diff.target_changes)
            self.assertEqual(diff.code, 1)

    def test_inode_identity_warning(self):
        before = accounts()
        after = copy.deepcopy(before)
        after.target_metadata["inode"] = 99
        self.assertIn("TARGET_CHANGED", snap.render_diff(snap.diff_snapshots(before, after), ph.__version__))

    def test_cross_scope_mode_target_rejected(self):
        before = accounts()
        for field, value in (("scope", "processes"), ("requested_mode", "w"), ("target", "/another")):
            after = copy.deepcopy(before)
            setattr(after, field, value)
            with self.assertRaises(snap.SnapshotError):
                snap.diff_snapshots(before, after)

    def test_unchanged_hidden_default_verbose_expands(self):
        before = accounts()
        diff = snap.diff_snapshots(before, copy.deepcopy(before))
        self.assertNotIn("'alice'", snap.render_diff(diff, ph.__version__))
        self.assertIn("'alice'", snap.render_diff(diff, ph.__version__, verbose=True))

    def test_json_all_individual_comparisons(self):
        before = accounts([account_result(SUBJECT), account_result(replace(SUBJECT, username="bob", uid=9999))])
        data = json.loads(json_output_text(snap.diff_document(snap.diff_snapshots(before, copy.deepcopy(before)), ph.__version__)))
        self.assertEqual(data["schema_version"], "1")
        self.assertEqual(data["command"], "diff")
        self.assertEqual(len(data["changes"]), 2)

    def test_human_capture_does_not_dump_snapshot(self):
        text = snap.render_capture(accounts(), "before.json")
        self.assertIn("Subjects captured: 1", text)
        self.assertIn("Output: 'before.json'", text)
        self.assertNotIn("authorization", text)

    def test_cli_stdout_snapshot_json(self):
        with patch.object(ph.sys, "platform", "linux"), patch.object(snap, "capture_snapshot", return_value=accounts()), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(ph.main(["snapshot", "/data/file"]), 0)
        self.assertEqual(json.loads(output.getvalue())["snapshot_version"], 1)

    def test_offline_diff_does_not_require_linux_or_engine(self):
        before = accounts()
        with patch.object(ph.sys, "platform", "win32"), patch.object(snap, "load_snapshot", return_value=before), \
                patch.object(ph, "diagnose", side_effect=AssertionError("live evaluation")), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(ph.main(["diff", "a.json", "b.json", "--json"]), 0)
        self.assertEqual(json.loads(output.getvalue())["command"], "diff")

    def test_cli_invalid_snapshot_input(self):
        with patch.object(snap.Path, "read_text", return_value="{bad"), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(ph.main(["diff", "a.json", "b.json", "--json"]), 2)
        self.assertEqual(json.loads(output.getvalue())["exit_code"], 2)

    def test_cli_output_acknowledgement_and_exit(self):
        capture = accounts()
        with patch.object(ph.sys, "platform", "linux"), patch.object(snap, "capture_snapshot", return_value=capture), \
                patch.object(snap, "write_snapshot") as writer, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(ph.main(["snapshot", "/data/file", "--output", "before.json", "--force"]), 0)
        writer.assert_called_once_with(capture, "before.json", force=True)
        self.assertIn("Output: 'before.json'", output.getvalue())

    def test_cli_force_requires_output_and_empty_output_rejected(self):
        for options in (["--force"], ["--output", ""]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                ph.main(["snapshot", "/data/file", *options])
            self.assertEqual(error.exception.code, 2)

    def test_cli_process_scope_and_partial_status(self):
        with patch.object(ph.sys, "platform", "linux"), patch.object(snap, "capture_snapshot", return_value=processes([failed("exited")])) as capture, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(ph.main(["snapshot", "/data/file", "--processes"]), 3)
        self.assertTrue(capture.call_args.kwargs["processes"])
        self.assertEqual(json.loads(output.getvalue())["capture_exit_code"], 3)


def json_output_text(data):
    return json.dumps(data, ensure_ascii=True)


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux snapshot integration")
class IntegrationTests(unittest.TestCase):
    def test_temp_permissions_before_after_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o755)
            target = Path(directory) / "resource"
            target.write_text("fixture data never read by snapshot capture")
            target.chmod(0o600)
            before = snap.capture_snapshot(str(target))
            target.chmod(0o644)
            after = snap.capture_snapshot(str(target))
            first, second = Path(directory) / "before.json", Path(directory) / "after.json"
            snap.write_snapshot(before, str(first))
            snap.write_snapshot(after, str(second))
            diff = snap.diff_snapshots(snap.load_snapshot(str(first)), snap.load_snapshot(str(second)))
        self.assertEqual(diff.target_changes["mode"], {"before": "0600", "after": "0644"})
        expected_gained = sum(left.verdict == "denied" and right.verdict == "permitted"
                              for left, right in zip(before.subjects, after.subjects))
        self.assertEqual(diff.summary["gained_access"], expected_gained)
        self.assertIn(diff.code, (1, 3))

    def test_process_capture_current_pid_included(self):
        with tempfile.NamedTemporaryFile() as target:
            capture = snap.capture_snapshot(target.name, processes=True)
        self.assertIn(os.getpid(), [subject.identity["pid"] for subject in capture.subjects])
        snap.validate_snapshot(json.loads(snap.serialize_snapshot(capture)))
