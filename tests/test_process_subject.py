"""Deterministic proc snapshots plus shared-engine filesystem identity checks."""

import contextlib
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import json_output as jo
import permissionhell as ph
import process_subject as ps
from test_permissionhell import metadata, MOUNTINFO
from test_posix_acl import make_acl, acl_metadata


STATUS = "Name:\tworker\nUid:\t1000 1001 1002 9000\nGid:\t100 101 102 500\nGroups:\t700 800\nCapEff:\t0000000000000000\n"
PID = 42


def snapshot(status=STATUS):
    parsed = ps.parse_status(status)
    uids = {v for v in (parsed.uids.real, parsed.uids.effective, parsed.uids.saved, parsed.uids.filesystem) if v is not None}
    gids = {v for v in (parsed.gids.real, parsed.gids.effective, parsed.gids.saved, parsed.gids.filesystem,
                       *parsed.supplementary_gids) if v is not None}
    return ps.ProcessSubject(PID, 123, parsed, {u: f"u{u}" for u in uids}, {g: f"g{g}" for g in gids},
                             ps.NamespaceObservation("mnt:[1]", "mnt:[1]", True),
                             ps.NamespaceObservation("user:[2]", "user:[2]", True),
                             ps.RootObservation("/", 1, 2, 1, 2, True, debugger_path="/"),
                             (ps.IDMapEntry(0, 0, 4294967295),), (ps.IDMapEntry(0, 0, 4294967295),))


def proc_text(path):
    if path.endswith("/stat"):
        return "42 (worker with ) name) " + " ".join(["S"] + ["0"] * 18 + ["123"])
    if path.endswith("/status"):
        return STATUS
    if path.endswith("_map"):
        return "0 0 4294967295\n"
    raise AssertionError(path)


def proc_link(path):
    if path.endswith("/root"):
        return "/"
    return "mnt:[1]" if path.endswith("/mnt") else "user:[2]"


class ProcessParsingTests(unittest.TestCase):
    def test_status_ids_and_live_groups(self):
        result = ps.parse_status(STATUS)
        self.assertEqual(result.name, "worker")
        self.assertEqual(result.uids, ps.CredentialIDs(1000, 1001, 1002, 9000))
        self.assertEqual(result.gids, ps.CredentialIDs(100, 101, 102, 500))
        self.assertEqual(result.supplementary_gids, (700, 800))
        self.assertEqual(result.uids.used, 9000)
        self.assertEqual(result.gids.used, 500)

    def test_fallback_ids(self):
        result = ps.parse_status("Uid: 1 2\nGid: 3 4 5\nGroups:\n")
        self.assertEqual(result.uids.used, 2)
        self.assertEqual(result.gids.used, 4)
        self.assertIsNone(result.uids.saved)
        self.assertIsNone(result.name)
        self.assertEqual(result.uids.source, "effective_fallback")

    def test_malformed_status(self):
        for text in ("", "Uid: 1\nGid: 1 1 1 1\nGroups:",
                     STATUS.replace("Groups:\t700 800\n", ""), STATUS + "Uid: 1 1 1 1\n",
                     STATUS.replace("9000", "-1"), STATUS.replace("9000", "4294967295"),
                     STATUS.replace("0000000000000000", "not_hex")):
            with self.subTest(text=text), self.assertRaises(ps.ProcessInspectionError):
                ps.parse_status(text)

    def test_map_parsing(self):
        self.assertEqual(ps.parse_id_map("0 100000 1000\n1000 200000 20\n"),
                         (ps.IDMapEntry(0, 100000, 1000), ps.IDMapEntry(1000, 200000, 20)))
        self.assertEqual(ps.parse_id_map("0 0 4294967295"), (ps.IDMapEntry(0, 0, 4294967295),))
        self.assertEqual(ps.parse_id_map(""), ())

    def test_invalid_maps(self):
        for text in ("0 0", "0 0 0", "0 x 5", "0 0 4294967296", "0 0 10\n5 100 20"):
            with self.subTest(text=text), self.assertRaises(ps.ProcessInspectionError):
                ps.parse_id_map(text)

    def test_complete_snapshot_unknown_names(self):
        with patch.object(ps, "read_text", side_effect=proc_text), patch.object(ps.os, "readlink", side_effect=proc_link), \
                patch.object(ps.os, "stat", return_value=SimpleNamespace(st_dev=1, st_ino=2)), \
                patch.object(ps, "identity_name", return_value=None):
            result = ps.inspect_process(PID)
        self.assertEqual(result.uid_names[9000], None)
        self.assertEqual(result.gid_names[500], None)
        self.assertEqual(result.start_time_ticks, 123)
        self.assertEqual(result.limitations, ())
        subject = ph.process_filesystem_subject(result)
        self.assertEqual((subject.username, subject.uid, subject.primary_group), ("9000", 9000, "500"))

    @unittest.skipUnless(ps.pwd is not None, "Unix account name lookup")
    def test_unknown_nss_identity_is_only_a_missing_label(self):
        with patch.object(ps.pwd, "getpwuid", side_effect=KeyError), patch.object(ps.grp, "getgrgid", side_effect=KeyError):
            self.assertIsNone(ps.identity_name(999999))
            self.assertIsNone(ps.identity_name(999999, group=True))

    def test_nonexistent_pid(self):
        with patch.object(ps, "read_text", side_effect=FileNotFoundError), self.assertRaises(ps.ProcessInspectionError) as error:
            ps.inspect_process(PID)
        self.assertEqual(error.exception.code, 2)

    def test_disappears_mid_read(self):
        with patch.object(ps, "read_text", side_effect=[proc_text("/stat"), FileNotFoundError()]), \
                self.assertRaises(ps.ProcessInspectionError) as error:
            ps.inspect_process(PID)
        self.assertEqual(error.exception.code, 3)
        self.assertIn("disappeared", str(error.exception))

    def test_permission_denied(self):
        with patch.object(ps, "read_text", side_effect=PermissionError("hidden proc")), \
                self.assertRaises(ps.ProcessInspectionError) as error:
            ps.inspect_process(PID)
        self.assertEqual(error.exception.code, 3)

    def test_pid_reused_during_snapshot(self):
        with patch.object(ps, "start_time", side_effect=[123, 124]), patch.object(ps, "read_text", side_effect=proc_text), \
                patch.object(ps, "namespace", return_value=snapshot().mount_namespace), \
                patch.object(ps, "process_root", return_value=snapshot().root), patch.object(ps, "identity_name", return_value=None), \
                self.assertRaisesRegex(ps.ProcessInspectionError, "changed identity"):
            ps.inspect_process(PID)

    def test_fallback_note_is_explicit(self):
        text = STATUS.replace("1000 1001 1002 9000", "1000 1001 1002").replace("100 101 102 500", "100 101 102")
        with patch.object(ps, "start_time", return_value=123), \
                patch.object(ps, "read_text", side_effect=lambda p: text if p.endswith("status") else "0 0 4294967295"), \
                patch.object(ps, "namespace", return_value=snapshot().mount_namespace), \
                patch.object(ps, "process_root", return_value=snapshot().root), patch.object(ps, "identity_name", return_value=None):
            result = ps.inspect_process(PID)
        self.assertIn("fsuid unavailable", result.notes[0])
        self.assertIn("fsgid unavailable", result.notes[1])

    def test_namespace_permission_error_is_unknown(self):
        with patch.object(ps.os, "readlink", side_effect=PermissionError("restricted")):
            result = ps.namespace(PID, "mnt")
        self.assertIsNone(result.matches_debugger)
        self.assertIn("restricted", result.error)

    def test_root_compares_both_path_and_inode(self):
        with patch.object(ps.os, "readlink", side_effect=["/jail", "/"]), \
                patch.object(ps.os, "stat", return_value=SimpleNamespace(st_dev=1, st_ino=2)):
            result = ps.process_root(PID)
        self.assertFalse(result.matches_debugger)
        self.assertEqual(result.path, "/jail")

    def test_root_metadata_denial_is_unknown(self):
        with patch.object(ps.os, "readlink", side_effect=PermissionError("root unavailable")):
            result = ps.process_root(PID)
        self.assertIsNone(result.matches_debugger)
        self.assertIn("root unavailable", result.error)

    def test_map_permission_failure_is_observed_not_a_mapping_guess(self):
        def read(path):
            if path.endswith("_map"):
                raise PermissionError("map hidden")
            return proc_text(path)
        with patch.object(ps, "read_text", side_effect=read), \
                patch.object(ps, "namespace", return_value=snapshot().mount_namespace), \
                patch.object(ps, "process_root", return_value=snapshot().root), patch.object(ps, "identity_name", return_value=None):
            result = ps.inspect_process(PID)
        self.assertIsNone(result.uid_map)
        self.assertIn("observational only", result.notes[0])
        self.assertEqual(result.limitations, ())


class ProcessEvaluationTests(unittest.TestCase):
    def evaluate(self, process=None, *, target_mode=0o600, owner=9000, group=500, acl=None, mode="r"):
        process = process or snapshot()
        def inode_stat(path):
            if path in ("/", "/data"):
                return metadata(0o755, uid=0, gid=0, kind=stat.S_IFDIR)
            if path == "/data/file":
                return acl_metadata(acl, uid=owner, gid=group) if acl else metadata(target_mode, uid=owner, gid=group)
            raise AssertionError(path)
        with patch.object(ph, "inspect_process", return_value=process), \
                patch.object(ph.os, "lstat", side_effect=inode_stat), patch.object(ph.os, "stat", side_effect=inode_stat), \
                patch.object(ph, "read_access_acl", side_effect=lambda p: acl if p == "/data/file" else None), \
                patch.object(ph, "owner_name", side_effect=str), patch.object(ph, "group_name", side_effect=str), \
                patch.object(ph, "read_mounts", return_value=ph.parse_mountinfo(MOUNTINFO)), \
                patch.object(ph, "resolve_subject", side_effect=AssertionError("account resolution")):
            return ph.diagnose_process("/data/file", PID, mode)

    def test_owner_grant_uses_fsuid(self):
        report = self.evaluate()
        self.assertEqual(report.code, 0)
        self.assertEqual(report.diagnosis.subject.uid, 9000)
        self.assertEqual(report.diagnosis.trace.target.decision.permission_class, "OWNER")

    def test_real_uid_ownership_does_not_grant(self):
        report = self.evaluate(owner=1000)
        self.assertEqual(report.code, 1)
        self.assertNotEqual(report.diagnosis.trace.target.decision.permission_class, "OWNER")

    def test_fsgid_grants(self):
        report = self.evaluate(owner=9999, target_mode=0o640)
        self.assertEqual(report.code, 0)
        self.assertEqual(report.diagnosis.subject.primary_gid, 500)

    def test_supplementary_group_grants(self):
        report = self.evaluate(owner=9999, group=800, target_mode=0o640)
        self.assertEqual(report.code, 0)
        self.assertEqual(report.diagnosis.trace.target.decision.permission_class, "GROUP")

    def test_root_fsuid_override(self):
        process = snapshot(STATUS.replace("1000 1001 1002 9000", "1000 1001 1002 0"))
        report = self.evaluate(process, target_mode=0)
        self.assertEqual(report.code, 0)
        self.assertTrue(report.diagnosis.trace.target.decision.root_override)

    def test_root_fsuid_execute_denial(self):
        process = snapshot(STATUS.replace("1000 1001 1002 9000", "1000 1001 1002 0"))
        self.assertEqual(self.evaluate(process, target_mode=0o644, mode="x").code, 1)

    def test_acl_uses_fsuid(self):
        report = self.evaluate(owner=9999, acl=make_acl(users=((9000, 4),), mask=4))
        self.assertEqual(report.code, 0)
        self.assertEqual(report.diagnosis.trace.target.acl_match.selection, "NAMED USER")

    def test_acl_uses_process_groups(self):
        report = self.evaluate(owner=9999, acl=make_acl(groups=((800, 4),), mask=4))
        self.assertEqual(report.code, 0)
        self.assertEqual(report.diagnosis.trace.target.acl_match.selection, "GROUP")

    def test_different_context_never_evaluates_host_inode(self):
        original = snapshot()
        variants = [replace(original, mount_namespace=ps.NamespaceObservation("mnt:[9]", "mnt:[1]", False)),
                    replace(original, user_namespace=ps.NamespaceObservation("user:[9]", "user:[2]", False)),
                    replace(original, root=replace(original.root, path="/jail", matches_debugger=False)),
                    replace(original, mount_namespace=ps.NamespaceObservation(None, None, None, "inaccessible"))]
        for process in variants:
            with self.subTest(process=process), patch.object(ph, "inspect_process", return_value=process), \
                    patch.object(ph, "diagnose", side_effect=AssertionError("unsafe host evaluation")):
                report = ph.diagnose_process("/data/file", PID)
            self.assertEqual(report.code, 3)
            self.assertIsNone(report.diagnosis)
            data = jo.process_document(report, ph.__version__)
            self.assertEqual(data["verdict"], "indeterminate")
            self.assertEqual(data["access_path"], [])
            self.assertTrue(data["limitations"])
            self.assertNotIn("remediations", data)

    def test_revalidation_discards_changed_process(self):
        original = snapshot()
        with patch.object(ph, "inspect_process", side_effect=[original, replace(original, start_time_ticks=999)]), \
                patch.object(ph, "diagnose", return_value=SimpleNamespace(code=ph.ExitCode.ALLOWED)):
            report = ph.diagnose_process("/data/file", PID)
        self.assertEqual(report.code, 3)
        self.assertIsNone(report.diagnosis)

    def test_exit_after_analysis_is_error_not_invalid_input(self):
        with patch.object(ph, "inspect_process", side_effect=[snapshot(), ps.ProcessInspectionError("gone", 2)]), \
                patch.object(ph, "diagnose", return_value=SimpleNamespace(code=ph.ExitCode.ALLOWED)):
            report = ph.diagnose_process("/data/file", PID)
        self.assertEqual(report.code, 3)
        self.assertIsNone(report.diagnosis)

    def test_relative_path_does_not_guess_process_cwd(self):
        with patch.object(ph, "inspect_process") as inspect:
            report = ph.diagnose_process("relative/file", PID)
        self.assertEqual(report.code, 2)
        inspect.assert_not_called()

    def test_process_json(self):
        data = jo.process_document(self.evaluate(), ph.__version__)
        self.assertEqual(data["schema_version"], "1")
        self.assertEqual(data["command"], "process")
        self.assertEqual(data["process"]["credentials"]["uids"]["real"]["id"], 1000)
        self.assertEqual(data["process"]["filesystem_identity"]["uid"], 9000)
        self.assertEqual(data["process"]["filesystem_identity"]["gid"], 500)
        self.assertTrue(data["process"]["namespaces"]["mount"]["matches_debugger"])
        self.assertEqual(data["process"]["uid_map"], [{"inside": 0, "outside": 0, "length": 4294967295}])
        self.assertFalse(data["process"]["maps_used_for_authorization"])
        self.assertEqual(data["subject"]["uid"], 9000)

    def test_human_rendering_and_verbose(self):
        report = self.evaluate()
        text = ph.render_process_report(report)
        self.assertIn("PROCESS DIAGNOSE", text)
        self.assertIn("ruid=1000 euid=1001 suid=1002 fsuid=9000", text)
        self.assertIn("Used for filesystem checks: UID 9000", text)
        self.assertIn("same as debugger", text)
        self.assertIn("RESULT: PERMITTED", text)
        verbose = ph.render_process_report(report, verbose=True)
        self.assertIn("FULL DIAGNOSTIC DETAIL", verbose)
        self.assertIn("UID map (observed only)", verbose)
        self.assertNotIn("account database groups", verbose)

    def test_cli_success_and_denial_codes(self):
        for owner, expected in ((9000, 0), (1000, 1)):
            report = self.evaluate(owner=owner)
            with self.subTest(expected=expected), patch.object(ph.sys, "platform", "linux"), \
                    patch.object(ph, "diagnose_process", return_value=report), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                code = ph.main(["process", "/data/file", "--pid", "42", "--json"])
            self.assertEqual(code, expected)
            self.assertEqual(json.loads(output.getvalue())["exit_code"], expected)


class ProcessCliTests(unittest.TestCase):
    def test_pid_cli_and_json_routing(self):
        report = ph.ProcessDiagnosis("/file", PID, "r", process=snapshot(), limitations=["test context mismatch"])
        with patch.object(ph.sys, "platform", "linux"), patch.object(ph, "diagnose_process", return_value=report) as diagnose, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            code = ph.main(["process", "/file", "--pid", "42", "--json", "--verbose"])
        data = json.loads(output.getvalue())
        self.assertEqual(code, 3)
        self.assertEqual(data["verdict"], "indeterminate")
        diagnose.assert_called_once_with("/file", 42, "r")

    def test_nonexistent_pid_cli(self):
        with patch.object(ph.sys, "platform", "linux"), \
                patch.object(ph, "inspect_process", side_effect=ps.ProcessInspectionError("PID absent", 2)), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            code = ph.main(["process", "/file", "--pid", "42", "--json"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["verdict"], "invalid_input")

    def test_invalid_pid_and_remediation_rejected(self):
        for extra in (["--pid", "0"], ["--pid", "-1"], ["--pid", "abc"], ["--pid", "42", "--suggest-fixes"]):
            with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                ph.main(["process", "/file", *extra])
            self.assertEqual(error.exception.code, 2)

    def test_unsupported_platform_json(self):
        with patch.object(ph.sys, "platform", "win32"), contextlib.redirect_stdout(io.StringIO()) as output:
            code = ph.main(["process", "/file", "--pid", "42", "--json"])
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(output.getvalue())["verdict"], "indeterminate")

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux proc integration")
    def test_current_process_without_credentials_changes(self):
        try:
            process = ps.inspect_process(os.getpid())
        except ps.ProcessInspectionError as exc:
            self.skipTest(f"proc inspection unavailable: {exc}")
        if process.limitations:
            self.skipTest("proc context unavailable: " + "; ".join(process.limitations))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "file"
            path.write_text("fixture")
            with patch("os.kill", side_effect=AssertionError("signal")), \
                    patch("os.setuid", side_effect=AssertionError("credential mutation")), \
                    patch("os.setgid", side_effect=AssertionError("credential mutation")):
                report = ph.diagnose_process(str(path), os.getpid())
            self.assertEqual(report.code, 0, report.limitations)
            self.assertEqual(report.diagnosis.subject.uid, process.status.uids.used)
            result = subprocess.run([sys.executable, ph.__file__, "process", str(path), "--pid", str(os.getpid()), "--json"],
                                    capture_output=True, text=True)
            data = json.loads(result.stdout)
            # ptrace restrictions can deny a child's read of its parent's proc root.
            if data["exit_code"] == 3:
                self.assertEqual(data["verdict"], "indeterminate")
                self.assertTrue(data["limitations"])
            else:
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertEqual(data["verdict"], "permitted")


if __name__ == "__main__":
    unittest.main()
