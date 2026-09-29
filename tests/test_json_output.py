"""Public schema and CLI contracts; serialization must never reevaluate access."""

import contextlib
import copy
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

import json_output as jo
import permissionhell as ph
from test_audit_rendering import account_result, ordinary_accounts, report_for
from test_permissionhell import ROOT
from test_posix_acl import make_acl


class DiagnosisJsonTests(unittest.TestCase):
    def setUp(self):
        self.subject = ordinary_accounts(1)[0]

    def document(self, subject=None, **kwargs):
        diagnosis = account_result(subject or self.subject, **kwargs).diagnosis
        before = copy.deepcopy(diagnosis)
        result = jo.diagnosis_document(diagnosis, ph.__version__)
        self.assertEqual(diagnosis, before)
        return result

    def test_permitted_and_metadata(self):
        result = self.document()
        self.assertEqual(result["schema_version"], "1")
        self.assertEqual(result["tool"], {"name": "permissionhell", "version": ph.__version__})
        self.assertEqual(result["command"], "diagnose")
        self.assertEqual(result["requested_mode"], "r")
        self.assertEqual(result["target_path"], "/data/file")
        self.assertEqual(result["resolved_target_path"], "/data/file")
        self.assertEqual(result["verdict"], "permitted")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["subject"]["uid"], self.subject.uid)
        self.assertEqual(result["target_inode"]["mode"]["octal"], "0644")

    def test_target_denied(self):
        result = self.document(target_mode=0o600)
        self.assertEqual(result["verdict"], "denied")
        self.assertEqual(result["exit_code"], 1)
        self.assertEqual(result["first_blocker"], {"stage": "target", "path": "/data/file", "mechanism": "unix_dac"})
        self.assertTrue(result["target_inode"]["blocker"])
        self.assertEqual(result["target_inode"]["effective_permissions"]["bits"], 0)

    def test_parent_blocker(self):
        result = self.document(parent_mode=0o700)
        self.assertEqual(result["first_blocker"]["path"], "/data")
        self.assertEqual(result["first_blocker"]["stage"], "traversal")
        self.assertEqual([step["path"] for step in result["access_path"]], ["/", "/data"])
        self.assertTrue(result["access_path"][-1]["blocker"])
        self.assertIsNone(result["target_inode"])
        self.assertEqual(result["mount"]["result"], "not_evaluated")

    def test_named_acl_mask(self):
        result = self.document(mode="w", acl=make_acl(users=((self.subject.uid, 6), (30000, 7)), mask=4))
        acl = result["target_inode"]["acl"]
        self.assertEqual(acl["decision_type"], "named_user")
        self.assertEqual(acl["matched_user_ids"], [self.subject.uid])
        self.assertEqual(len(acl["entries"]), 1)
        self.assertEqual(acl["mask"]["bits"], 4)
        self.assertEqual(acl["effective_permissions"]["bits"], 4)
        self.assertTrue(acl["mask_reduced_requested_rights"])
        self.assertEqual(acl["result"], "denied")

    def test_group_union(self):
        subject = ph.Subject("member", 2000, 700, "primary", (800,), ("extra",))
        result = self.document(subject, acl=make_acl(groups=((700, 4), (800, 2)), mask=6))
        inode = result["target_inode"]
        self.assertEqual(inode["acl"]["group_union"]["bits"], 6)
        self.assertEqual(inode["acl"]["matched_group_ids"], [700, 800])
        self.assertEqual(inode["matched_groups"][1], {"gid": 800, "name": "extra", "membership": "supplementary"})

    def test_supplementary_group(self):
        subject = ph.Subject("member", 2000, 600, "primary", (500,), ("media",))
        result = self.document(subject)
        self.assertEqual(result["subject"]["supplementary_groups"], [{"gid": 500, "name": "media"}])
        self.assertEqual(result["target_inode"]["matched_groups"], [{"gid": 500, "name": "media", "membership": "supplementary"}])

    def test_symlink_order_and_resolved_path(self):
        diagnosis = account_result(self.subject).diagnosis
        root = diagnosis.trace.events[0]
        diagnosis.trace.events[1:1] = [ph.Symlink("/alias", "/data/file"), root]
        result = jo.diagnosis_document(diagnosis, ph.__version__, explain=True)
        self.assertEqual([e["kind"] for e in result["access_path"]], ["inode", "symlink", "inode", "inode"])
        self.assertEqual(result["access_path"][1]["destination"], "/data/file")
        self.assertEqual(result["resolved_target_path"], "/data/file")

    def test_root_override(self):
        inode = self.document(ROOT, target_mode=0)["target_inode"]
        self.assertEqual(inode["mechanism"], "root")
        self.assertTrue(inode["root_override"])
        self.assertEqual(inode["root_assumption"], "traditional_privileged_uid_0")
        self.assertIsNone(inode["acl"])

    def test_mount_blocker(self):
        result = self.document(mode="w", target_mode=0o666, readonly=True)
        self.assertEqual(result["mount"]["result"], "denied")
        self.assertTrue(result["mount"]["blocker"])
        self.assertEqual(result["first_blocker"], {"stage": "mount", "path": "/", "mechanism": "mount"})

    def test_first_blocker_precedes_mount(self):
        result = self.document(mode="w", target_mode=0o600, readonly=True)
        self.assertEqual(result["first_blocker"]["stage"], "target")
        self.assertEqual(result["mount"]["result"], "denied")
        self.assertFalse(result["mount"]["blocker"])

    def test_unknown_mount_does_not_become_denial(self):
        diagnosis = account_result(self.subject).diagnosis
        diagnosis.mount = None
        diagnosis.mount_error = "Cannot inspect mountinfo"
        diagnosis.reasons = []
        ph.determine_verdict(diagnosis)
        result = jo.diagnosis_document(diagnosis, ph.__version__)
        self.assertEqual(result["exit_code"], 3)
        self.assertEqual(result["verdict"], "error")
        self.assertEqual(result["mount"]["result"], "unknown")
        self.assertIsNone(result["first_blocker"])
        self.assertEqual(result["errors"][0]["stage"], "mount")

    def test_known_denial_retained_with_mount_error(self):
        diagnosis = account_result(self.subject, target_mode=0o600).diagnosis
        diagnosis.mount = None
        diagnosis.mount_error = "Cannot inspect mountinfo"
        diagnosis.reasons = []
        ph.determine_verdict(diagnosis)
        result = jo.diagnosis_document(diagnosis, ph.__version__)
        self.assertEqual(result["verdict"], "denied")
        self.assertEqual(result["exit_code"], 1)
        self.assertEqual(result["mount"]["result"], "unknown")
        self.assertEqual(result["errors"][0]["stage"], "mount")

    def test_noexec_mount(self):
        diagnosis = account_result(self.subject, target_mode=0o755, mode="x").diagnosis
        diagnosis.mount = replace(diagnosis.mount, options=frozenset({"rw", "noexec"}))
        diagnosis.reasons = []
        ph.determine_verdict(diagnosis)
        result = jo.diagnosis_document(diagnosis, ph.__version__, explain=True)
        self.assertTrue(result["mount"]["noexec"])
        self.assertEqual(result["mount"]["result"], "denied")
        self.assertEqual(result["first_blocker"]["stage"], "mount")

    def test_acl_inspection_error(self):
        diagnosis = account_result(self.subject).diagnosis
        diagnosis.trace.target = None
        diagnosis.trace.failure = "ACL inspection failed: unavailable"
        diagnosis.trace.code = ph.ExitCode.ERROR
        diagnosis.reasons = []
        ph.determine_verdict(diagnosis)
        result = jo.diagnosis_document(diagnosis, ph.__version__)
        self.assertEqual(result["verdict"], "error")
        self.assertEqual(result["mount"]["result"], "not_evaluated")
        self.assertIsNone(result["target_inode"])
        self.assertEqual(result["errors"][0]["message"], diagnosis.trace.failure)

    def test_deterministic_escaped_json(self):
        diagnosis = account_result(self.subject).diagnosis
        diagnosis.requested_path = "a\n\x1b\udcff"
        document = jo.diagnosis_document(diagnosis, ph.__version__)
        text = jo.render_json(document)
        self.assertEqual(text, jo.render_json(document))
        self.assertEqual(json.loads(text)["target_path"], diagnosis.requested_path)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("PERMISSION HELL", text)


class AuditJsonTests(unittest.TestCase):
    def test_every_account_counts_and_no_compression(self):
        results = [account_result(subject) for subject in ordinary_accounts(25)]
        results.append(account_result(ph.Subject("denied", 8000, 8000, "own", (), ()), target_mode=0o600))
        report = report_for(results)
        data = jo.audit_document(report, ph.__version__)
        self.assertEqual(len(data["accounts"]), 26)
        self.assertEqual(data["totals"], {"permitted": 25, "denied": 1, "errors": 0})
        self.assertEqual(data["exit_code"], 0)
        self.assertEqual(data["verdict"], "complete")
        self.assertEqual({a["username"] for a in data["accounts"]}, {r.account.username for r in results})
        self.assertEqual(data["accounts"][-1]["blocker_path"], "/data/file")
        self.assertEqual(data["account_source"], "/etc/passwd")

    def test_acl_granted_account(self):
        subject = ordinary_accounts(1)[0]
        result = account_result(subject, acl=make_acl(users=((subject.uid, 4),), mask=4))
        data = jo.audit_document(report_for([result]), ph.__version__)["accounts"][0]
        self.assertEqual(data["mechanism"], "posix_acl")
        self.assertEqual(data["decision"]["acl"]["matched_user_ids"], [subject.uid])
        self.assertEqual(data["verdict"], "permitted")

    def test_per_account_error(self):
        error = ph.AccountAudit(ph.LocalAccount("missing", 100, 200), error="Identity lookup failed")
        data = jo.audit_document(report_for([error]), ph.__version__)
        self.assertEqual(data["exit_code"], 3)
        self.assertEqual(data["totals"]["errors"], 1)
        self.assertEqual(data["accounts"][0]["verdict"], "error")
        self.assertIsNone(data["accounts"][0]["decision"])
        self.assertEqual(data["accounts"][0]["errors"][0]["message"], error.error)

    def test_global_failure(self):
        report = ph.AuditReport("/absent", "r", failure="Unresolved target", code=ph.ExitCode.INPUT)
        data = jo.audit_document(report, ph.__version__)
        self.assertEqual(data["exit_code"], 2)
        self.assertEqual(data["accounts"], [])
        self.assertEqual(data["errors"][0]["stage"], "audit")


class JsonCliTests(unittest.TestCase):
    def setUp(self):
        self.subject = ordinary_accounts(1)[0]
        self.diagnosis = account_result(self.subject).diagnosis

    def invoke(self, argv):
        with contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
            code = ph.main(argv)
        self.assertEqual(stderr.getvalue(), "")
        data = json.loads(stdout.getvalue())
        self.assertEqual(data["exit_code"], code)
        return data

    def test_diagnose_permitted_json_no_human_renderer(self):
        with patch.object(ph.sys, "platform", "linux"), patch.object(ph, "resolve_subject", return_value=self.subject), \
                patch.object(ph, "diagnose", return_value=self.diagnosis), \
                patch.object(ph, "render_report", side_effect=AssertionError("human renderer")):
            data = self.invoke(["diagnose", "/file", "--as", self.subject.username, "--json"])
        self.assertEqual(data["verdict"], "permitted")

    def test_explain_permitted_and_denied(self):
        for target_mode, expected in ((0o644, "permitted"), (0o600, "denied")):
            diagnosis = account_result(self.subject, target_mode=target_mode).diagnosis
            with self.subTest(expected=expected), patch.object(ph.sys, "platform", "linux"), \
                    patch.object(ph, "explain_audit_target", return_value=ph.AuditExplanation(diagnosis)), \
                    patch.object(ph, "render_audit_explanation", side_effect=AssertionError("human renderer")):
                data = self.invoke(["audit", "/file", "--explain", self.subject.username, "--json"])
            self.assertEqual(data["mode"], "explain")
            self.assertEqual(data["verdict"], expected)
            self.assertNotIn("remediations", data)

    def test_audit_json(self):
        report = report_for([account_result(s) for s in ordinary_accounts(10)])
        with patch.object(ph.sys, "platform", "linux"), patch.object(ph, "audit_target", return_value=report), \
                patch.object(ph, "render_audit", side_effect=AssertionError("human renderer")):
            data = self.invoke(["audit", "/file", "--json"])
        self.assertEqual(len(data["accounts"]), 10)

    def test_verbose_keeps_identical_json(self):
        with patch.object(ph.sys, "platform", "linux"), patch.object(ph, "resolve_subject", return_value=self.subject), \
                patch.object(ph, "diagnose", return_value=self.diagnosis):
            args = ["diagnose", "/file", "--as", self.subject.username, "--json"]
            self.assertEqual(self.invoke(args), self.invoke(args + ["--verbose"]))

    def test_remediation_json_mask_warning_no_execution(self):
        diagnosis = account_result(self.subject, mode="w", acl=make_acl(users=((self.subject.uid, 6),), mask=4)).diagnosis
        with patch.object(ph.sys, "platform", "linux"), \
                patch.object(ph, "explain_audit_target", return_value=ph.AuditExplanation(diagnosis)), \
                patch("subprocess.run", side_effect=AssertionError("execution")), \
                patch("os.system", side_effect=AssertionError("execution")), \
                patch.object(ph, "render_remediations", side_effect=AssertionError("human renderer")):
            data = self.invoke(["audit", "/file", "--explain", self.subject.username, "--mode", "w",
                                "--suggest-fixes", "--verbose", "--json"])
        suggestion = data["remediations"][0]
        self.assertEqual(suggestion["category"], "group_level_change")
        self.assertIsInstance(suggestion["commands"], list)
        self.assertIn("ALL mask-governed", suggestion["effect"])
        self.assertEqual(data["exit_code"], 1)

    def test_unknown_user_json(self):
        with patch.object(ph.sys, "platform", "linux"), \
                patch.object(ph, "resolve_subject", side_effect=ph.DiagnosticError("No such user", ph.ExitCode.INPUT)):
            for args in (["diagnose", "/file", "--as", "absent", "--json"],
                         ["audit", "/file", "--explain", "absent", "--json", "--suggest-fixes"]):
                data = self.invoke(args)
                self.assertEqual(data["exit_code"], 2)
                self.assertEqual(data["requested_username"], "absent")
                self.assertEqual(data["errors"][0]["kind"], "invalid_input")

    def test_system_error_json(self):
        with patch.object(ph.sys, "platform", "linux"), \
                patch.object(ph, "resolve_subject", side_effect=OSError("Identity unavailable")):
            data = self.invoke(["diagnose", "/file", "--as", "user", "--json"])
        self.assertEqual(data["exit_code"], 3)

    def test_unsupported_platform_json(self):
        with patch.object(ph.sys, "platform", "win32"):
            data = self.invoke(["audit", "/file", "--json"])
        self.assertEqual(data["errors"][0]["stage"], "platform")
        self.assertEqual(data["exit_code"], 3)

    def test_parser_error_stays_stderr(self):
        with contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr, \
                self.assertRaises(SystemExit) as error:
            ph.main(["audit", "/file", "--json", "--suggest-fixes"])
        self.assertEqual(error.exception.code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("requires --explain", stderr.getvalue())

    def test_human_output_unchanged_without_flag(self):
        with patch.object(ph.sys, "platform", "linux"), patch.object(ph, "resolve_subject", return_value=self.subject), \
                patch.object(ph, "diagnose", return_value=self.diagnosis), contextlib.redirect_stdout(io.StringIO()) as output:
            ph.main(["diagnose", "/file", "--as", self.subject.username])
        self.assertEqual(output.getvalue(), ph.render_report(self.diagnosis) + "\n")

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux subprocess integration")
    def test_subprocess_real_path_and_missing_path(self):
        import pwd
        username = pwd.getpwuid(os.getuid()).pw_name
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "file"
            path.write_text("not exported")
            broken = path.with_name("broken")
            broken.symlink_to("absent")
            for target, code in ((path, 0), (path.with_name("absent"), 2), (broken, 2)):
                result = subprocess.run([sys.executable, str(Path(ph.__file__)), "diagnose", str(target),
                                         "--as", username, "--json"], capture_output=True, text=True)
                self.assertEqual(result.returncode, code, result.stderr)
                data = json.loads(result.stdout)
                self.assertEqual(data["exit_code"], code)
                self.assertEqual(result.stderr, "")
                self.assertNotIn("not exported", result.stdout)
