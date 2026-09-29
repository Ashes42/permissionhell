"""Focused presentation consumes engine decisions without changing their semantics."""

import contextlib
import io
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

import permissionhell as ph
from test_audit_rendering import account_result, ordinary_accounts
from test_permissionhell import ROOT
from test_posix_acl import make_acl


class AuditExplainTests(unittest.TestCase):
    def setUp(self):
        self.subject = ordinary_accounts(1)[0]

    def render(self, subject=None, **kwargs):
        diagnosis = account_result(subject or self.subject, **kwargs).diagnosis
        return ph.render_audit_explanation(ph.AuditExplanation(diagnosis))

    def test_owner_permitted(self):
        text = self.render(ph.Subject("owner", 9000, 500, "files", (), ()))
        self.assertIn("RESULT: PERMITTED", text)
        self.assertIn("PASS READ | OWNER rw-", text)
        self.assertIn("Every parent permits search", text)

    def test_other_denied(self):
        text = self.render(target_mode=0o600)
        self.assertIn("RESULT: DENIED", text)
        self.assertIn("FAIL READ | OTHER --- <-- BLOCKED HERE", text)
        self.assertIn("neither", text)

    def test_supplementary_group_name_and_gid(self):
        text = self.render(ph.Subject("member", 2000, 2000, "own", (500,), ("media",)))
        self.assertIn("via supplementary group media (GID 500)", text)

    def test_named_user_and_mask(self):
        acl = make_acl(users=((self.subject.uid, 6), (30000, 7)), mask=4)
        text = self.render(acl=acl)
        self.assertIn("ACL NAMED USER", text)
        self.assertIn(f"user:{self.subject.uid}:rw-", text)
        self.assertIn("Mask: r--; effective: r--", text)
        self.assertNotIn("user:30000", text)

    def test_mask_denial(self):
        text = self.render(acl=make_acl(users=((self.subject.uid, 6),), mask=4), mode="w")
        self.assertIn("RESULT: DENIED", text)
        self.assertIn("mask removes WRITE", text)

    def test_mask_denial_explanation_appears_once_in_target_step(self):
        text = self.render(acl=make_acl(users=((self.subject.uid, 6),), mask=4), mode="w")
        access_path = text.split("\nACCESS PATH\n", 1)[1].split("\nWHY\n", 1)[0]
        target_step = access_path.split("  '/data/file'", 1)[1].split("\n  Mount:", 1)[0]
        explanation = (f"ACL NAMED USER: user:{self.subject.uid}:rw-. "
                       "Mask: r--; effective: r--. The ACL mask removes WRITE; "
                       "access denied, no fallback.")
        self.assertEqual(target_step.count(explanation), 1)

    def test_named_groups_union_and_names(self):
        subject = ph.Subject("member", 2000, 2000, "own", (700, 800), ("media", "editors"))
        text = self.render(subject, acl=make_acl(groups=((700, 4), (800, 2)), mask=6))
        self.assertIn("ACL GROUP", text)
        self.assertIn("Group union: rw-", text)
        self.assertIn("group:700:r--", text)
        self.assertIn("group:800:-w-", text)
        self.assertIn("media (GID 700)", text)
        self.assertIn("editors (GID 800)", text)

    def test_traversal_blocker(self):
        text = self.render(parent_mode=0o700)
        self.assertIn("'/data'  FAIL search | OTHER --- <-- BLOCKED HERE", text)
        self.assertIn("Target not evaluated", text)
        self.assertNotIn("PASS READ", text)
        self.assertEqual(text.count("BLOCKED HERE"), 1)

    def test_mount_blocker(self):
        text = self.render(target_mode=0o666, mode="w", readonly=True)
        self.assertIn("PASS WRITE", text)
        self.assertIn("READ-ONLY | FAIL <-- BLOCKED HERE", text)
        self.assertIn("blocks writing", text)

    def test_target_remains_first_when_mount_also_denies(self):
        text = self.render(target_mode=0o600, mode="w", readonly=True)
        self.assertIn("OTHER --- <-- BLOCKED HERE", text)
        self.assertIn("READ-ONLY | FAIL", text)
        self.assertEqual(text.count("BLOCKED HERE"), 1)

    def test_root_override(self):
        text = self.render(ROOT, target_mode=0)
        self.assertIn("PASS READ | ROOT OVERRIDE", text)
        self.assertIn("traditional privileged UID 0", text)

    def test_root_execute_denial(self):
        text = self.render(ROOT, target_mode=0o644, mode="x")
        self.assertIn("RESULT: DENIED", text)
        self.assertIn("FAIL EXECUTE/SEARCH | ROOT", text)
        self.assertNotIn("ROOT OVERRIDE", text)

    def test_symlink_keeps_sequence_and_resolution(self):
        diagnosis = account_result(self.subject).diagnosis
        root, parent = diagnosis.trace.events
        diagnosis.trace.events = [root, ph.Symlink("/alias", "/data/file"), root, parent]
        text = ph.render_audit_explanation(ph.AuditExplanation(diagnosis))
        self.assertIn("LINK '/alias' -> '/data/file'", text)
        self.assertIn("Resolved target: '/data/file'", text)
        self.assertIn("same check as above", text)
        self.assertLess(text.index("LINK"), text.index("'/data'"))

    def test_verbose_appends_full_detail(self):
        explanation = ph.AuditExplanation(account_result(self.subject).diagnosis)
        concise = ph.render_audit_explanation(explanation)
        verbose = ph.render_audit_explanation(explanation, verbose=True)
        self.assertTrue(verbose.startswith(concise))
        self.assertIn(ph.render_verbose_report(explanation.diagnosis), verbose)
        self.assertNotIn(ph.SCOPE_TEXT, concise)

    def test_mount_inspection_error_is_unknown(self):
        diagnosis = account_result(self.subject).diagnosis
        diagnosis.mount = None
        diagnosis.mount_error = "Cannot read mountinfo"
        diagnosis.reasons = []
        ph.determine_verdict(diagnosis)
        text = ph.render_audit_explanation(ph.AuditExplanation(diagnosis))
        self.assertEqual(diagnosis.code, ph.ExitCode.ERROR)
        self.assertIn("RESULT: INCOMPLETE", text)
        self.assertIn("Mount: UNKNOWN | Cannot read mountinfo", text)

    def test_unresolved_path_retains_trace(self):
        diagnosis = account_result(self.subject).diagnosis
        diagnosis.trace.target = None
        diagnosis.trace.resolved_path = None
        diagnosis.trace.failure = "Broken symlink: '/data/link'"
        diagnosis.trace.code = ph.ExitCode.INPUT
        diagnosis.mount = None
        ph.determine_verdict(diagnosis)
        text = ph.render_audit_explanation(ph.AuditExplanation(diagnosis))
        self.assertEqual(diagnosis.code, ph.ExitCode.INPUT)
        self.assertIn("UNRESOLVED PATH", text)
        self.assertIn("Broken symlink", text)
        self.assertIn("'/data'  PASS search", text)

    def test_rendering_does_not_modify_diagnosis(self):
        import copy
        diagnosis = account_result(self.subject, target_mode=0o600).diagnosis
        original = copy.deepcopy(diagnosis)
        ph.render_audit_explanation(ph.AuditExplanation(diagnosis), verbose=True)
        self.assertEqual(diagnosis, original)

    def test_focused_analysis_resolves_only_requested_identity(self):
        diagnosis = account_result(self.subject).diagnosis
        with patch.object(ph, "resolve_subject", return_value=self.subject) as resolve, \
                patch.object(ph, "diagnose", return_value=diagnosis) as diagnose, \
                patch.object(ph, "audit_target") as audit:
            result = ph.explain_audit_target("/data/file", self.subject.username, "r")
        resolve.assert_called_once_with(self.subject.username)
        diagnose.assert_called_once_with("/data/file", self.subject, "r")
        audit.assert_not_called()
        self.assertIs(result.diagnosis, diagnosis)

    def test_unknown_user(self):
        with patch.object(ph.sys, "platform", "linux"), \
                patch.object(ph, "resolve_subject", side_effect=ph.DiagnosticError("No such user: absent", ph.ExitCode.INPUT)), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            code = ph.main(["audit", "/data/file", "--explain", "absent"])
        self.assertEqual(code, 2)
        self.assertIn("No such user: absent", err.getvalue())

    def test_explain_exit_codes_and_routing(self):
        for code in ph.ExitCode:
            with self.subTest(code=code):
                diagnosis = account_result(self.subject).diagnosis
                diagnosis.code = code
                with patch.object(ph.sys, "platform", "linux"), \
                        patch.object(ph, "explain_audit_target", return_value=ph.AuditExplanation(diagnosis)) as focused, \
                        patch.object(ph, "render_audit_explanation", return_value="focused") as renderer, \
                        patch.object(ph, "audit_target") as audit, contextlib.redirect_stdout(io.StringIO()):
                    actual = ph.main(["audit", "/data/file", "--mode", "w", "--explain", "account", "--verbose"])
                self.assertEqual(actual, code)
                focused.assert_called_once_with("/data/file", "account", "w")
                renderer.assert_called_once_with(ph.AuditExplanation(diagnosis), verbose=True)
                audit.assert_not_called()

    def test_normal_audit_routing_unchanged(self):
        report = ph.AuditReport("/file", "r")
        with patch.object(ph.sys, "platform", "linux"), patch.object(ph, "audit_target", return_value=report) as audit, \
                patch.object(ph, "explain_audit_target") as focused, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ph.main(["audit", "/file"]), 0)
        audit.assert_called_once_with("/file", "r")
        focused.assert_not_called()

    def test_diagnose_routing_unchanged(self):
        diagnosis = account_result(self.subject).diagnosis
        with patch.object(ph.sys, "platform", "linux"), patch.object(ph, "resolve_subject", return_value=self.subject), \
                patch.object(ph, "diagnose", return_value=diagnosis) as diagnose, \
                patch.object(ph, "explain_audit_target") as focused, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ph.main(["diagnose", "/file", "--as", self.subject.username]), 0)
        diagnose.assert_called_once_with("/file", self.subject, "r")
        focused.assert_not_called()

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux metadata and mount integration")
    def test_linux_real_file_and_symlink(self):
        import pwd
        username = pwd.getpwuid(os.getuid()).pw_name
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "file")
            with open(path, "w") as output:
                output.write("fixture")
            link = os.path.join(directory, "link")
            os.symlink("file", link)
            explanation = ph.explain_audit_target(link, username)
            self.assertEqual(explanation.code, ph.ExitCode.ALLOWED)
            self.assertEqual(explanation.diagnosis.trace.resolved_path, path)
            self.assertIn("LINK", ph.render_audit_explanation(explanation))


if __name__ == "__main__":
    unittest.main()
