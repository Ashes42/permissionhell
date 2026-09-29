import contextlib
import copy
import io
import shlex
import unittest
from unittest.mock import patch

import permissionhell as ph
from test_audit_rendering import account_result, ordinary_accounts
from test_permissionhell import ROOT
from test_posix_acl import make_acl


class RemediationTests(unittest.TestCase):
    def setUp(self):
        self.subject = ordinary_accounts(1)[0]

    def suggestions(self, subject=None, **kwargs):
        diagnosis = account_result(subject or self.subject, **kwargs).diagnosis
        before = copy.deepcopy(diagnosis)
        result = ph.suggest_remediations(diagnosis)
        self.assertEqual(before, diagnosis)
        return result

    def text(self, subject=None, **kwargs):
        return ph.render_remediations(self.suggestions(subject, **kwargs))

    def test_other_denial(self):
        text = self.text(target_mode=0o600, mode="w")
        self.assertIn("chmod o+w -- /data/file", text)
        self.assertIn("setfacl -n -m", text)
        self.assertIn("every account using OTHER", text)

    def test_owner_denial(self):
        text = self.text(ph.Subject("owner", 9000, 1, "own", (), ()), target_mode=0o400, mode="w")
        self.assertIn("chmod u+w", text)
        self.assertNotIn("setfacl", text)

    def test_group_denial(self):
        text = self.text(ph.Subject("member", 2000, 500, "files", (), ()), target_mode=0o640, mode="w")
        self.assertIn("chmod g+w", text)
        self.assertIn("every account using the owning-group", text)

    def test_supplementary_group_denial(self):
        text = self.text(ph.Subject("member", 2000, 600, "own", (500,), ("files",)), target_mode=0o640, mode="w")
        self.assertIn("Review supplementary group membership", text)
        self.assertIn("refreshed process credentials", text)

    def test_named_user_denial(self):
        text = self.text(acl=make_acl(users=((self.subject.uid, 4),), mask=6), mode="w")
        self.assertIn(f"u:{self.subject.username}:rw-", text)
        self.assertIn("keeps the existing mask", text)

    def test_mask_denial_warns_all_entries(self):
        text = self.text(acl=make_acl(users=((self.subject.uid, 6),), mask=4), mode="w")
        self.assertIn("setfacl -n -m m::rw-", text)
        self.assertIn("ALL mask-governed named-user and group ACL entries", text)

    def test_named_group_denial(self):
        text = self.text(ph.Subject("member", 2000, 700, "files", (), ()),
                         acl=make_acl(groups=((700, 4),), mask=6), mode="w")
        self.assertIn("matching ACL groups and their union", text)
        self.assertNotIn("chmod g", text)

    def test_extended_owning_group_does_not_get_chmod_mask_command(self):
        suggestions = self.suggestions(ph.Subject("member", 2000, 500, "files", (), ()),
                                       acl=make_acl(group=4, mask=4), mode="w")
        self.assertFalse(any(s.commands for s in suggestions))
        self.assertIn("shared mask", ph.render_remediations(suggestions))

    def test_traversal_changes_blocker_not_target(self):
        suggestions = self.suggestions(parent_mode=0o700)
        commands = [shlex.split(c) for s in suggestions for c in s.commands]
        self.assertTrue(commands)
        self.assertTrue(all(c[-1] == "/data" for c in commands))
        self.assertIn("Directory x means search/traversal", ph.render_remediations(suggestions))

    def test_readonly_mount(self):
        suggestions = self.suggestions(target_mode=0o666, mode="w", readonly=True)
        self.assertFalse(any(s.commands for s in suggestions))
        self.assertIn("READ-ONLY", ph.render_remediations(suggestions))

    def test_noexec_mount(self):
        diagnosis = account_result(self.subject, target_mode=0o755, mode="x").diagnosis
        from dataclasses import replace
        diagnosis.mount = replace(diagnosis.mount, options=frozenset({"rw", "noexec"}))
        diagnosis.reasons = []
        ph.determine_verdict(diagnosis)
        suggestions = ph.suggest_remediations(diagnosis)
        self.assertFalse(any(s.commands for s in suggestions))
        self.assertIn("noexec", ph.render_remediations(suggestions))

    def test_root_execute_denial(self):
        text = self.text(ROOT, target_mode=0o644, mode="x")
        self.assertIn("chmod u+x", text)
        self.assertIn("also grants execute to its owner", text)

    def test_root_permitted(self):
        text = self.text(ROOT)
        self.assertIn("do not reliably revoke root access", text)

    def test_other_reduction(self):
        text = self.text()
        self.assertIn("chmod o-r", text)
        self.assertIn("named entry prevents fallback", text)

    def test_supplementary_reduction(self):
        text = self.text(ph.Subject("member", 2000, 600, "own", (500,), ("files",)))
        self.assertIn("Removing membership may narrow access", text)
        self.assertIn("OTHER or another matching ACL group may still permit", text)

    def test_named_acl_reduction(self):
        text = self.text(acl=make_acl(users=((self.subject.uid, 6),), mask=6))
        self.assertIn(f"u:{self.subject.username}:-w-", text)
        self.assertIn("Deleting it instead may restore access", text)

    def test_shell_quoting(self):
        from dataclasses import replace
        diagnosis = account_result(self.subject, target_mode=0o600).diagnosis
        path = "/data/a 'quoted'; $(touch BAD)\nfile"
        diagnosis.trace.target = replace(diagnosis.trace.target, path=path)
        for suggestion in ph.suggest_remediations(diagnosis):
            for command in suggestion.commands:
                args = shlex.split(command)
                self.assertEqual(args[-1], path)
                self.assertEqual(args[-2], "--")

    def test_unknown_diagnosis_has_no_commands(self):
        diagnosis = account_result(self.subject).diagnosis
        diagnosis.code = ph.ExitCode.ERROR
        self.assertFalse(any(s.commands for s in ph.suggest_remediations(diagnosis)))

    def test_suggestions_are_not_executed_and_no_777(self):
        with patch("os.system", side_effect=AssertionError("executed")), \
                patch("subprocess.run", side_effect=AssertionError("executed")), \
                patch("subprocess.Popen", side_effect=AssertionError("executed")), \
                patch("os.chmod", side_effect=AssertionError("modified")), \
                patch("os.chown", side_effect=AssertionError("modified")):
            text = self.text(target_mode=0o600)
        self.assertNotIn("chmod 777", text)

    def test_flag_requires_explain(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            ph.main(["audit", "/file", "--suggest-fixes"])
        self.assertEqual(error.exception.code, 2)

    def test_exit_codes_unchanged(self):
        for code in ph.ExitCode:
            with self.subTest(code=code):
                diagnosis = account_result(self.subject).diagnosis
                diagnosis.code = code
                with patch.object(ph.sys, "platform", "linux"), \
                        patch.object(ph, "explain_audit_target", return_value=ph.AuditExplanation(diagnosis)), \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(ph.main(["audit", "/file", "--explain", "user", "--suggest-fixes"]), code)
                self.assertIn("POSSIBLE CHANGES", output.getvalue())

    def test_no_suggestions_without_flag(self):
        diagnosis = account_result(self.subject).diagnosis
        with patch.object(ph.sys, "platform", "linux"), \
                patch.object(ph, "explain_audit_target", return_value=ph.AuditExplanation(diagnosis)), \
                patch.object(ph, "suggest_remediations") as suggest, contextlib.redirect_stdout(io.StringIO()):
            ph.main(["audit", "/file", "--explain", "user"])
        suggest.assert_not_called()
