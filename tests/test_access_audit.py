"""Local-account inventory, shared-engine audit, rendering, and CLI tests."""

import contextlib
import copy
import errno
import io
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import mock_open, patch

import permissionhell as ph
from test_permissionhell import metadata, SUBJECT, ROOT, MOUNTINFO
from test_posix_acl import make_acl, acl_metadata


MEMBER = ph.Subject("audio", 1002, 300, "audio", (200,), ("media",))
VISITOR = ph.Subject("visitor", 1003, 400, "visitor", (), ())


def local(subject):
    return ph.LocalAccount(subject.username, subject.uid, subject.primary_gid)


class AccountEnumerationTest(unittest.TestCase):
    def enumerate(self, content):
        with patch("builtins.open", mock_open(read_data=content)) as read:
            accounts = ph.enumerate_local_accounts()
        read.assert_called_once_with("/etc/passwd", encoding="utf-8", errors="surrogateescape")
        return accounts

    def test_includes_root_service_locked_and_high_uid_accounts(self):
        accounts = self.enumerate("zuser:x:100000:20::/home/z:/bin/bash\n"
                                  "daemon:*:1:1::/:/usr/sbin/nologin\n"
                                  "root:x:0:0::/root:/bin/bash\n")
        self.assertEqual([account.username for account in accounts], ["daemon", "root", "zuser"])
        self.assertEqual([account.uid for account in accounts], [1, 0, 100000])

    def test_same_uid_aliases_remain_separate_accounts(self):
        self.assertEqual(len(self.enumerate("alias:x:1000:100::/:/bin/sh\n"
                                            "user:x:1000:100::/:/bin/sh\n")), 2)

    def test_compat_directives_are_not_remote_account_enumeration(self):
        accounts = self.enumerate("# comment\n\n+::::::\n+remote::::::\n-remote\n"
                                  "local:x:1000:100::/:/bin/sh\n")
        self.assertEqual(accounts, [ph.LocalAccount("local", 1000, 100)])

    def test_never_retains_authentication_or_gecos_fields(self):
        accounts = self.enumerate("local:secret-hash:1000:100:private-name:/home/private:/bin/sh\n")
        self.assertNotIn("secret", repr(accounts))
        self.assertNotIn("private", repr(accounts))

    def test_rejects_malformed_inventory_instead_of_silent_exclusions(self):
        for line in ("bad\n", "u:x:no:100::/:/bin/sh\n", "u:x:2:-1::/:/bin/sh\n",
                     ":x:2:2::/:/bin/sh\n", "u:x:4294967295:2::/:/bin/sh\n",
                     "u:x:" + "9" * 5000 + ":2::/:/bin/sh\n"):
            with self.subTest(line=line), self.assertRaises(ph.DiagnosticError):
                self.enumerate(line)

    def test_duplicate_names_are_an_inventory_error(self):
        with self.assertRaisesRegex(ph.DiagnosticError, "Duplicate"):
            self.enumerate("u:x:1000:100::/:/bin/sh\nu:x:1001:101::/:/bin/sh\n")

    def test_inventory_unreadable_is_system_error(self):
        with patch("builtins.open", side_effect=PermissionError("denied")), \
                self.assertRaises(ph.DiagnosticError) as error:
            ph.enumerate_local_accounts()
        self.assertEqual(error.exception.code, 3)


class AuditTest(unittest.TestCase):
    def setUp(self):
        self.subjects = [SUBJECT, MEMBER, VISITOR, ROOT]
        self.nodes = {"/": metadata(0o755, kind=stat.S_IFDIR),
                      "/srv": metadata(0o755, kind=stat.S_IFDIR),
                      "/srv/file": metadata(0o640, gid=200)}
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.inventory = self.stack.enter_context(patch.object(ph, "enumerate_local_accounts",
                                    side_effect=lambda: [local(subject) for subject in self.subjects]))
        self.resolver = self.stack.enter_context(patch.object(ph, "resolve_subject",
                                    side_effect=lambda name: next(s for s in self.subjects if s.username == name)))
        self.preflight = self.stack.enter_context(patch.object(ph.os, "stat", return_value=metadata()))
        self.lookups = self.stack.enter_context(patch.object(ph.os, "lstat", side_effect=lambda path: self.nodes[path]))
        self.acls = self.stack.enter_context(patch.object(ph, "read_access_acl", return_value=None))
        self.mounts = self.stack.enter_context(patch.object(ph, "read_mounts", return_value=ph.parse_mountinfo(MOUNTINFO)))
        self.stack.enter_context(patch.object(ph, "owner_name", side_effect=str))
        self.stack.enter_context(patch.object(ph, "group_name", side_effect=str))

    def test_owner_and_supplementary_group_and_root_allowed(self):
        result = ph.audit_target("/srv/file")
        self.assertEqual([entry.account.username for entry in result.permitted], ["alice", "audio", "root"])
        self.assertEqual([entry.account.username for entry in result.denied], ["visitor"])
        self.assertEqual(result.errors, [])
        self.assertEqual(result.code, 0)
        owner = result.permitted[0].diagnosis.trace.target
        self.assertEqual(owner.decision.permission_class, "OWNER")
        member = result.permitted[1].diagnosis
        self.assertEqual(member.trace.target.decision.permission_class, "GROUP")
        self.assertIn(200, member.subject.supplementary_gids)

    def test_other_access_is_explicit_and_neutral(self):
        self.nodes["/srv/file"] = metadata(0o644, gid=200)
        result = ph.audit_target("/srv/file")
        text = ph.render_audit(result)
        self.assertEqual(len(result.permitted), 4)
        self.assertIn("Access via OTHER; effective: r--", text)
        self.assertNotIn("unexpected", text.lower())

    def test_existing_structured_engine_called_once_for_each_account(self):
        with patch.object(ph, "diagnose", wraps=ph.diagnose) as diagnose:
            result = ph.audit_target("/srv/file")
        self.assertEqual(diagnose.call_count, 4)
        self.assertEqual([call.args[1] for call in diagnose.call_args_list], self.subjects)
        self.assertEqual(result.permitted[0].diagnosis.trace.resolved_path, "/srv/file")

    def test_mount_snapshot_shared_but_not_across_audits(self):
        ph.audit_target("/srv/file")
        self.mounts.assert_called_once_with()
        ph.audit_target("/srv/file")
        self.assertEqual(self.mounts.call_count, 2)

    def test_named_user_acl_grants_access(self):
        acl = make_acl(users=((VISITOR.uid, 4),), mask=4)
        self.nodes["/srv/file"] = acl_metadata(acl, uid=SUBJECT.uid)
        self.acls.side_effect = lambda path: acl if path == "/srv/file" else None
        result = ph.audit_target("/srv/file")
        entry = next(entry for entry in result.permitted if entry.account.username == "visitor")
        self.assertFalse(entry.diagnosis.trace.target.dac_decision.allowed)
        self.assertIn("ACL NAMED USER", ph.render_audit(result))
        self.assertIn("user:1003:r--", ph.render_audit(result))

    def test_supplementary_named_group_acl_grants_access(self):
        acl = make_acl(groups=((200, 4),), mask=4)
        self.nodes["/srv/file"] = acl_metadata(acl, uid=SUBJECT.uid, gid=999)
        self.acls.side_effect = lambda path: acl if path == "/srv/file" else None
        result = ph.audit_target("/srv/file")
        self.assertIn("audio", [entry.account.username for entry in result.permitted])
        text = ph.render_audit(result)
        self.assertIn("ACL GROUP", text)
        self.assertIn("Matching supplementary GIDs: 200", text)

    def test_acl_mask_denial_explains_removed_permission(self):
        acl = make_acl(users=((VISITOR.uid, 6),), mask=4)
        self.nodes["/srv/file"] = acl_metadata(acl, uid=SUBJECT.uid)
        self.acls.side_effect = lambda path: acl if path == "/srv/file" else None
        result = ph.audit_target("/srv/file", "w")
        entry = next(entry for entry in result.denied if entry.account.username == "visitor")
        self.assertEqual(entry.diagnosis.trace.target.acl_match.effective, 4)
        self.assertIn("ACL mask removes WRITE", ph.render_audit(result))
        self.assertEqual(result.code, 0)

    def test_directory_denial_identifies_blocker(self):
        self.nodes["/srv"] = metadata(0o700, kind=stat.S_IFDIR)
        result = ph.audit_target("/srv/file")
        denied = next(entry for entry in result.denied if entry.account.username == "visitor")
        self.assertIsNone(denied.diagnosis.trace.target)
        self.assertIn("BLOCKED at '/srv': missing EXECUTE/SEARCH", ph.render_audit(result))

    def test_parent_acl_grant_is_summarized_as_part_of_access_path(self):
        acl = make_acl(users=((VISITOR.uid, 1),), mask=1)
        self.nodes["/srv"] = acl_metadata(acl, uid=SUBJECT.uid, directory=True)
        self.nodes["/srv/file"] = metadata(0o644)
        self.acls.side_effect = lambda path: acl if path == "/srv" else None
        result = ph.audit_target("/srv/file")
        self.assertIn("visitor", [entry.account.username for entry in result.permitted])
        text = ph.render_audit(result)
        self.assertIn("Search at '/srv': ACL NAMED USER", text)
        self.assertIn("Access via OTHER", text)

    def test_readonly_mount_denies_write_but_audit_succeeds(self):
        self.nodes["/srv/file"] = metadata(0o666)
        self.mounts.return_value = ph.parse_mountinfo(MOUNTINFO.replace("rw", "ro"))
        result = ph.audit_target("/srv/file", "w")
        self.assertEqual((len(result.permitted), len(result.denied), result.code), (0, 4, 0))
        self.assertIn("BLOCKED by mount: Mount '/' is READ-ONLY", ph.render_audit(result))

    def test_noexec_mount_denies_execution(self):
        self.nodes["/srv/file"] = metadata(0o755)
        self.mounts.return_value = ph.parse_mountinfo(MOUNTINFO.replace("rw,relatime", "rw,noexec"))
        result = ph.audit_target("/srv/file", "x")
        self.assertEqual(len(result.denied), 4)
        self.assertEqual(result.code, 0)
        self.assertIn("noexec", ph.render_audit(result))

    def test_root_override_and_execute_requirement_preserved(self):
        self.nodes["/srv/file"] = metadata(0)
        result = ph.audit_target("/srv/file", "r")
        self.assertEqual([entry.account.username for entry in result.permitted], ["root"])
        self.assertIn("ROOT OVERRIDE", ph.render_audit(result))
        result = ph.audit_target("/srv/file", "x")
        self.assertEqual(len(result.denied), 4)
        self.assertIn("Root still needs at least one execute bit", ph.render_audit(result))

    def test_symlink_target_audited_by_existing_resolution(self):
        self.nodes["/alias"] = metadata(0o777, kind=stat.S_IFLNK)
        with patch.object(ph.os, "readlink", return_value="/srv/file"):
            result = ph.audit_target("/alias")
        self.assertEqual(result.code, 0)
        for entry in result.permitted + result.denied:
            self.assertEqual(entry.diagnosis.trace.resolved_path, "/srv/file")
            self.assertTrue(any(isinstance(event, ph.Symlink) for event in entry.diagnosis.trace.events))
        self.assertIn("Resolved target(s): '/srv/file'", ph.render_audit(result))

    def test_one_identity_error_does_not_stop_other_accounts(self):
        def resolve(name):
            if name == "audio":
                raise ph.DiagnosticError("Group lookup unavailable")
            return next(subject for subject in self.subjects if subject.username == name)
        self.resolver.side_effect = resolve
        result = ph.audit_target("/srv/file")
        self.assertEqual((len(result.permitted), len(result.denied), len(result.errors)), (2, 1, 1))
        self.assertEqual(result.code, 3)
        self.assertEqual(result.errors[0].account.username, "audio")
        self.assertIn("Group lookup unavailable", ph.render_audit(result))

    def test_disappearing_or_shadowed_identity_is_error_not_wrong_account(self):
        self.resolver.side_effect = lambda name: ROOT
        result = ph.audit_target("/srv/file")
        self.assertEqual(len(result.errors), 3)
        self.assertEqual([entry.account.username for entry in result.permitted], ["root"])
        self.assertIn("disagrees", result.errors[0].error)

    def test_missing_identity_input_error_is_per_account_system_error(self):
        self.resolver.side_effect = ph.DiagnosticError("No such user", ph.ExitCode.INPUT)
        result = ph.audit_target("/srv/file")
        self.assertEqual(len(result.errors), 4)
        self.assertEqual(result.code, 3)

    def test_acl_inspection_errors_never_become_denials(self):
        self.acls.side_effect = ph.ACLInspectionError("unsupported")
        result = ph.audit_target("/srv/file")
        self.assertEqual([entry.account.username for entry in result.permitted], ["alice", "root"])
        self.assertEqual(len(result.errors), 2)
        self.assertEqual(result.denied, [])
        self.assertEqual(result.code, 3)

    def test_mount_error_cached_and_preserved_as_unknown(self):
        self.nodes["/srv/file"] = metadata(0o644)
        self.mounts.side_effect = ph.DiagnosticError("Cannot inspect mountinfo")
        result = ph.audit_target("/srv/file")
        self.assertEqual(len(result.errors), 4)
        self.assertEqual(result.permitted + result.denied, [])
        self.assertEqual(result.code, 3)
        self.mounts.assert_called_once_with()
        self.assertIn("Cannot inspect mountinfo", ph.render_audit(result))

    def test_known_denials_retained_if_mount_inspection_fails(self):
        self.subjects = [SUBJECT, MEMBER, VISITOR]
        self.nodes["/srv/file"] = metadata(0)
        self.mounts.side_effect = ph.DiagnosticError("Cannot inspect mountinfo")
        result = ph.audit_target("/srv/file")
        self.assertEqual(len(result.denied), 3)
        self.assertEqual(result.code, 0)
        self.assertIn("Inspection note (known denials retained)", ph.render_audit(result))

    def test_path_error_mid_audit_preserves_partial_results_and_code_two(self):
        diagnose = ph.diagnose
        def changed(path, subject, mode, **kwargs):
            if subject == VISITOR:
                return ph.Diagnosis(subject, path, mode,
                    ph.PathTrace(failure="Target disappeared", code=ph.ExitCode.INPUT),
                    code=ph.ExitCode.INPUT, reasons=["Target disappeared"])
            return diagnose(path, subject, mode, **kwargs)
        with patch.object(ph, "diagnose", side_effect=changed):
            result = ph.audit_target("/srv/file")
        self.assertEqual(len(result.permitted), 3)
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(result.code, 2)

    def test_missing_target_fails_preflight_even_if_all_subjects_would_be_blocked(self):
        self.preflight.side_effect = FileNotFoundError(errno.ENOENT, "missing", "/srv/file")
        result = ph.audit_target("/srv/file")
        self.assertEqual(result.code, 2)
        self.assertEqual(result.permitted + result.denied + result.errors, [])
        self.inventory.assert_not_called()

    def test_uninspectable_target_is_system_error_not_denial(self):
        self.preflight.side_effect = PermissionError(errno.EACCES, "denied", "/srv/file")
        result = ph.audit_target("/srv/file")
        self.assertEqual(result.code, 3)
        self.assertIn("Debugger cannot inspect", result.failure)

    def test_symlink_loop_preflight_is_path_error(self):
        self.preflight.side_effect = OSError(errno.ELOOP, "loop")
        self.assertEqual(ph.audit_target("/loop").code, 2)

    def test_empty_and_nul_paths_are_invalid(self):
        for path in ("", "/bad\x00"):
            self.assertEqual(ph.audit_target(path).code, 2)
        self.preflight.assert_not_called()

    def test_inventory_failure_is_global_system_error(self):
        self.inventory.side_effect = ph.DiagnosticError("Cannot read /etc/passwd")
        result = ph.audit_target("/srv/file")
        self.assertEqual(result.code, 3)
        self.assertIn("Cannot read /etc/passwd", result.failure)

    def test_empty_inventory_is_not_successful_audit(self):
        self.subjects = []
        result = ph.audit_target("/srv/file")
        self.assertEqual(result.code, 3)
        self.assertIn("No local accounts", result.failure)

    def test_compact_output_counts_and_mechanisms(self):
        result = ph.audit_target("/srv/file")
        text = ph.render_audit(result)
        self.assertIn("PERMISSION HELL v0.3 | ACCESS AUDIT", text)
        self.assertIn("Requested: READ (r)", text)
        self.assertIn("3 accounts permitted | 1 account denied | 0 account errors", text)
        self.assertIn("Access via OWNER", text)
        self.assertIn("supplementary group 200", text)
        self.assertIn("BLOCKED at '/srv/file'", text)
        self.assertIn("OTHER --- (neither owner nor in the owning group).", text)
        self.assertNotIn("no fallback to another class", text)
        self.assertNotIn("PATH (search x)", text)
        self.assertNotIn("Scope:", text)
        self.assertLessEqual(len(text.splitlines()), 24)

    def test_rendering_keeps_structured_data_unchanged(self):
        result = ph.audit_target("/srv/file")
        before = copy.deepcopy(result)
        ph.render_audit(result)
        self.assertEqual(result, before)


class AuditCliTest(unittest.TestCase):
    def test_parsing_default_read_and_explicit_modes(self):
        for mode in (None, "r", "w", "x"):
            result = ph.AuditReport("/file", mode or "r")
            with self.subTest(mode=mode), patch.object(ph.sys, "platform", "linux"), \
                    patch.object(ph, "audit_target", return_value=result) as audit, \
                    patch.object(ph, "resolve_subject") as resolve, \
                    contextlib.redirect_stdout(io.StringIO()):
                args = ["audit", "/file"] + (["--mode", mode] if mode else [])
                self.assertEqual(ph.main(args), 0)
                audit.assert_called_once_with("/file", mode or "r")
                resolve.assert_not_called()

    def test_cli_preserves_audit_exit_codes(self):
        for code in (0, 2, 3):
            result = ph.AuditReport("/file", "r", code=ph.ExitCode(code))
            with patch.object(ph.sys, "platform", "linux"), \
                    patch.object(ph, "audit_target", return_value=result), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(ph.main(["audit", "/file"]), code)

    def test_invalid_arguments(self):
        for args in (["audit"], ["audit", "/file", "--mode", "rw"], ["audit", "/file", "--as", "alice"]):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as error:
                ph.main(args)
            self.assertEqual(error.exception.code, 2)

    def test_unsupported_platform(self):
        with patch.object(ph.sys, "platform", "win32"), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ph.main(["audit", "/file"]), 3)

    def test_help_describes_local_scope(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as error:
            ph.main(["audit", "--help"])
        self.assertEqual(error.exception.code, 0)
        self.assertIn("service accounts", output.getvalue())
        self.assertIn("not intended policy", output.getvalue())


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux local-account integration")
class AuditLinuxIntegrationTest(unittest.TestCase):
    def test_actual_local_accounts_temporary_file_and_symlink(self):
        accounts = ph.enumerate_local_accounts()
        current = next((account for account in accounts if account.uid == os.getuid()), None)
        if current is None:
            self.skipTest("Current account has no explicit local /etc/passwd record")
        with tempfile.TemporaryDirectory(prefix="permissionhell-audit-") as directory:
            target = os.path.join(directory, "file")
            with open(target, "w") as output:
                output.write("audit fixture\n")
            link = os.path.join(directory, "alias")
            os.symlink("file", link)
            result = ph.audit_target(link)
            self.assertEqual(result.code, 0, ph.render_audit(result))
            self.assertEqual(len(result.permitted) + len(result.denied) + len(result.errors), len(accounts))
            owner = next(entry for entry in result.permitted if entry.account == current)
            self.assertEqual(owner.diagnosis.trace.resolved_path, target)
            command = [sys.executable, os.path.abspath(ph.__file__), "audit", link]
            process = subprocess.run(command, text=True, capture_output=True)
            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
            self.assertIn("ACCESS AUDIT", process.stdout)

    def test_real_broken_symlink_is_path_error(self):
        with tempfile.TemporaryDirectory(prefix="permissionhell-audit-") as directory:
            link = os.path.join(directory, "broken")
            os.symlink("missing", link)
            result = ph.audit_target(link)
            self.assertEqual(result.code, 2)
            self.assertIn("broken link", result.failure)


if __name__ == "__main__":
    unittest.main()
