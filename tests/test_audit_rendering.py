"""Audit display compression must not alter or merge distinct diagnoses."""

import contextlib
import copy
import io
import stat
import unittest
from unittest.mock import patch

import permissionhell as ph
from test_permissionhell import metadata, ROOT, MOUNTINFO
from test_posix_acl import make_acl, acl_metadata


def ordinary_accounts(count=20):
    return [ph.Subject(f"account_{i:02d}", 20000 + i, 600 + i, "own", (), ()) for i in range(count)]


def account_result(subject, *, mode="r", target_mode=0o644, acl=None,
                   parent_mode=0o755, root_mode=0o755, readonly=False):
    trace = ph.PathTrace()
    with patch.object(ph, "owner_name", side_effect=lambda uid: f"u{uid}"), \
            patch.object(ph, "group_name", side_effect=lambda gid: f"g{gid}"), \
            patch.object(ph, "read_access_acl", side_effect=lambda path: acl if path == "/data/file" else None):
        for path, permissions in (("/", root_mode), ("/data", parent_mode)):
            parent = ph.inspect_inode(path, metadata(permissions, uid=9000, gid=500, kind=stat.S_IFDIR), subject, "x")
            trace.events.append(parent)
            if not parent.decision.allowed:
                trace.failure = f"Traversal blocked at {path!r}: subject lacks execute/search permission."
                trace.code = ph.ExitCode.DENIED
                break
        else:
            meta = acl_metadata(acl, uid=9000, gid=500) if acl else metadata(target_mode, uid=9000, gid=500)
            trace.target = ph.inspect_inode("/data/file", meta, subject, mode)
            trace.resolved_path = "/data/file"
    mount = ph.parse_mountinfo(MOUNTINFO.replace("rw", "ro") if readonly else MOUNTINFO)[0]
    diagnosis = ph.Diagnosis(subject, "/data/file", mode, trace, mount=mount if trace.target else None)
    ph.determine_verdict(diagnosis)
    return ph.AccountAudit(ph.LocalAccount(subject.username, subject.uid, subject.primary_gid), diagnosis=diagnosis)


def report_for(results, mode="r"):
    report = ph.AuditReport("/data/file", mode)
    for result in results:
        if result.error:
            report.errors.append(result)
            report.code = ph.ExitCode.ERROR
        elif result.diagnosis.code == ph.ExitCode.ALLOWED:
            report.permitted.append(result)
        else:
            report.denied.append(result)
    return report


class AuditCompressionTest(unittest.TestCase):
    def test_many_identical_other_permits_are_one_summary(self):
        report = report_for([account_result(subject) for subject in ordinary_accounts()])
        text = ph.render_audit(report)
        self.assertIn("20 accounts with the same result", text)
        self.assertIn("sample: account_00, account_01, account_02; +17 more", text)
        self.assertEqual(text.count("Access via OTHER; effective: r--."), 1)
        self.assertIn("--verbose for the full account list", text)
        self.assertNotIn("account_19", text)

    def test_many_identical_other_denials_are_one_summary(self):
        report = report_for([account_result(subject, target_mode=0o600) for subject in ordinary_accounts()])
        text = ph.render_audit(report)
        self.assertIn("20 accounts with the same result", text)
        self.assertEqual(text.count("BLOCKED at '/data/file': missing READ."), 1)
        self.assertEqual(text.count("OTHER --- (neither owner nor in the owning group)."), 1)

    def test_owner_remains_individual(self):
        owner = ph.Subject("owner", 9000, 9000, "owner", (), ())
        report = report_for([account_result(owner)] + [account_result(s) for s in ordinary_accounts()])
        text = ph.render_audit(report)
        self.assertIn("  owner (UID 9000)", text)
        self.assertIn("Access via OWNER", text)
        self.assertIn("20 accounts with the same result", text)

    def test_named_user_acl_remains_individual(self):
        subject = ph.Subject("acl_user", 7001, 7001, "own", (), ())
        acl = make_acl(users=((7001, 6),), mask=4, other=4)
        report = report_for([account_result(subject, acl=acl)] +
                            [account_result(s, acl=acl) for s in ordinary_accounts()])
        text = ph.render_audit(report)
        self.assertIn("  acl_user (UID 7001)", text)
        self.assertIn("ACL NAMED USER: user:7001:rw-", text)
        self.assertIn("Mask: r--; effective: r--", text)
        self.assertIn("20 accounts with the same result", text)

    def test_named_group_acl_remains_individual(self):
        subject = ph.Subject("acl_group", 7002, 6004, "acl", (), ())
        acl = make_acl(groups=((6004, 4),), mask=4, other=4)
        report = report_for([account_result(subject, acl=acl)] +
                            [account_result(s, acl=acl) for s in ordinary_accounts()])
        text = ph.render_audit(report)
        self.assertIn("  acl_group (UID 7002)", text)
        self.assertIn("ACL GROUP: group:6004:r--", text)

    def test_supplementary_group_path_remains_individual(self):
        subject = ph.Subject("member", 7003, 7003, "own", (500,), ("media",))
        report = report_for([account_result(subject)] + [account_result(s) for s in ordinary_accounts()])
        text = ph.render_audit(report)
        self.assertIn("  member (UID 7003)", text)
        self.assertIn("supplementary group g500", text)
        self.assertIn("20 accounts with the same result", text)

    def test_root_remains_individual(self):
        report = report_for([account_result(ROOT)] + [account_result(s) for s in ordinary_accounts()])
        text = ph.render_audit(report)
        self.assertIn("  root (UID 0)", text)
        self.assertIn("Access via ROOT", text)
        self.assertIn("20 accounts with the same result", text)

    def test_root_override_remains_individual(self):
        report = report_for([account_result(ROOT, target_mode=0)] +
                            [account_result(s, target_mode=0) for s in ordinary_accounts()])
        text = ph.render_audit(report)
        self.assertIn("  root (UID 0)", text)
        self.assertIn("ROOT OVERRIDE", text)
        self.assertIn("20 accounts with the same result", text)

    def test_errors_remain_individual_even_with_identical_messages(self):
        errors = [ph.AccountAudit(ph.LocalAccount(f"broken_{i}", 8000 + i, 8000), error="Group lookup failed")
                  for i in range(5)]
        report = report_for([account_result(s) for s in ordinary_accounts()] + errors)
        text = ph.render_audit(report)
        for error in errors:
            self.assertIn(f"  {error.account.username} (UID {error.account.uid})", text)
        self.assertEqual(text.count("Group lookup failed"), 5)
        self.assertEqual(report.code, 3)

    def test_mount_restrictions_remain_individual(self):
        report = report_for([account_result(s, mode="w", target_mode=0o666, readonly=True)
                            for s in ordinary_accounts(5)], mode="w")
        text = ph.render_audit(report)
        self.assertNotIn("accounts with the same result", text)
        self.assertEqual(text.count("BLOCKED by mount"), 5)

    def test_additional_mount_restriction_after_dac_denial_stays_individual(self):
        report = report_for([account_result(s, mode="w", readonly=True)
                            for s in ordinary_accounts(5)], mode="w")
        self.assertNotIn("accounts with the same result", ph.render_audit(report))

    def test_less_common_traversal_failure_locations_remain_individual(self):
        subjects = ordinary_accounts(23)
        common = [account_result(s, parent_mode=0o700) for s in subjects[:20]]
        unusual = [account_result(s, root_mode=0o700) for s in subjects[20:]]
        text = ph.render_audit(report_for(common + unusual))
        self.assertIn("20 accounts with the same result", text)
        self.assertEqual(text.count("BLOCKED at '/data': missing EXECUTE/SEARCH"), 1)
        self.assertEqual(text.count("BLOCKED at '/': missing EXECUTE/SEARCH"), 3)
        for subject in subjects[20:]:
            self.assertIn(f"  {subject.username} (UID {subject.uid})", text)

    def test_same_short_reason_different_inode_observation_is_not_merged(self):
        subjects = ordinary_accounts(23)
        common = [account_result(s) for s in subjects[:20]]
        changed = [account_result(s, target_mode=0o664) for s in subjects[20:]]
        text = ph.render_audit(report_for(common + changed))
        self.assertIn("20 accounts with the same result", text)
        for subject in subjects[20:]:
            self.assertIn(f"  {subject.username} (UID {subject.uid})", text)

    def test_verbose_shows_every_account_without_groups(self):
        subjects = ordinary_accounts()
        report = report_for([account_result(s) for s in subjects])
        text = ph.render_audit(report, verbose=True)
        for subject in subjects:
            self.assertIn(f"  {subject.username} (UID {subject.uid})", text)
        self.assertEqual(text.count("Access via OTHER; effective: r--."), 20)
        self.assertNotIn("accounts with the same result", text)

    def test_totals_and_analysis_unchanged_in_both_views(self):
        results = [account_result(s) for s in ordinary_accounts(10)]
        results += [account_result(s, target_mode=0) for s in ordinary_accounts(7)]
        results += [ph.AccountAudit(ph.LocalAccount("broken", 8888, 8888), error="unavailable")]
        report = report_for(results)
        before = copy.deepcopy(report)
        for verbose in (False, True):
            text = ph.render_audit(report, verbose=verbose)
            self.assertIn("10 accounts permitted | 7 accounts denied | 1 account error", text)
            self.assertEqual(report, before)

    def test_small_audits_do_not_group_pairs(self):
        text = ph.render_audit(report_for([account_result(s) for s in ordinary_accounts(2)]))
        self.assertNotIn("accounts with the same result", text)
        self.assertIn("account_00 (UID", text)
        self.assertIn("account_01 (UID", text)


class AuditVerboseCliTest(unittest.TestCase):
    def test_verbose_reaches_renderer_without_changing_evaluation_or_exit_code(self):
        for verbose in (False, True):
            for code in (ph.ExitCode.ALLOWED, ph.ExitCode.INPUT, ph.ExitCode.ERROR):
                with self.subTest(verbose=verbose, code=code):
                    report = ph.AuditReport("/data/file", "r", code=code)
                    with patch.object(ph.sys, "platform", "linux"), \
                            patch.object(ph, "audit_target", return_value=report) as audit, \
                            patch.object(ph, "render_audit", return_value="audit") as render, \
                            contextlib.redirect_stdout(io.StringIO()):
                        args = ["audit", "/data/file"] + (["--verbose"] if verbose else [])
                        self.assertEqual(ph.main(args), code)
                        audit.assert_called_once_with("/data/file", "r")
                        render.assert_called_once_with(report, verbose=verbose)

    def test_audit_help_exposes_verbose(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit):
            ph.main(["audit", "--help"])
        self.assertIn("--verbose", output.getvalue())
        self.assertIn("without grouping", output.getvalue())


if __name__ == "__main__":
    unittest.main()
