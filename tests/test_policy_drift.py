"""Policy syntax, domain scoping, existing access engines and comparison output."""
import contextlib
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

import permissionhell as ph
import policy_drift as pd
import process_audit as pa
import process_subject as ps
import json_output as jo
from test_permissionhell import SUBJECT, ROOT
from test_audit_rendering import account_result, report_for
from test_posix_acl import make_acl
from test_capabilities import evaluate
from test_idmap import evaluate as mapped_evaluate, foreign
from test_process_audit import failed


def raw_policy(check=None, path="/data/file"):
    return {"policy_version": 1, "resources": [{"path": path, "checks": [check or {"mode": "r", "accounts": {"allow": ["alice"]}}]}]}


def parsed(check=None):
    return pd.parse_policy(json.dumps(raw_policy(check)))


def run(check, *, accounts=None, processes=None):
    accounts, processes = accounts or {}, processes or {}
    def resolve(name):
        if name not in accounts:
            raise ph.DiagnosticError(f"No such user: {name!r}", ph.ExitCode.INPUT)
        return accounts[name].subject
    with patch.object(ph, "inspect_audit_target"), patch.object(ph, "resolve_subject", side_effect=resolve), \
            patch.object(ph, "diagnose", side_effect=lambda path, subject, mode: accounts[subject.username]), \
            patch.object(ph, "diagnose_process", side_effect=lambda path, pid, mode: processes[pid]):
        return pd.evaluate_policy(parsed(check), "policy.json", engine=ph)


def account_run(expected="allow", **kwargs):
    diagnosis = account_result(SUBJECT, **kwargs).diagnosis
    return run({"mode": diagnosis.mode, "accounts": {expected: ["alice"]}}, accounts={"alice": diagnosis})


def process_run(expected="allow", report=None):
    report = report or evaluate(permissions=4)
    return run({"mode": report.mode, "processes": {expected: [42]}}, processes={42: report})


class ParsingTests(unittest.TestCase):
    def reject(self, value):
        with self.assertRaises(pd.PolicyError):
            pd.parse_policy(json.dumps(value))

    def test_valid_version_one(self):
        policy = parsed()
        self.assertEqual(policy.policy_version, 1)
        self.assertEqual(policy.resources[0].checks[0].accounts.allow, ("alice",))

    def test_process_domain_explicit(self):
        check = parsed({"mode": "x", "processes": {"allow": [42]}}).resources[0].checks[0]
        self.assertIsNone(check.accounts)
        self.assertEqual(check.processes.allow, (42,))

    def test_unsupported_versions(self):
        for version in (0, 2, True, 1.0, "1", None):
            data = raw_policy()
            data["policy_version"] = version
            self.reject(data)

    def test_malformed_json(self):
        for text in ("", "{", "[]", "null", '{"policy_version":NaN}', '{"policy_version":Infinity}'):
            with self.subTest(text=text), self.assertRaises(pd.PolicyError):
                pd.parse_policy(text)

    def test_duplicate_object_keys(self):
        with self.assertRaisesRegex(pd.PolicyError, "Duplicate JSON key"):
            pd.parse_policy('{"policy_version":1,"policy_version":1,"resources":[]}')

    def test_required_fields(self):
        self.reject({"policy_version": 1})
        self.reject({"resources": []})
        self.reject({"policy_version": 1, "resources": [{"checks": []}]})
        self.reject(raw_policy({"accounts": {"allow": ["a"]}}))

    def test_unknown_keys_rejected(self):
        data = raw_policy()
        data["typo"] = True
        self.reject(data)
        self.reject(raw_policy({"mode": "r", "accounts": {"allow": ["a"], "deny_other": True}}))
        self.reject(raw_policy({"mode": "r", "groups": {"allow": ["staff"]}}))

    def test_invalid_modes(self):
        for mode in ("rw", "", "READ", 4, [], None):
            self.reject(raw_policy({"mode": mode, "accounts": {"allow": ["a"]}}))

    def test_invalid_paths(self):
        for path in ("", "relative", 12, None, "/bad\0path", "/bad\ud800"):
            self.reject(raw_policy(path=path))

    def test_path_not_normalized_before_traversal(self):
        value = pd.parse_policy(json.dumps(raw_policy(path="/blocked/../file")))
        self.assertEqual(value.resources[0].path, "/blocked/../file")

    def test_invalid_pids(self):
        for pid in (0, -1, True, 3.0, "42", None, [], 0x80000000):
            self.reject(raw_policy({"mode": "r", "processes": {"allow": [pid]}}))

    def test_invalid_account_names(self):
        for name in ("", 1001, None, "bad name", "bad\nname", "bad\0name", []):
            self.reject(raw_policy({"mode": "r", "accounts": {"allow": [name]}}))

    def test_duplicate_subjects(self):
        self.reject(raw_policy({"mode": "r", "accounts": {"allow": ["a", "a"]}}))
        self.reject(raw_policy({"mode": "r", "processes": {"deny": [42, 42]}}))

    def test_contradictions(self):
        self.reject(raw_policy({"mode": "r", "accounts": {"allow": ["a"], "deny": ["a"]}}))
        self.reject(raw_policy({"mode": "r", "processes": {"allow": [42], "deny": [42]}}))

    def test_empty_and_bad_structures(self):
        for resources in ([], {}, None, [False]):
            self.reject({"policy_version": 1, "resources": resources})
        for scope in ({}, [], None, {"allow": "alice"}, {"deny_others": 1}):
            self.reject(raw_policy({"mode": "r", "accounts": scope}))

    def test_deny_others_only_scope_valid(self):
        scope = parsed({"mode": "r", "accounts": {"deny_others": True}}).resources[0].checks[0].accounts
        self.assertEqual(scope.allow, ())
        self.assertTrue(scope.deny_others)

    def test_duplicate_resources_and_modes(self):
        data = raw_policy()
        data["resources"].append(data["resources"][0])
        self.reject(data)
        data = raw_policy()
        data["resources"][0]["checks"] *= 2
        self.reject(data)

    def test_whole_document_validated_before_evaluation(self):
        with patch.object(pd.Path, "read_text", return_value=json.dumps(raw_policy({"mode": "oops"}))), \
                patch.object(ph, "diagnose") as evaluate_account:
            report = pd.check_policy_file("policy.json")
        self.assertEqual(report.code, 2)
        evaluate_account.assert_not_called()

    def test_invalid_utf8_policy(self):
        with patch.object(pd.Path, "read_text", side_effect=UnicodeError("invalid UTF-8")):
            self.assertEqual(pd.check_policy_file("policy.json").code, 2)

    def test_unreadable_policy(self):
        with patch.object(pd.Path, "read_text", side_effect=PermissionError("policy inaccessible")):
            self.assertEqual(pd.check_policy_file("policy.json").code, 3)

    def test_missing_policy(self):
        with patch.object(pd.Path, "read_text", side_effect=FileNotFoundError):
            self.assertEqual(pd.check_policy_file("missing.json").code, 2)


class AccountComparisonTests(unittest.TestCase):
    def test_allow_permit_match(self):
        self.assertEqual(account_run().summary.matches, 1)
        self.assertEqual(account_run().code, 0)

    def test_deny_denied_match(self):
        self.assertEqual(account_run("deny", target_mode=0).summary.matches, 1)

    def test_missing_access(self):
        report = account_run(target_mode=0)
        self.assertEqual(report.summary.missing_access, 1)
        self.assertEqual(report.code, 1)

    def test_unexpected_access(self):
        report = account_run("deny")
        self.assertEqual(report.summary.unexpected_access, 1)
        self.assertEqual(report.code, 1)

    def test_unknown_user_policy_error(self):
        report = run({"mode": "r", "accounts": {"allow": ["missing"]}})
        self.assertEqual(report.summary.policy_errors, 1)
        self.assertEqual(report.code, 2)

    def test_group_lookup_error_indeterminate(self):
        with patch.object(ph, "inspect_audit_target"), patch.object(ph, "resolve_subject", side_effect=OSError("NSS down")):
            report = pd.evaluate_policy(parsed())
        self.assertEqual(report.summary.indeterminate, 1)
        self.assertEqual(report.code, 3)

    def test_owner_group_supplementary_root(self):
        for subject, phrase in ((replace(SUBJECT, uid=9000), "OWNER"),
                                (replace(SUBJECT, primary_gid=500), "primary GID 500"),
                                (replace(SUBJECT, supplementary_gids=(500,), supplementary_groups=("media",)), "supplementary GID 500"),
                                (replace(ROOT, username="alice"), "ROOT model")):
            diagnosis = account_result(subject, target_mode=0o640).diagnosis
            report = run({"mode": "r", "accounts": {"deny": ["alice"]}}, accounts={"alice": diagnosis})
            self.assertEqual(report.summary.unexpected_access, 1)
            self.assertIn(phrase, pd.render_policy(report, ph.__version__))

    def test_acl_mechanism(self):
        report = account_run("deny", acl=make_acl(users=((1001, 4),), mask=4))
        self.assertIn("via ACL named user", pd.render_policy(report, ph.__version__))
        self.assertEqual(pd.decision_details(report.resources[0].results[0])["mechanism"], "posix_acl")

    def test_mask_missing_access(self):
        report = account_run(mode="w", acl=make_acl(users=((1001, 6),), mask=4))
        data = pd.policy_document(report, ph.__version__)["resources"][0]["results"][0]
        self.assertEqual(data["drift"], "missing_access")
        self.assertTrue(data["effective"]["target_inode"]["acl"]["mask_reduced_requested_rights"])

    def test_mount_denial(self):
        report = account_run(target_mode=0o666, mode="w", readonly=True)
        details = pd.decision_details(report.resources[0].results[0])
        self.assertEqual(details["blocker"]["stage"], "mount")
        self.assertEqual(details["mechanism"], "mount")

    def test_parent_blocker(self):
        report = account_run(parent_mode=0)
        text = pd.render_policy(report, ph.__version__)
        self.assertIn("blocker: '/data' (traversal)", text)
        self.assertIn("execute/search", text)

    def test_unknown_access_never_matches_deny(self):
        for actual in ("unknown", "error", "indeterminate", "unavailable", "invalid_input"):
            self.assertEqual(pd.compare_access("deny", actual), "indeterminate")

    def test_missing_resource_is_policy_error(self):
        with patch.object(ph, "inspect_audit_target", side_effect=ph.DiagnosticError("target missing", ph.ExitCode.INPUT)):
            report = pd.evaluate_policy(parsed())
        self.assertEqual(report.code, 2)
        self.assertEqual(report.resources[0].results[0].subject, "alice")


class DenyOthersTests(unittest.TestCase):
    def test_account_allowlist_and_extras_without_process_scope(self):
        bob = replace(SUBJECT, username="bob")
        carol = replace(SUBJECT, username="carol")
        audit = report_for([account_result(SUBJECT), account_result(bob), account_result(carol, target_mode=0)])
        with patch.object(ph, "inspect_audit_target"), patch.object(ph, "audit_target", return_value=audit) as runner, \
                patch.object(ph, "diagnose") as diagnose, patch.object(pa, "audit_processes") as processes:
            report = pd.evaluate_policy(parsed({"mode": "r", "accounts": {"allow": ["alice"], "deny_others": True}}))
        self.assertEqual(report.summary, pd.DriftSummary(3, 2, 1, 0, 0, 0, 2))
        runner.assert_called_once_with("/data/file", "r")
        diagnose.assert_not_called()
        processes.assert_not_called()

    def test_explicit_deny_not_duplicate_extra(self):
        bob = replace(SUBJECT, username="bob")
        audit = report_for([account_result(SUBJECT), account_result(bob)])
        with patch.object(ph, "inspect_audit_target"), patch.object(ph, "audit_target", return_value=audit):
            report = pd.evaluate_policy(parsed({"mode": "r", "accounts": {"allow": ["alice"], "deny": ["bob"], "deny_others": True}}))
        self.assertEqual(report.summary.checks, 2)
        self.assertEqual(report.summary.extra_subjects, 0)

    def test_explicit_nss_account_outside_local_inventory(self):
        audit = report_for([account_result(replace(SUBJECT, username="local"))])
        with patch.object(ph, "inspect_audit_target"), patch.object(ph, "audit_target", return_value=audit), \
                patch.object(ph, "resolve_subject", return_value=SUBJECT), patch.object(ph, "diagnose", return_value=account_result(SUBJECT).diagnosis):
            report = pd.evaluate_policy(parsed({"mode": "r", "accounts": {"allow": ["alice"], "deny_others": True}}))
        self.assertEqual(report.summary.checks, 2)
        self.assertEqual(report.summary.matches, 1)

    def test_audit_account_error_conservative(self):
        audit = ph.AuditReport("/data/file", "r")
        audit.errors.append(ph.AccountAudit(ph.LocalAccount("alice", 1001, 100), error="ACL unavailable"))
        audit.code = ph.ExitCode.ERROR
        with patch.object(ph, "inspect_audit_target"), patch.object(ph, "audit_target", return_value=audit):
            report = pd.evaluate_policy(parsed({"mode": "r", "accounts": {"deny_others": True}}))
        self.assertEqual(report.summary.indeterminate, 1)
        self.assertEqual(report.code, 3)

    def test_inventory_failure_not_vacuous_match(self):
        audit = ph.AuditReport("/data/file", "r", failure="inventory unavailable", code=ph.ExitCode.ERROR)
        with patch.object(ph, "inspect_audit_target"), patch.object(ph, "audit_target", return_value=audit):
            report = pd.evaluate_policy(parsed({"mode": "r", "accounts": {"deny_others": True}}))
        self.assertEqual(report.code, 3)
        self.assertEqual(report.resources[0].results[0].subject_type, "scope")

    def test_process_deny_others_does_not_enumerate_accounts(self):
        permitted = pa.classify(evaluate(2))
        denied = replace(pa.classify(evaluate()), pid=43)
        audit = pa.ProcessAuditResult("/data/file", entries=[permitted, denied], discovered=2)
        with patch.object(ph, "inspect_audit_target"), patch.object(pa, "audit_processes", return_value=audit) as runner, \
                patch.object(ph, "audit_target") as account_audit, patch.object(ph, "diagnose_process") as diagnose:
            report = pd.evaluate_policy(parsed({"mode": "r", "processes": {"allow": [42], "deny_others": True}}))
        self.assertEqual(report.summary.matches, 2)
        self.assertEqual(report.summary.extra_subjects, 1)
        self.assertFalse(runner.call_args.kwargs.get("include_cmdline", False))
        account_audit.assert_not_called()
        diagnose.assert_not_called()

    def test_transient_extra_process_still_incomplete_policy(self):
        audit = pa.ProcessAuditResult("/data/file", entries=[pa.classify(failed("exited"))], discovered=1)
        with patch.object(ph, "inspect_audit_target"), patch.object(pa, "audit_processes", return_value=audit):
            report = pd.evaluate_policy(parsed({"mode": "r", "processes": {"deny_others": True}}))
        self.assertEqual(report.code, 3)
        self.assertEqual(report.summary.extra_subjects, 1)

    def test_process_inventory_error_scope_record(self):
        audit = pa.ProcessAuditResult("/data/file", failure="procfs hidden", code=3)
        with patch.object(ph, "inspect_audit_target"), patch.object(pa, "audit_processes", return_value=audit):
            report = pd.evaluate_policy(parsed({"mode": "r", "processes": {"deny_others": True}}))
        self.assertEqual(report.code, 3)
        self.assertIn("procfs hidden", pd.render_policy(report, ph.__version__))

    def test_process_deny_others_unexpected_capability_access(self):
        audit = pa.ProcessAuditResult("/data/file", entries=[pa.classify(evaluate(4))], discovered=1)
        with patch.object(ph, "inspect_audit_target"), patch.object(pa, "audit_processes", return_value=audit):
            report = pd.evaluate_policy(parsed({"mode": "r", "processes": {"deny_others": True}}))
        self.assertEqual(report.summary.unexpected_access, 1)
        self.assertEqual(report.summary.extra_subjects, 1)
        self.assertIn("CAP_DAC_READ_SEARCH", pd.render_policy(report, ph.__version__))

    def test_explicit_pid_outside_inventory_is_still_checked(self):
        audit = pa.ProcessAuditResult("/data/file", entries=[replace(pa.classify(evaluate()), pid=43)], discovered=1)
        diagnosis = evaluate(permissions=4)
        with patch.object(ph, "inspect_audit_target"), patch.object(pa, "audit_processes", return_value=audit), \
                patch.object(ph, "diagnose_process", return_value=diagnosis) as runner:
            report = pd.evaluate_policy(parsed({"mode": "r", "processes": {"allow": [42], "deny_others": True}}))
        runner.assert_called_once_with("/data/file", 42, "r")
        self.assertEqual(report.summary.matches, 2)


class ProcessComparisonTests(unittest.TestCase):
    def test_allow_permitted_match(self):
        self.assertEqual(process_run().code, 0)

    def test_deny_denied_match(self):
        self.assertEqual(process_run("deny", evaluate()).summary.matches, 1)

    def test_missing_access(self):
        self.assertEqual(process_run(report=evaluate()).summary.missing_access, 1)

    def test_unexpected_access(self):
        self.assertEqual(process_run("deny").summary.unexpected_access, 1)

    def test_capability_unexpected_access(self):
        for mask, name in ((2, "CAP_DAC_OVERRIDE"), (4, "CAP_DAC_READ_SEARCH")):
            report = process_run("deny", evaluate(mask))
            self.assertEqual(report.summary.unexpected_access, 1)
            self.assertIn(name, pd.render_policy(report, ph.__version__))
            self.assertEqual(pd.decision_details(report.resources[0].results[0])["mechanism"], "capability")

    def test_capability_on_parent_preserved(self):
        report = process_run("deny", evaluate(2, permissions=4, parent_permissions=0))
        self.assertIn("CAP_DAC_OVERRIDE at '/data'", pd.render_policy(report, ph.__version__))

    def test_readonly_mount_after_capability(self):
        report = process_run(report=evaluate(2, mode="w", readonly=True))
        self.assertEqual(report.summary.missing_access, 1)
        self.assertIn("READ-ONLY", pd.render_policy(report, ph.__version__))

    def test_mapped_uid_and_gid(self):
        for diagnosis in (mapped_evaluate(owner=100000), mapped_evaluate(group=100010, permissions=0o640)):
            report = process_run(report=diagnosis)
            self.assertEqual(report.summary.matches, 1)
            effective = report.resources[0].results[0].effective
            self.assertEqual(effective["process"]["filesystem_identity"]["fsuid"]["mapped"], 100000)

    def test_foreign_capability_indeterminate(self):
        report = process_run(report=mapped_evaluate(foreign(capability=2)))
        self.assertEqual(report.summary.indeterminate, 1)
        self.assertEqual(report.code, 3)

    def test_foreign_mount_indeterminate(self):
        observed = replace(foreign(), mount_namespace=ps.NamespaceObservation("mnt:[9]", "mnt:[1]", False))
        report = process_run(report=mapped_evaluate(observed))
        self.assertEqual(report.summary.indeterminate, 1)
        self.assertIn("mount namespace", pd.render_policy(report, ph.__version__))

    def test_disappeared_never_matches_deny(self):
        report = process_run("deny", failed("exited"))
        self.assertEqual(report.summary.indeterminate, 1)
        self.assertEqual(report.resources[0].results[0].actual, "unavailable")

    def test_inaccessible_process(self):
        report = process_run(report=failed("proc_permission"))
        self.assertEqual(report.code, 3)

    def test_missing_pid_indeterminate_not_missing_access(self):
        report = process_run(report=failed("not_visible", code=2))
        self.assertEqual(report.summary.indeterminate, 1)
        self.assertEqual(report.summary.policy_errors, 0)

    def test_pid_reuse_no_stale_identity(self):
        report = process_run(report=failed("identity_changed"))
        self.assertEqual(report.resources[0].results[0].effective["process"], None)
        self.assertEqual(report.code, 3)


class SummaryAndOutputTests(unittest.TestCase):
    def test_multiple_resources_modes_and_domains(self):
        data = raw_policy({"mode": "r", "accounts": {"allow": ["alice"]}, "processes": {"allow": [42]}})
        data["resources"][0]["checks"].append({"mode": "w", "accounts": {"deny": ["alice"]}})
        data["resources"].append({"path": "/other", "checks": [{"mode": "x", "accounts": {"allow": ["alice"]}}]})
        process_report = evaluate(permissions=4)
        with patch.object(ph, "inspect_audit_target"), patch.object(ph, "resolve_subject", return_value=SUBJECT), \
                patch.object(ph, "diagnose", side_effect=[account_result(SUBJECT).diagnosis, account_result(SUBJECT, mode="w").diagnosis,
                                                        account_result(SUBJECT, mode="x", target_mode=0o755).diagnosis]), \
                patch.object(ph, "diagnose_process", return_value=process_report):
            report = pd.evaluate_policy(pd.parse_policy(json.dumps(data)))
        self.assertEqual(len(report.resources), 3)
        self.assertEqual(report.summary.checks, 4)
        self.assertEqual(report.summary.matches, 4)

    def test_exit_precedence_invalid_over_incomplete_over_drift(self):
        report = account_run("deny")
        report.errors.append({"drift": "indeterminate", "message": "uncertain"})
        self.assertEqual(report.code, 3)
        report.errors.append({"drift": "policy_error", "message": "invalid"})
        self.assertEqual(report.code, 2)

    def test_continue_after_unresolved_resource(self):
        data = raw_policy()
        data["resources"].append({"path": "/second", "checks": [{"mode": "r", "accounts": {"allow": ["alice"]}}]})
        with patch.object(ph, "inspect_audit_target", side_effect=[ph.DiagnosticError("missing", ph.ExitCode.INPUT), None]), \
                patch.object(ph, "resolve_subject", return_value=SUBJECT), patch.object(ph, "diagnose", return_value=account_result(SUBJECT).diagnosis):
            report = pd.evaluate_policy(pd.parse_policy(json.dumps(data)))
        self.assertEqual(report.summary.policy_errors, 1)
        self.assertEqual(report.summary.matches, 1)

    def test_concise_statuses_and_summary(self):
        for report, word in ((account_run(), "MATCH"), (account_run("deny"), "UNEXPECTED_ACCESS"),
                             (account_run(target_mode=0), "MISSING_ACCESS"), (process_run(report=failed("exited")), "INDETERMINATE")):
            text = pd.render_policy(report, ph.__version__)
            self.assertIn(word, text)
            self.assertIn("expected:", text)
            self.assertIn("actual:", text)
            self.assertIn("SUMMARY", text)

    def test_verbose_underlying_details(self):
        report = process_run("deny", evaluate(2))
        text = pd.render_policy(report, ph.__version__, verbose=True)
        self.assertIn("base_result", text)
        self.assertIn("capability_override", text)
        self.assertNotIn("Effective observation:", pd.render_policy(report, ph.__version__))

    def test_json_keeps_every_result(self):
        report = account_run("deny")
        report.resources[0].results.append(replace(report.resources[0].results[0], subject="bob", extra=True))
        data = json.loads(jo.render_json(pd.policy_document(report, ph.__version__)))
        self.assertEqual(data["schema_version"], "1")
        self.assertEqual(data["policy_version"], 1)
        self.assertEqual(data["command"], "policy-check")
        self.assertEqual(len(data["resources"][0]["results"]), 2)
        self.assertEqual(data["summary"]["unexpected_access"], 2)
        self.assertEqual(data["summary"]["extra_subjects"], 1)

    def test_json_subject_types_expectation_mechanism_blocker(self):
        data = pd.policy_document(account_run(target_mode=0), ph.__version__)["resources"][0]["results"][0]
        self.assertEqual((data["subject_type"], data["expected"], data["actual"]), ("account", "allow", "denied"))
        self.assertEqual(data["mechanism"], "unix_dac")
        self.assertEqual(data["blocker"]["path"], "/data/file")
        data = pd.policy_document(process_run(), ph.__version__)["resources"][0]["results"][0]
        self.assertEqual((data["subject_type"], data["subject"]), ("process", 42))

    def test_implicit_matches_compact_but_json_and_verbose_complete(self):
        report = account_run("deny", target_mode=0)
        source = report.resources[0].results[0]
        report.resources[0].results = [replace(source, subject=f"extra{i}", extra=True) for i in range(10)]
        self.assertIn("10 other subjects match DENY", pd.render_policy(report, ph.__version__))
        self.assertNotIn("extra9", pd.render_policy(report, ph.__version__))
        self.assertIn("extra9", pd.render_policy(report, ph.__version__, verbose=True))
        self.assertEqual(len(pd.policy_document(report, ph.__version__)["resources"][0]["results"]), 10)

    def test_policy_verbose_does_not_read_command_lines(self):
        report = process_run()
        with patch.object(pa, "collect_cmdline", side_effect=AssertionError("unexpected command line read")), \
                patch.object(pd.Path, "read_bytes", side_effect=AssertionError("unexpected process read")):
            text = pd.render_policy(report, ph.__version__, verbose=True)
        self.assertIn("PID 42 'worker'", text)

    def test_unavailable_target_preserves_both_domain_declarations(self):
        policy = parsed({"mode": "r", "accounts": {"allow": ["alice"], "deny_others": True}, "processes": {"deny": [42]}})
        with patch.object(ph, "inspect_audit_target", side_effect=ph.DiagnosticError("resource absent", ph.ExitCode.INPUT)):
            report = pd.evaluate_policy(policy)
        self.assertEqual(report.summary.policy_errors, 3)
        self.assertEqual([result.subject_type for result in report.resources[0].results], ["account", "scope", "process"])

    def test_resource_metadata_error_is_incomplete_not_policy_error(self):
        with patch.object(ph, "inspect_audit_target", side_effect=ph.DiagnosticError("metadata unavailable")):
            report = pd.evaluate_policy(parsed())
        self.assertEqual(report.code, 3)
        self.assertEqual(report.summary.policy_errors, 0)

    def test_cli_json(self):
        with patch.object(ph.sys, "platform", "linux"), patch.object(pd, "check_policy_file", return_value=account_run("deny")), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            code = ph.main(["policy-check", "policy.json", "--json"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue())["command"], "policy-check")

    def test_unsupported_platform_json(self):
        with patch.object(ph.sys, "platform", "win32"), contextlib.redirect_stdout(io.StringIO()) as output:
            code = ph.main(["policy-check", "policy.json", "--json"])
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(output.getvalue())["summary"]["indeterminate"], 1)

    def test_cli_invalid_policy_no_traceback(self):
        with patch.object(ph.sys, "platform", "linux"), patch.object(pd.Path, "read_text", return_value="{"), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            code = ph.main(["policy-check", "policy.json", "--json"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["summary"]["policy_errors"], 1)


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux policy integration")
class IntegrationTests(unittest.TestCase):
    def test_current_account_and_process_temporary_policy(self):
        import pwd
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "resource"
            target.write_text("test-owned resource")
            policy = Path(directory) / "policy.json"
            policy.write_text(json.dumps(raw_policy({"mode": "r", "accounts": {"allow": [pwd.getpwuid(os.getuid()).pw_name]},
                                                     "processes": {"allow": [os.getpid()]}}, str(target))))
            completed = subprocess.run([sys.executable, ph.__file__, "policy-check", str(policy), "--json"], capture_output=True, text=True)
            document = json.loads(completed.stdout)
        self.assertEqual(document["summary"]["checks"], 2)
        self.assertEqual(document["summary"]["matches"], 2)
        self.assertEqual(completed.returncode, 0)
