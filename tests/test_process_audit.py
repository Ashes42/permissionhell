"""Process inventory, shared engine decisions, presentation and read-only Linux smoke tests."""
import contextlib
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import permissionhell as ph
import process_audit as audit
import process_subject as ps
import json_output as jo
from test_capabilities import evaluate, process_with
from test_idmap import evaluate as mapped_evaluate, foreign
from test_process_subject import PID, snapshot, proc_text, proc_link
from test_posix_acl import make_acl


def run_reports(reports, **kwargs):
    with patch.object(ph, "inspect_audit_target"), patch.object(audit, "enumerate_pids", return_value=[r.pid for r in reports]), \
            patch.object(ph, "diagnose_process", side_effect=reports):
        return audit.audit_processes("/data/file", reports[0].mode if reports else "r", engine=ph, **kwargs)


def failed(kind, *, code=3, process=None):
    return ph.ProcessDiagnosis("/data/file", PID, "r", process=process, code=code,
                               inspection_kind=kind, limitations=[f"inspection: {kind}"])


def with_pid(report, pid):
    return replace(report, pid=pid, process=replace(report.process, pid=pid) if report.process else None)


class EnumerationTests(unittest.TestCase):
    def test_numeric_entries_only_sorted_unique(self):
        entries = [SimpleNamespace(name=name) for name in ("self", "thread-self", "sys", "20", "1", "0", "-3", "٤", "999999999999")]
        with patch.object(audit.os, "scandir") as scan:
            scan.return_value.__enter__.return_value = iter(entries)
            self.assertEqual(audit.enumerate_pids(), [1, 20])
            scan.assert_called_once_with("/proc")

    def test_enumeration_failure(self):
        with patch.object(ph, "inspect_audit_target"), patch.object(audit, "enumerate_pids", side_effect=PermissionError("hidepid")):
            result = audit.audit_processes("/data/file")
        self.assertEqual(result.code, 3)
        self.assertIn("hidepid", result.failure)

    def test_empty_inventory_incomplete(self):
        self.assertEqual(run_reports([]).code, 3)

    def test_pid_filter_deduplicates_without_enumerating(self):
        with patch.object(ph, "inspect_audit_target"), patch.object(audit, "enumerate_pids") as scan, \
                patch.object(ph, "diagnose_process", return_value=evaluate(permissions=4)) as evaluate_pid:
            result = audit.audit_processes("/data/file", pids=[42, 42], engine=ph)
        scan.assert_not_called()
        evaluate_pid.assert_called_once_with("/data/file", 42, "r")
        self.assertEqual(result.summary.discovered, 1)

    def test_missing_explicit_pid_not_assumed_exited(self):
        result = run_reports([failed("not_visible", code=2)], pids=[PID])
        self.assertEqual(result.code, 3)
        self.assertEqual(result.entries[0].verdict, "unavailable")
        self.assertFalse(result.entries[0].transient)

    def test_invalid_pid_api(self):
        with patch.object(ph, "inspect_audit_target"):
            for pid in (0, -1, True, "42", 0x80000000):
                self.assertEqual(audit.audit_processes("/data/file", pids=[pid]).code, 2)

    def test_relative_target(self):
        self.assertEqual(audit.audit_processes("relative").code, 2)

    def test_unresolved_target(self):
        with patch.object(ph.os, "stat", side_effect=FileNotFoundError), patch.object(audit, "enumerate_pids") as scan:
            result = audit.audit_processes("/no/file")
        self.assertEqual(result.code, 2)
        scan.assert_not_called()

    def test_target_metadata_denied(self):
        with patch.object(ph.os, "stat", side_effect=PermissionError):
            self.assertEqual(audit.audit_processes("/no/file").code, 3)


class RaceAndFailureTests(unittest.TestCase):
    def test_disappearance_before_initial_stat(self):
        with patch.object(ps, "start_time", side_effect=FileNotFoundError):
            report = ph.diagnose_process("/data/file", PID)
        self.assertEqual(audit.classify(report).verdict, "unavailable")
        self.assertFalse(audit.classify(report).transient)

    def test_exit_before_status_read(self):
        with patch.object(ps, "start_time", return_value=123), patch.object(ps, "read_text", side_effect=FileNotFoundError), \
                patch.object(ps.os, "stat", side_effect=FileNotFoundError):
            report = ph.diagnose_process("/data/file", PID)
        result = run_reports([report])
        self.assertEqual(result.code, 0)
        self.assertTrue(result.entries[0].transient)

    def test_missing_metadata_for_existing_pid_is_error(self):
        with patch.object(ps, "start_time", return_value=123), patch.object(ps, "read_text", side_effect=FileNotFoundError), \
                patch.object(ps.os, "stat", return_value=object()):
            report = ph.diagnose_process("/data/file", PID)
        self.assertEqual(audit.classify(report).verdict, "error")

    def test_process_exits_during_map_read(self):
        def text(path):
            if path.endswith("_map"):
                raise FileNotFoundError("process exited during map inspection")
            return proc_text(path)
        with patch.object(ps, "start_time", return_value=123), patch.object(ps, "read_text", side_effect=text), \
                patch.object(ps, "namespace", return_value=snapshot().user_namespace), \
                patch.object(ps, "process_root", return_value=snapshot().root), patch.object(ps, "read_setgroups", return_value="deny"), \
                patch.object(ps.os, "stat", side_effect=FileNotFoundError):
            report = ph.diagnose_process("/data/file", PID)
        result = run_reports([report])
        self.assertTrue(result.entries[0].transient)
        self.assertEqual(result.entries[0].reason_code, "exited")
        self.assertEqual(result.code, 0)

    def test_exit_after_permission_analysis_is_transient(self):
        diagnosis = evaluate().diagnosis
        with patch.object(ph, "inspect_process", side_effect=[snapshot(), ps.ProcessInspectionError("gone", 2, kind="not_visible")]), \
                patch.object(ph, "diagnose", return_value=diagnosis):
            entry = audit.classify(ph.diagnose_process("/data/file", PID))
        self.assertTrue(entry.transient)
        self.assertIsNone(entry.report)

    def test_mid_read_permission_error(self):
        with patch.object(ps, "start_time", return_value=123), patch.object(ps, "read_text", side_effect=PermissionError("status hidden")):
            report = ph.diagnose_process("/data/file", PID)
        self.assertEqual(report.inspection_kind, "proc_permission")
        result = run_reports([report])
        self.assertEqual(result.code, 3)
        self.assertIn("status hidden", result.entries[0].reason)

    def test_malformed_status_is_error(self):
        with patch.object(ps, "start_time", return_value=123), patch.object(ps, "read_text", return_value="Uid: nonsense"):
            report = ph.diagnose_process("/data/file", PID)
        self.assertEqual(audit.classify(report).verdict, "error")

    def test_changed_start_time_discards_snapshot(self):
        with patch.object(ps, "start_time", side_effect=[123, 124]), patch.object(ps, "read_text", side_effect=proc_text), \
                patch.object(ps, "namespace", return_value=snapshot().user_namespace), \
                patch.object(ps, "process_root", return_value=snapshot().root), patch.object(ps, "read_setgroups", return_value="allow"):
            report = ph.diagnose_process("/data/file", PID)
        entry = audit.classify(report)
        self.assertTrue(entry.transient)
        self.assertIsNone(entry.report)

    def test_race_after_analysis_discards_old_metadata(self):
        entry = audit.classify(failed("identity_changed", process=snapshot()))
        self.assertIsNone(entry.report)
        self.assertIsNone(entry.name)

    def test_one_bad_process_does_not_abort(self):
        result = run_reports([failed("inspection_error"), with_pid(evaluate(permissions=4), 43)])
        self.assertEqual(len(result.entries), 2)
        self.assertEqual(result.summary.permitted, 1)
        self.assertEqual(result.summary.errors, 1)

    def test_unexpected_os_error_does_not_abort(self):
        with patch.object(ph, "inspect_audit_target"), patch.object(ph, "diagnose_process", side_effect=[OSError("io"), evaluate(permissions=4)]):
            result = audit.audit_processes("/data/file", pids=[1, 42])
        self.assertEqual([e.verdict for e in result.entries], ["error", "permitted"])

    def test_target_lost_during_audit(self):
        report = replace(evaluate(), code=ph.ExitCode.INPUT)
        result = run_reports([report])
        self.assertEqual(result.code, 2)
        self.assertIn("Target became unresolved", result.failure)

    def test_summary_counts_and_exit_policy(self):
        reports = [evaluate(permissions=4), evaluate(), mapped_evaluate(foreign(capability=2)),
                   failed("exited"), failed("inspection_error"), failed("not_visible", code=2)]
        result = run_reports([with_pid(r, index + 1) for index, r in enumerate(reports)])
        self.assertEqual(result.summary, audit.ProcessAuditSummary(6, 3, 1, 1, 1, 2, 1))
        self.assertEqual(result.code, 3)

    def test_denials_do_not_fail_audit(self):
        self.assertEqual(run_reports([evaluate()]).code, 0)


class SharedEngineTests(unittest.TestCase):
    def assert_verdict(self, report, verdict):
        result = run_reports([report])
        self.assertEqual(result.entries[0].verdict, verdict)
        self.assertIs(result.entries[0].report, report)
        return result

    def test_owner_access(self):
        self.assert_verdict(mapped_evaluate(owner=100000), "permitted")

    def test_group_access(self):
        self.assert_verdict(mapped_evaluate(group=100000, permissions=0o640), "permitted")

    def test_supplementary_group(self):
        result = self.assert_verdict(mapped_evaluate(group=100010, permissions=0o640), "permitted")
        self.assertIn("supplementary", audit.render_audit(result))

    def test_other_access(self):
        self.assert_verdict(evaluate(permissions=4), "permitted")

    def test_dac_denial(self):
        self.assert_verdict(evaluate(), "denied")

    def test_acl_named_user_permit(self):
        self.assert_verdict(evaluate(acl=make_acl(users=((9000, 4),), mask=4)), "permitted")

    def test_acl_mask_denial(self):
        result = self.assert_verdict(evaluate(mode="w", acl=make_acl(users=((9000, 6),), mask=4)), "denied")
        self.assertIn("mask removes WRITE", audit.render_audit(result))

    def test_capability_override(self):
        result = self.assert_verdict(evaluate(2), "permitted")
        self.assertIn("CAP_DAC_OVERRIDE", audit.render_audit(result))

    def test_read_search_override(self):
        result = self.assert_verdict(evaluate(4), "permitted")
        self.assertIn("CAP_DAC_READ_SEARCH", audit.render_audit(result))

    def test_traversal_capability_visible(self):
        result = self.assert_verdict(evaluate(2, parent_permissions=0, permissions=4), "permitted")
        self.assertIn("Search at '/data'", audit.render_audit(result))

    def test_readonly_wins_over_capability(self):
        result = self.assert_verdict(evaluate(2, mode="w", readonly=True), "denied")
        self.assertIn("READ-ONLY", audit.render_audit(result))

    def test_noexec_wins(self):
        self.assert_verdict(evaluate(2, mode="x", permissions=1, noexec=True), "denied")

    def test_foreign_capability_scope(self):
        result = self.assert_verdict(mapped_evaluate(foreign(capability=2)), "indeterminate")
        self.assertEqual(result.code, 3)
        self.assertIn("Capability scope", audit.render_audit(result))

    def test_foreign_read_search_scope(self):
        self.assert_verdict(mapped_evaluate(foreign(capability=4)), "indeterminate")

    def test_mapped_named_group_acl(self):
        result = self.assert_verdict(mapped_evaluate(acl=make_acl(groups=((100010, 4),), mask=4)), "permitted")
        self.assertIn("ACL", audit.render_audit(result))

    def test_foreign_ordinary_permit(self):
        self.assert_verdict(mapped_evaluate(foreign(capability=2), permissions=4), "permitted")

    def test_foreign_mount_safety(self):
        process = replace(foreign(), mount_namespace=ps.NamespaceObservation("mnt:[3]", "mnt:[1]", False))
        result = self.assert_verdict(mapped_evaluate(process), "indeterminate")
        self.assertIn("mount namespace", audit.render_audit(result))

    def test_unmapped_uid(self):
        self.assert_verdict(mapped_evaluate(foreign(uid=200000)), "indeterminate")

    def test_namespace_json_retained(self):
        result = self.assert_verdict(mapped_evaluate(owner=100000), "permitted")
        data = audit.audit_document(result, ph.__version__)["processes"][0]
        self.assertEqual(data["process"]["filesystem_identity"]["fsuid"]["local"], 0)
        self.assertEqual(data["process"]["filesystem_identity"]["fsuid"]["mapped"], 100000)


class PresentationTests(unittest.TestCase):
    def many(self, permissions=0):
        report = evaluate(permissions=permissions)
        return run_reports([with_pid(report, pid) for pid in range(100, 112)])

    def test_grouped_denial(self):
        text = audit.render_audit(self.many())
        self.assertIn("12 processes with the same result", text)
        self.assertIn("OTHER ---", text)
        self.assertIn("PIDs: 100 'worker'", text)
        self.assertIn("+7 more", text)

    def test_grouped_permit(self):
        self.assertIn("12 processes with the same result", audit.render_audit(self.many(4)))

    def test_verbose_expands_every_pid(self):
        text = audit.render_audit(self.many(), verbose=True)
        for pid in range(100, 112):
            self.assertIn(f"PID {pid} 'worker'", text)
        self.assertNotIn("processes with the same result", text)

    def test_distinct_identity_not_grouped(self):
        first = evaluate()
        second = evaluate(process=replace(process_with(), status=replace(process_with().status, uids=ps.CredentialIDs(1, 1, 1, 1))))
        self.assertNotIn("processes with the same result", audit.render_audit(run_reports([first, with_pid(second, 43)])))

    def test_capability_permits_individual(self):
        first = evaluate(2)
        text = audit.render_audit(run_reports([first, with_pid(first, 43)]))
        self.assertNotIn("processes with the same result", text)

    def test_error_entries_individual(self):
        text = audit.render_audit(run_reports([failed("inspection_error"), with_pid(failed("inspection_error"), 43)]))
        self.assertIn("PID 42", text)
        self.assertIn("PID 43", text)

    def test_visibility_failure_distinct_from_namespace_mismatch(self):
        process = replace(foreign(), mount_namespace=ps.NamespaceObservation(None, "mnt:[1]", None, "permission denied"))
        result = run_reports([mapped_evaluate(process)])
        self.assertEqual(result.entries[0].verdict, "error")
        self.assertIn("Proc context unavailable: mount namespace", audit.render_audit(result))

    def test_equivalent_visibility_errors_grouped_with_pids(self):
        process = replace(foreign(), mount_namespace=ps.NamespaceObservation(None, "mnt:[1]", None, "permission denied"))
        report = mapped_evaluate(process)
        result = run_reports([with_pid(report, 42), with_pid(report, 43)])
        text = audit.render_audit(result)
        self.assertIn("2 processes with the same result", text)
        self.assertIn("42 'worker', 43 'worker'", text)
        self.assertEqual(result.summary.errors, 2)

    def test_json_every_pid_and_counts(self):
        data = json.loads(jo.render_json(audit.audit_document(self.many(), ph.__version__)))
        self.assertEqual(data["schema_version"], "1")
        self.assertEqual(data["command"], "audit-processes")
        self.assertEqual(data["summary"]["denied"], 12)
        self.assertEqual([e["pid"] for e in data["processes"]], list(range(100, 112)))

    def test_json_capability_structure(self):
        data = audit.audit_document(run_reports([evaluate(2)]), ph.__version__)["processes"][0]
        self.assertIn("CAP_DAC_OVERRIDE", data["process"]["capabilities"]["effective"])
        self.assertTrue(data["target_inode"]["capability_override"]["applied"])

    def test_json_transient_has_no_stale_identity(self):
        data = audit.audit_document(run_reports([failed("exited", process=snapshot())]), ph.__version__)["processes"][0]
        self.assertEqual(data["verdict"], "unavailable")
        self.assertTrue(data["transient"])
        self.assertIsNone(data["process"])

    def test_cli_routing_repeatable_pid(self):
        with patch.object(audit, "audit_processes", return_value=self.many()) as runner, \
                patch.object(ph.sys, "platform", "linux"), contextlib.redirect_stdout(io.StringIO()) as output:
            code = ph.main(["audit-processes", "/data/file", "--pid", "42", "--pid", "43", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(runner.call_args.kwargs["pids"], [42, 43])
        self.assertEqual(json.loads(output.getvalue())["tool"]["version"], "1.4.0")

    def test_cli_rejects_bad_pid(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            ph.main(["audit-processes", "/data/file", "--pid", "0"])
        self.assertEqual(error.exception.code, 2)


class CommandLinePrivacyTests(unittest.TestCase):
    def test_no_cmdline_read_by_default(self):
        with patch.object(audit, "collect_cmdline") as collect:
            run_reports([evaluate(permissions=4)])
        collect.assert_not_called()

    def test_verbose_cmdline_is_guarded_and_escaped(self):
        with patch.object(audit, "start_time", return_value=123), patch.object(audit.Path, "read_bytes", return_value=b"worker\0secret\nvalue\0"):
            result = run_reports([evaluate(permissions=4)], include_cmdline=True)
        text = audit.render_audit(result, verbose=True)
        self.assertIn("secret\\nvalue", text)
        self.assertEqual(audit.audit_document(result, ph.__version__)["processes"][0]["cmdline"], ["worker", "secret\nvalue"])

    def test_cmdline_permission_failure_keeps_verdict(self):
        with patch.object(audit, "start_time", return_value=123), patch.object(audit.Path, "read_bytes", side_effect=PermissionError("private")):
            result = run_reports([evaluate(permissions=4)], include_cmdline=True)
        self.assertEqual(result.code, 0)
        self.assertEqual(result.entries[0].verdict, "permitted")
        self.assertIn("private", result.entries[0].cmdline_note)

    def test_cmdline_pid_reuse_discards_all_old_data(self):
        with patch.object(audit, "start_time", side_effect=[123, 124]), patch.object(audit.Path, "read_bytes", return_value=b"other\0"):
            result = run_reports([evaluate(permissions=4)], include_cmdline=True)
        self.assertEqual(result.entries[0].verdict, "unavailable")
        self.assertIsNone(result.entries[0].cmdline)
        self.assertIsNone(result.entries[0].report)

    def test_cmdline_stat_parser_error_not_called_exit(self):
        with patch.object(audit, "start_time", side_effect=ps.ProcessInspectionError("Malformed stat")):
            result = run_reports([evaluate(permissions=4)], include_cmdline=True)
        self.assertEqual(result.entries[0].verdict, "error")
        self.assertFalse(result.entries[0].transient)
        self.assertEqual(result.code, 3)


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux procfs integration")
class IntegrationTests(unittest.TestCase):
    def test_visible_process_set_temp_file(self):
        with tempfile.NamedTemporaryFile() as target:
            result = audit.audit_processes(target.name)
        self.assertIn(os.getpid(), [entry.pid for entry in result.entries])
        self.assertEqual(result.discovered, len(result.entries))
        summary = result.summary
        self.assertEqual(summary.discovered, summary.permitted + summary.denied + summary.indeterminate + summary.unavailable + summary.errors)

    def test_current_process_visible_in_inventory(self):
        self.assertIn(os.getpid(), audit.enumerate_pids())

    def test_current_process_temp_file_json(self):
        with tempfile.NamedTemporaryFile() as target:
            result = audit.audit_processes(target.name, pids=[os.getpid()])
        data = json.loads(jo.render_json(audit.audit_document(result, ph.__version__)))
        self.assertEqual(data["summary"]["discovered"], 1)
        self.assertEqual(data["processes"][0]["pid"], os.getpid())
        self.assertIsNotNone(data["processes"][0]["name"])
        self.assertNotEqual(data["processes"][0]["verdict"], "denied")

    def test_script_entrypoint_json(self):
        with tempfile.NamedTemporaryFile() as target:
            result = subprocess.run([sys.executable, str(Path(ph.__file__)), "audit-processes", target.name,
                                     "--pid", str(os.getpid()), "--json"], capture_output=True, text=True)
        data = json.loads(result.stdout)
        self.assertEqual(data["command"], "audit-processes")
        self.assertEqual(data["processes"][0]["pid"], os.getpid())
        self.assertEqual(result.returncode, data["exit_code"])
