"""Presentation regressions; the original semantic tests remain unchanged."""

import contextlib
import copy
import io
import stat
import unittest
from unittest.mock import patch

import permissionhell as ph
from test_permissionhell import metadata, SUBJECT, ROOT, MOUNTINFO


def inode(path, mode=0o640, subject=SUBJECT, operation="r", directory=False, uid=1001, gid=100):
    meta = metadata(mode, uid=uid, gid=gid, kind=stat.S_IFDIR if directory else stat.S_IFREG)
    return ph.Inode(path, uid, gid, "owner", "staff", meta.st_mode,
                    ph.evaluate_permission(subject, meta, operation))


def report(subject=SUBJECT, mode="r", target_mode=0o640, mountinfo=MOUNTINFO):
    parents = [inode(path, 0o755, subject, "x", directory=True) for path in ("/", "/srv")]
    target = inode("/srv/song", target_mode, subject, mode)
    result = ph.Diagnosis(subject, "/srv/song", mode,
                          ph.PathTrace(events=parents, target=target, resolved_path=target.path),
                          mount=ph.parse_mountinfo(mountinfo)[0])
    ph.determine_verdict(result)
    return result


class RenderingTest(unittest.TestCase):
    def test_default_success_is_compact_and_diagnostic_first(self):
        result = report()
        text = ph.render_report(result)
        self.assertIn("PERMISSION HELL", text)
        self.assertIn("READ as alice (UID 1001)", text)
        self.assertLess(text.index("ACCESS PERMITTED"), text.index("PATH (search x)"))
        self.assertIn("Directory search and target access pass", text)
        self.assertIn("PASS '/'  OWNER rwx", text)
        self.assertIn("Owner: owner (1001) | Group: staff (100) | Mode: 0640 (-rw-r-----)", text)
        self.assertIn("Access: OWNER rw- | Required: READ (r)", text)
        self.assertIn("Mount: '/' | ext4 | READ-WRITE", text)
        self.assertNotIn("Scope:", text)
        self.assertNotIn("Not modeled:", text)
        self.assertNotIn("relatime", text)
        for event in result.trace.events:
            self.assertNotIn(event.decision.reason, text)
        self.assertLessEqual(len(text.splitlines()), 16)

    def test_target_denial_explains_exclusive_class(self):
        text = ph.render_report(report(target_mode=0o044))
        self.assertIn("ACCESS DENIED", text)
        self.assertIn("alice lacks READ permission on '/srv/song'", text)
        self.assertIn("OWNER selected: UID 1001 owns this inode", text)
        self.assertIn("bits lack r; no fallback", text)
        self.assertIn("TARGET FAIL '/srv/song'  <-- BLOCKED HERE", text)

    def test_group_and_other_denials_explain_class_selection(self):
        for gid, selected, reason in ((100, "GROUP", "belongs to owning GID 100"),
                                      (999, "OTHER", "neither owner nor in the owning group")):
            with self.subTest(selected=selected):
                result = report()
                result.trace.target = inode("/srv/song", 0, uid=999, gid=gid)
                result.reasons.clear()
                ph.determine_verdict(result)
                text = ph.render_report(result)
                self.assertIn(selected + " selected:", text)
                self.assertIn(reason, text)

    def test_parent_denial_highlights_first_blocker(self):
        result = report()
        result.trace = ph.PathTrace(
            events=[result.trace.events[0], inode("/srv", 0o600, operation="x", directory=True)],
            failure="Traversal blocked at '/srv': subject lacks execute/search permission.",
            code=ph.ExitCode.DENIED)
        result.mount = None
        result.reasons.clear()
        ph.determine_verdict(result)
        text = ph.render_report(result)
        self.assertIn("FAIL '/srv'  OWNER rw-  <-- BLOCKED HERE", text)
        self.assertIn("bits lack x", text)
        self.assertIn("Target and mount not evaluated", text)
        self.assertNotIn("TARGET PASS", text)

    def test_mount_restrictions_remain_prominent(self):
        for mode, mountinfo, expected in (
                ("w", MOUNTINFO.replace("rw", "ro"), "READ-ONLY and blocks writing"),
                ("x", MOUNTINFO.replace("rw,relatime", "rw,noexec"), "noexec and blocks direct execution")):
            with self.subTest(mode=mode):
                text = ph.render_report(report(mode=mode, target_mode=0o700, mountinfo=mountinfo))
                self.assertIn("ACCESS DENIED", text)
                self.assertLess(text.index(expected), text.index("PATH (search x)"))
                self.assertIn("TARGET PASS", text)

    def test_root_override_is_primary_explanation(self):
        text = ph.render_report(report(subject=ROOT, target_mode=0))
        self.assertIn("ACCESS PERMITTED", text)
        self.assertIn("Access: ROOT OVERRIDE [ordinary OTHER ---]", text)
        self.assertIn("assumes privileged UID 0", text)
        self.assertNotIn("Matched class: OTHER", text)

    def test_root_without_bypass_is_not_marked_override_on_target(self):
        text = ph.render_report(report(subject=ROOT, target_mode=0o644))
        self.assertIn("Access: ROOT [ordinary OTHER r--]", text)

    def test_root_execution_denial_explains_execute_requirement(self):
        text = ph.render_report(report(subject=ROOT, mode="x", target_mode=0))
        self.assertIn("ACCESS DENIED", text)
        self.assertIn("Root still needs at least one execute bit", text)
        self.assertIn("none is set", text)
        self.assertNotIn("Access: ROOT OVERRIDE", text)

    def test_symlink_trace_collapses_only_identical_successes(self):
        result = report()
        root, parent = result.trace.events
        result.requested_path = "/alias"
        result.trace.events = [root, ph.Symlink("/alias", "/srv/song"), root, parent]
        text = ph.render_report(result)
        self.assertIn("Target: '/alias' -> '/srv/song'", text)
        self.assertIn("LINK '/alias' -> '/srv/song'", text)
        self.assertEqual(text.count("PASS '/'"), 1)
        self.assertIn("1 repeated successful search checks omitted", text)
        self.assertEqual(ph.render_report(result, verbose=True).count("PASS '/'"), 2)

    def test_changed_and_failed_repeated_observations_are_not_hidden(self):
        result = report()
        result.trace.events += [inode("/srv", 0o711, operation="x", directory=True),
                                inode("/srv", 0o600, operation="x", directory=True)]
        text = ph.render_report(result)
        self.assertEqual(text.count("PASS '/srv'"), 2)
        self.assertIn("FAIL '/srv'", text)

    def test_unresolved_symlink_label_keeps_exit_code(self):
        result = report()
        result.trace = ph.PathTrace(events=[ph.Symlink("/broken", "/missing")],
                                   failure="Path component does not exist (possibly a broken symlink): '/missing'",
                                   code=ph.ExitCode.INPUT)
        result.mount = None
        result.reasons.clear()
        ph.determine_verdict(result)
        for verbose in (False, True):
            text = ph.render_report(result, verbose=verbose)
            self.assertIn("UNRESOLVED PATH", text)
            self.assertIn("possibly a broken symlink", text)
            self.assertNotIn("INVALID INPUT", text)
        self.assertEqual(result.code, 2)

    def test_empty_input_still_has_invalid_input_label(self):
        result = report()
        result.requested_path = ""
        result.code = ph.ExitCode.INPUT
        self.assertEqual(ph.verdict_label(result), "INVALID INPUT")

    def test_mount_inspection_error_is_never_hidden(self):
        result = report()
        result.mount = None
        result.mount_error = "Cannot inspect mountinfo: permission denied"
        result.reasons.clear()
        ph.determine_verdict(result)
        text = ph.render_report(result)
        self.assertIn("DIAGNOSIS INCOMPLETE", text)
        self.assertIn(result.mount_error, text)

    def test_verbose_retains_reasons_groups_mount_details_and_scope(self):
        result = report()
        text = ph.render_report(result, verbose=True)
        self.assertIn(result.trace.events[0].decision.reason, text)
        self.assertIn("Supplementary groups: media (200)", text)
        self.assertIn("Mount options: relatime,rw", text)
        self.assertIn("Scope:", text)
        self.assertIn("POSIX ACLs", text)

    def test_renderers_do_not_mutate_analysis(self):
        result = report()
        before = copy.deepcopy(result)
        ph.render_report(result)
        ph.render_report(result, verbose=True)
        self.assertEqual(result, before)


class RenderingCliTest(unittest.TestCase):
    def test_verbose_flag_reaches_renderer_and_preserves_all_exit_codes(self):
        for verbose in (False, True):
            for code in ph.ExitCode:
                with self.subTest(verbose=verbose, code=code):
                    result = report()
                    result.code = code
                    with patch.object(ph.sys, "platform", "linux"), \
                            patch.object(ph, "resolve_subject", return_value=SUBJECT), \
                            patch.object(ph, "diagnose", return_value=result), \
                            patch.object(ph, "render_report", return_value="report") as render, \
                            contextlib.redirect_stdout(io.StringIO()):
                        args = ["diagnose", "/srv/song", "--as", "alice"]
                        if verbose:
                            args.append("--verbose")
                        self.assertEqual(ph.main(args), code)
                        render.assert_called_once_with(result, verbose=verbose)

    def test_help_exposes_scope_and_verbose(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as error:
            ph.main(["diagnose", "--help"])
        self.assertEqual(error.exception.code, 0)
        self.assertIn("--verbose", output.getvalue())
        self.assertIn("POSIX ACLs", output.getvalue())


if __name__ == "__main__":
    unittest.main()
