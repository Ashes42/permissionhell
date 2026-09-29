import contextlib
import errno
import io
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import permissionhell as ph


def metadata(mode=0o640, uid=1001, gid=100, kind=stat.S_IFREG):
    return os.stat_result((kind | mode, 0, 0, 1, uid, gid, 0, 0, 0, 0))


SUBJECT = ph.Subject("alice", 1001, 100, "staff", (200,), ("media",))
ROOT = ph.Subject("root", 0, 0, "root", (), ())
MOUNTINFO = "24 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n"


class PermissionsTest(unittest.TestCase):
    def check(self, inode, allowed, selected, mode="r", subject=SUBJECT):
        decision = ph.evaluate_permission(subject, inode, mode)
        self.assertEqual(decision.allowed, allowed)
        self.assertEqual(decision.permission_class, selected)
        return decision

    def test_owner_read_allowed(self):
        self.check(metadata(), True, "OWNER")

    def test_owner_denied_despite_group_and_other(self):
        self.check(metadata(0o044), False, "OWNER")

    def test_primary_group(self):
        self.check(metadata(uid=3000), True, "GROUP")

    def test_supplementary_group(self):
        self.check(metadata(uid=3000, gid=200), True, "GROUP")

    def test_other(self):
        self.check(metadata(0o004, uid=3000, gid=300), True, "OTHER")

    def test_group_does_not_fall_through_to_other(self):
        self.check(metadata(0o004, uid=3000), False, "GROUP")

    def test_write_and_execute(self):
        self.check(metadata(0o200), True, "OWNER", "w")
        self.check(metadata(0o200), False, "OWNER", "x")
        self.check(metadata(0o100), True, "OWNER", "x")

    def test_root_read_write_bypass(self):
        for mode in ("r", "w"):
            decision = self.check(metadata(0), True, "OTHER", mode, ROOT)
            self.assertTrue(decision.root_override)

    def test_root_execute_requires_some_execute_bit(self):
        self.check(metadata(0), False, "OTHER", "x", ROOT)
        self.check(metadata(0o100), True, "OTHER", "x", ROOT)
        self.check(metadata(0o010), True, "OTHER", "x", ROOT)
        self.check(metadata(0o001), True, "OTHER", "x", ROOT)

    def test_root_directory_search_bypass(self):
        self.check(metadata(0, kind=stat.S_IFDIR), True, "OTHER", "x", ROOT)


class IdentityTest(unittest.TestCase):
    def test_nonexistent_user(self):
        with patch.object(ph, "pwd", SimpleNamespace(getpwnam=lambda name: {}[name])):
            with self.assertRaises(ph.DiagnosticError) as error:
                ph.resolve_subject("missing")
        self.assertEqual(error.exception.code, ph.ExitCode.INPUT)

    def test_supplementary_groups_deduplicated(self):
        database = SimpleNamespace(getpwnam=lambda name: SimpleNamespace(pw_name=name, pw_uid=1001, pw_gid=100))
        with patch.object(ph, "pwd", database), patch.object(ph.os, "getgrouplist", return_value=[200, 100, 200], create=True), \
                patch.object(ph, "group_name", side_effect=str):
            subject = ph.resolve_subject("alice")
        self.assertEqual(subject.supplementary_gids, (200,))
        self.assertEqual(subject.gids, {100, 200})


class PathTest(unittest.TestCase):
    def setUp(self):
        self.nodes = {"/": metadata(0o755, kind=stat.S_IFDIR),
                      "/srv": metadata(0o710, kind=stat.S_IFDIR),
                      "/srv/music": metadata(0o750, kind=stat.S_IFDIR),
                      "/srv/music/song": metadata()}
        self.links = {}
        self.lookups = []
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(ph.os, "lstat", side_effect=self.lstat))
        self.stack.enter_context(patch.object(ph.os, "readlink", side_effect=lambda p: self.links[p]))
        self.stack.enter_context(patch.object(ph, "owner_name", side_effect=str))
        self.stack.enter_context(patch.object(ph, "group_name", side_effect=str))
        self.stack.enter_context(patch.object(ph, "read_mounts", return_value=ph.parse_mountinfo(MOUNTINFO)))

    def lstat(self, path):
        self.lookups.append(path)
        if path not in self.nodes:
            raise FileNotFoundError(errno.ENOENT, "No such file", path)
        value = self.nodes[path]
        if isinstance(value, Exception):
            raise value
        return value

    def link(self, path, destination):
        self.nodes[path] = metadata(0o777, kind=stat.S_IFLNK)
        self.links[path] = destination

    def test_nested_traversal_success(self):
        report = ph.diagnose("/srv/music/song", SUBJECT, "r")
        self.assertEqual(report.code, ph.ExitCode.ALLOWED)
        self.assertEqual([event.path for event in report.trace.events], ["/", "/srv", "/srv/music"])

    def test_parent_directory_denial_preserves_trace(self):
        self.nodes["/srv"] = metadata(0o600, kind=stat.S_IFDIR)
        report = ph.diagnose("/srv/music/song", SUBJECT, "r")
        self.assertEqual(report.code, ph.ExitCode.DENIED)
        self.assertIn("'/srv'", report.reasons[0])
        self.assertEqual(len(report.trace.events), 2)
        self.assertNotIn("/srv/music", self.lookups)
        self.assertIsNone(report.trace.target)

    def test_directory_search_does_not_require_read(self):
        self.nodes["/srv"] = metadata(0o100, kind=stat.S_IFDIR)
        self.assertEqual(ph.diagnose("/srv/music/song", SUBJECT, "r").code, ph.ExitCode.ALLOWED)

    def test_target_denial(self):
        self.nodes["/srv/music/song"] = metadata(0o044)
        report = ph.diagnose("/srv/music/song", SUBJECT, "r")
        self.assertEqual(report.code, ph.ExitCode.DENIED)
        self.assertIn("OWNER", ph.render_report(report))

    def test_missing_path(self):
        self.assertEqual(ph.diagnose("/missing", SUBJECT, "r").code, ph.ExitCode.INPUT)

    def test_metadata_denial_is_not_subject_denial(self):
        self.nodes["/srv"] = PermissionError(errno.EACCES, "Permission denied", "/srv")
        report = ph.diagnose("/srv/music/song", SUBJECT, "r")
        self.assertEqual(report.code, ph.ExitCode.ERROR)
        self.assertIn("inspection error", report.reasons[0])

    def test_absolute_symlink(self):
        self.link("/alias", "/srv/music")
        report = ph.diagnose("/alias/song", SUBJECT, "r")
        self.assertEqual(report.code, ph.ExitCode.ALLOWED)
        self.assertEqual(report.trace.resolved_path, "/srv/music/song")
        self.assertIsInstance(report.trace.events[1], ph.Symlink)
        self.assertEqual([e.path for e in report.trace.events if isinstance(e, ph.Inode)],
                         ["/", "/", "/srv", "/srv/music"])

    def test_relative_symlink(self):
        self.link("/srv/alias", "music/song")
        report = ph.diagnose("/srv/alias", SUBJECT, "r")
        self.assertEqual(report.trace.resolved_path, "/srv/music/song")
        self.assertEqual(report.code, ph.ExitCode.ALLOWED)

    def test_broken_symlink(self):
        self.link("/broken", "/missing")
        report = ph.diagnose("/broken", SUBJECT, "r")
        self.assertEqual(report.code, ph.ExitCode.INPUT)
        self.assertIn("broken symlink", report.reasons[0])

    def test_symlink_loop(self):
        self.link("/loop", "/loop")
        report = ph.diagnose("/loop", SUBJECT, "r")
        self.assertEqual(report.code, ph.ExitCode.INPUT)
        self.assertIn("40", report.reasons[0])

    def test_dotdot_must_not_erase_search_denial(self):
        self.nodes["/srv"] = metadata(0o600, kind=stat.S_IFDIR)
        report = ph.diagnose("/srv/../srv/music/song", SUBJECT, "r")
        self.assertEqual(report.code, ph.ExitCode.DENIED)
        self.assertIn("'/srv'", report.reasons[0])

    def test_dotdot_after_symlink_uses_resolved_directory(self):
        self.link("/alias", "/srv/music")
        self.nodes["/srv/music/.."] = self.nodes["/srv"]
        self.nodes["/srv/song"] = metadata()
        report = ph.diagnose("/alias/../song", SUBJECT, "r")
        self.assertEqual(report.code, ph.ExitCode.ALLOWED)
        self.assertEqual(report.trace.resolved_path, "/srv/song")
        self.assertIn("/srv/music/..", self.lookups)

    def test_relative_path_starts_at_debugger_cwd(self):
        with patch.object(ph.os, "getcwd", return_value="/srv/music"):
            report = ph.diagnose("song", SUBJECT, "r")
        self.assertEqual(report.code, ph.ExitCode.ALLOWED)
        self.assertEqual(report.trace.resolved_path, "/srv/music/song")

    def test_original_symlink_parent_must_be_searchable(self):
        self.nodes["/srv"] = metadata(0o600, kind=stat.S_IFDIR)
        self.link("/srv/alias", "/")
        report = ph.diagnose("/srv/alias", SUBJECT, "r")
        self.assertEqual(report.code, ph.ExitCode.DENIED)
        self.assertNotIn("/srv/alias", self.lookups)

    def test_empty_and_nul_paths(self):
        for path in ("", "/srv/\x00"):
            self.assertEqual(ph.diagnose(path, SUBJECT, "r").code, ph.ExitCode.INPUT)

    def test_trailing_slash_requires_directory(self):
        report = ph.diagnose("/srv/music/song/", SUBJECT, "r")
        self.assertEqual(report.code, ph.ExitCode.INPUT)

    def test_file_used_as_directory(self):
        report = ph.diagnose("/srv/music/song/child", SUBJECT, "r")
        self.assertEqual(report.code, ph.ExitCode.INPUT)
        self.assertIn("Not a directory", report.reasons[0])

    def test_root_path_is_target(self):
        report = ph.diagnose("/", SUBJECT, "r")
        self.assertEqual(report.code, ph.ExitCode.ALLOWED)
        self.assertEqual(report.trace.events, [])

    def test_readonly_mount_blocks_write_even_root(self):
        with patch.object(ph, "read_mounts", return_value=ph.parse_mountinfo(MOUNTINFO.replace("rw", "ro"))):
            for subject in (SUBJECT, ROOT):
                report = ph.diagnose("/srv/music/song", subject, "w")
                self.assertTrue(report.trace.target.decision.allowed)
                self.assertEqual(report.code, ph.ExitCode.DENIED)
                self.assertIn("READ-ONLY", report.reasons[0])

    def test_mount_failure_cannot_claim_allowed(self):
        with patch.object(ph, "read_mounts", side_effect=ph.DiagnosticError("unavailable")):
            report = ph.diagnose("/srv/music/song", SUBJECT, "r")
        self.assertEqual(report.code, ph.ExitCode.ERROR)
        self.assertEqual(report.mount_error, "unavailable")

    def test_mount_failure_preserves_known_dac_denial(self):
        self.nodes["/srv/music/song"] = metadata(0)
        with patch.object(ph, "read_mounts", side_effect=ph.DiagnosticError("unavailable")):
            report = ph.diagnose("/srv/music/song", SUBJECT, "r")
        self.assertEqual(report.code, ph.ExitCode.DENIED)
        self.assertIn("unavailable", ph.render_report(report))

    def test_noexec_blocks_file_but_not_directory_search(self):
        self.nodes["/srv/music/song"] = metadata(0o700)
        with patch.object(ph, "read_mounts", return_value=ph.parse_mountinfo(MOUNTINFO.replace("rw,relatime", "rw,noexec"))):
            self.assertEqual(ph.diagnose("/srv/music/song", SUBJECT, "x").code, ph.ExitCode.DENIED)
            self.assertEqual(ph.diagnose("/srv/music", SUBJECT, "x").code, ph.ExitCode.ALLOWED)


class MountTest(unittest.TestCase):
    def test_longest_mount_with_component_boundary_and_escapes(self):
        mounts = ph.parse_mountinfo(MOUNTINFO +
            "25 24 8:2 / /srv ro - ext4 /dev/sda2 rw\n"
            "26 24 8:3 / /space\\040dir rw shared:3 - ext4 /dev/sda3 rw\n")
        self.assertEqual(ph.find_mount("/srv/song", mounts).point, "/srv")
        self.assertTrue(ph.find_mount("/srv/song", mounts).readonly)
        self.assertEqual(ph.find_mount("/srv-other/song", mounts).point, "/")
        self.assertEqual(ph.find_mount("/space dir/song", mounts).point, "/space dir")

    def test_readonly_superblock(self):
        self.assertTrue(ph.parse_mountinfo(MOUNTINFO.rstrip().removesuffix("rw") + "ro")[0].readonly)

    def test_malformed_mountinfo(self):
        for content in ("", "garbage", "24 1 - ext4"):
            with self.assertRaises(ph.DiagnosticError):
                ph.parse_mountinfo(content)

    def test_ambiguous_stacked_mounts(self):
        with self.assertRaises(ph.DiagnosticError):
            ph.find_mount("/file", ph.parse_mountinfo(MOUNTINFO + MOUNTINFO))

    def test_mount_read_error(self):
        with patch("builtins.open", side_effect=PermissionError("denied")):
            with self.assertRaises(ph.DiagnosticError):
                ph.read_mounts()


class CliTest(unittest.TestCase):
    def test_unsupported_platform(self):
        with patch.object(ph.sys, "platform", "win32"), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ph.main(["diagnose", "/file", "--as", "alice"]), ph.ExitCode.ERROR)

    def test_malformed_arguments(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            ph.main(["diagnose", "/file", "--as", "alice", "--mode", "z"])
        self.assertEqual(error.exception.code, ph.ExitCode.INPUT)

    def test_default_read(self):
        with patch.object(ph.sys, "platform", "linux"), patch.object(ph, "resolve_subject", return_value=SUBJECT), \
                patch.object(ph, "diagnose") as diagnose, patch.object(ph, "render_report", return_value="report"), \
                contextlib.redirect_stdout(io.StringIO()):
            diagnose.return_value.code = ph.ExitCode.ALLOWED
            self.assertEqual(ph.main(["diagnose", "/file", "--as", "alice"]), ph.ExitCode.ALLOWED)
            diagnose.assert_called_once_with("/file", SUBJECT, "r")


@unittest.skipUnless(sys.platform.startswith("linux"), "real Linux integration")
class LinuxIntegrationTest(unittest.TestCase):
    def test_real_metadata_mounts_and_symlink(self):
        subject = ph.resolve_subject(ph.pwd.getpwuid(os.getuid()).pw_name)
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "file")
            with open(target, "w") as output:
                output.write("fixture")
            os.symlink("file", os.path.join(directory, "alias"))
            report = ph.diagnose(os.path.join(directory, "alias"), subject, "r")
            self.assertEqual(report.code, ph.ExitCode.ALLOWED, ph.render_report(report))
            self.assertEqual(report.trace.resolved_path, target)
            self.assertIsNotNone(report.mount)
            executable = os.path.abspath(ph.__file__)
            result = subprocess.run([sys.executable, executable, "diagnose", target, "--as", subject.username],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertIn("ACCESS PERMITTED", result.stdout)


if __name__ == "__main__":
    unittest.main()
