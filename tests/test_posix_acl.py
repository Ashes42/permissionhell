"""ACL parsing, selection, pipeline, output, and real-Linux regressions."""

import contextlib
import copy
import errno
import io
import os
import stat
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

import permissionhell as ph
import posix_acl as pa
from test_permissionhell import metadata, SUBJECT, ROOT, MOUNTINFO


def encoded(entries):
    return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in entries)


def acl_data(owner=7, users=(), group=0, groups=(), mask=7, other=0):
    entries = [(pa.Tag.OWNER, owner, pa.UNDEFINED_ID)]
    entries += [(pa.Tag.USER, permissions, uid) for uid, permissions in users]
    entries += [(pa.Tag.GROUP_OBJ, group, pa.UNDEFINED_ID)]
    entries += [(pa.Tag.GROUP, permissions, gid) for gid, permissions in groups]
    if mask is not None:
        entries += [(pa.Tag.MASK, mask, pa.UNDEFINED_ID)]
    entries += [(pa.Tag.OTHER, other, pa.UNDEFINED_ID)]
    return encoded(entries)


def make_acl(**kwargs):
    return pa.parse_access_acl(acl_data(**kwargs))


def acl_metadata(acl, directory=False, uid=9000, gid=999):
    group = acl.entry(pa.Tag.MASK) or acl.entry(pa.Tag.GROUP_OBJ)
    mode = (acl.entry(pa.Tag.OWNER).permissions << 6) | (group.permissions << 3) | acl.entry(pa.Tag.OTHER).permissions
    return metadata(mode, uid, gid, stat.S_IFDIR if directory else stat.S_IFREG)


class ACLParsingTest(unittest.TestCase):
    def test_minimal_acl_is_not_extended(self):
        acl = make_acl(owner=6, group=4, mask=None, other=0)
        self.assertFalse(acl.extended)
        self.assertEqual(len(acl.entries), 3)

    def test_mask_only_acl_is_extended(self):
        self.assertTrue(make_acl(mask=4).extended)

    def test_numeric_qualifiers_and_permissions(self):
        acl = make_acl(users=((12345, 6),), groups=((54321, 5),))
        self.assertEqual(acl.entry(pa.Tag.USER), pa.ACLEntry(pa.Tag.USER, 6, 12345))
        self.assertEqual(acl.entry(pa.Tag.GROUP), pa.ACLEntry(pa.Tag.GROUP, 5, 54321))

    def test_bad_lengths_and_empty_access_acl(self):
        for data in (b"", b"\x02", struct.pack("<I", 2), acl_data()[:-1]):
            with self.subTest(data=data), self.assertRaises(pa.ACLInspectionError):
                pa.parse_access_acl(data)

    def test_unsupported_version(self):
        with self.assertRaisesRegex(pa.ACLInspectionError, "version"):
            pa.parse_access_acl(struct.pack("<I", 1) + acl_data()[4:])

    def test_unknown_tag_and_invalid_permission(self):
        for tag, permissions in ((3, 4), (pa.Tag.OWNER, 8)):
            with self.subTest(tag=tag), self.assertRaises(pa.ACLInspectionError):
                pa.parse_access_acl(encoded([(tag, permissions, pa.UNDEFINED_ID)]))

    def test_missing_required_entries(self):
        raw = list(struct.iter_unpack("<HHI", acl_data()[4:]))
        for tag in (pa.Tag.OWNER, pa.Tag.GROUP_OBJ, pa.Tag.OTHER):
            with self.subTest(tag=tag), self.assertRaises(pa.ACLInspectionError):
                pa.parse_access_acl(encoded([entry for entry in raw if entry[0] != tag]))

    def test_named_entries_require_mask(self):
        for kwargs in ({"users": ((1001, 4),)}, {"groups": ((200, 4),)}):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(pa.ACLInspectionError, "mask"):
                make_acl(mask=None, **kwargs)

    def test_duplicate_qualifiers_or_singleton_entries_rejected(self):
        for kwargs in ({"users": ((1001, 4), (1001, 2))}, {"groups": ((200, 4), (200, 2))}):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(pa.ACLInspectionError, "duplicate"):
                make_acl(**kwargs)
        raw = list(struct.iter_unpack("<HHI", acl_data()[4:]))
        with self.assertRaises(pa.ACLInspectionError):
            pa.parse_access_acl(encoded([raw[0], *raw]))

    def test_invalid_identifiers(self):
        raw = list(struct.iter_unpack("<HHI", acl_data(users=((1001, 4),))[4:]))
        for index, identifier in ((0, 1001), (1, pa.UNDEFINED_ID)):
            bad = raw.copy()
            tag, permissions, _ = bad[index]
            bad[index] = (tag, permissions, identifier)
            with self.subTest(index=index), self.assertRaisesRegex(pa.ACLInspectionError, "identifier"):
                pa.parse_access_acl(encoded(bad))

    def test_out_of_order_tags(self):
        raw = list(struct.iter_unpack("<HHI", acl_data()[4:]))
        with self.assertRaisesRegex(pa.ACLInspectionError, "out-of-order"):
            pa.parse_access_acl(encoded(list(reversed(raw))))

    def test_mode_group_bits_correspond_to_mask(self):
        acl = make_acl(owner=6, group=0, mask=4, other=1)
        pa.validate_acl_mode(acl, stat.S_IFREG | 0o641)
        with self.assertRaisesRegex(pa.ACLInspectionError, "disagree"):
            pa.validate_acl_mode(acl, stat.S_IFREG | 0o601)


class ACLReaderTest(unittest.TestCase):
    def test_read_access_xattr_without_following_final_symlink(self):
        with patch.object(pa.os, "getxattr", return_value=acl_data(), create=True) as read:
            self.assertTrue(pa.read_access_acl("/file").extended)
        read.assert_called_once_with("/file", "system.posix_acl_access", follow_symlinks=False)

    def test_enodata_means_absent(self):
        with patch.object(pa.os, "getxattr", side_effect=OSError(errno.ENODATA, "absent"), create=True):
            self.assertIsNone(pa.read_access_acl("/file"))

    def test_errors_never_mean_no_acl(self):
        for code in (errno.EACCES, errno.EPERM, errno.ENOENT, errno.EIO,
                     errno.ENOTSUP, errno.ENOSYS, errno.ERANGE):
            with self.subTest(code=code), \
                    patch.object(pa.os, "getxattr", side_effect=OSError(code, "unavailable"), create=True), \
                    self.assertRaises(pa.ACLInspectionError):
                pa.read_access_acl("/file")

    def test_missing_python_facility_is_error(self):
        with patch.object(pa.os, "getxattr", side_effect=NotImplementedError, create=True), \
                self.assertRaises(pa.ACLInspectionError):
            pa.read_access_acl("/file")

    def test_malformed_data_is_not_absence(self):
        with patch.object(pa.os, "getxattr", return_value=b"", create=True), \
                self.assertRaises(pa.ACLInspectionError):
            pa.read_access_acl("/file")


class ACLSelectionTest(unittest.TestCase):
    def check(self, acl, required=4, subject=SUBJECT, owner=9000, group=999):
        return pa.evaluate_acl(acl, subject.uid, subject.gids, owner, group, required)

    def test_named_user_grants_beyond_other(self):
        match = self.check(make_acl(users=((1001, 4),), other=0))
        self.assertTrue(match.allowed)
        self.assertEqual(match.selection, "NAMED USER")
        self.assertEqual(match.effective, 4)

    def test_named_user_denial_no_fallback_to_groups_or_other(self):
        match = self.check(make_acl(users=((1001, 0),), group=7, groups=((200, 7),), other=7), group=100)
        self.assertFalse(match.allowed)
        self.assertEqual(match.selection, "NAMED USER")

    def test_named_user_mask_removes_write(self):
        acl = make_acl(users=((1001, 6),), mask=4)
        self.assertTrue(self.check(acl, 4).allowed)
        match = self.check(acl, 2)
        self.assertFalse(match.allowed)
        self.assertEqual((match.specified, match.mask, match.effective), (6, 4, 4))

    def test_mask_is_a_ceiling_not_a_grant(self):
        self.assertFalse(self.check(make_acl(users=((1001, 2),), mask=7), 4).allowed)

    def test_named_primary_group_grant(self):
        match = self.check(make_acl(groups=((100, 4),)))
        self.assertTrue(match.allowed)
        self.assertEqual(match.entries[0].qualifier, 100)

    def test_supplementary_named_group_grant(self):
        self.assertTrue(self.check(make_acl(groups=((200, 4),))).allowed)

    def test_owning_group_and_named_groups_form_union_for_single_bits(self):
        acl = make_acl(group=4, groups=((100, 2), (200, 1)), mask=7)
        for required in (4, 2, 1):
            match = self.check(acl, required, group=100)
            self.assertTrue(match.allowed)
            self.assertEqual(match.specified, 7)
            self.assertEqual(len(match.entries), 3)

    def test_matching_groups_limited_by_mask(self):
        match = self.check(make_acl(group=4, groups=((200, 2),), mask=4), 2, group=100)
        self.assertEqual(match.specified, 6)
        self.assertEqual(match.effective, 4)
        self.assertFalse(match.allowed)

    def test_group_denial_never_falls_through_to_other(self):
        for kwargs, owning_gid in (({"groups": ((200, 0),)}, 999), ({"group": 0}, 100)):
            with self.subTest(kwargs=kwargs):
                match = self.check(make_acl(other=7, **kwargs), group=owning_gid)
                self.assertFalse(match.allowed)
                self.assertEqual(match.selection, "GROUP")

    def test_group_match_checks_more_than_first_entry(self):
        match = self.check(make_acl(group=0, groups=((100, 0), (200, 4))), group=100)
        self.assertTrue(match.allowed)

    def test_other_selected_only_without_any_user_or_group_match(self):
        match = self.check(make_acl(users=((555, 0),), groups=((888, 0),), mask=0, other=4))
        self.assertEqual(match.selection, "OTHER")
        self.assertTrue(match.allowed)
        self.assertIsNone(match.mask)

    def test_owner_ignores_mask_and_named_entry_for_same_uid(self):
        match = self.check(make_acl(owner=4, users=((1001, 0),), mask=0), owner=1001)
        self.assertEqual(match.selection, "OWNER")
        self.assertTrue(match.allowed)
        self.assertIsNone(match.mask)

    def test_owner_denial_no_fallback_to_named_entry(self):
        match = self.check(make_acl(owner=0, users=((1001, 7),), other=7), owner=1001)
        self.assertFalse(match.allowed)

    def test_minimal_acl_group_has_no_mask(self):
        match = self.check(make_acl(group=4, mask=None), group=100)
        self.assertTrue(match.allowed)
        self.assertIsNone(match.mask)

    def test_mask_only_acl_can_restrict_owning_group(self):
        match = self.check(make_acl(group=0, mask=7), group=100)
        self.assertFalse(match.allowed)

    def test_reject_combined_request_instead_of_incorrect_union_semantics(self):
        with self.assertRaises(ValueError):
            self.check(make_acl(groups=((100, 4), (200, 2))), required=6)


class ACLPipelineTest(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(ph, "owner_name", side_effect=str))
        self.stack.enter_context(patch.object(ph, "group_name", side_effect=str))

    def inspect(self, acl, mode="r", subject=SUBJECT, **metadata_kwargs):
        with patch.object(ph, "read_access_acl", return_value=acl):
            return ph.inspect_inode("/srv/file", acl_metadata(acl, **metadata_kwargs), subject, mode)

    def diagnosis(self, node, subject=SUBJECT, mode="r", mountinfo=MOUNTINFO):
        report = ph.Diagnosis(subject, node.path, mode,
            ph.PathTrace(target=node, resolved_path=node.path), mount=ph.parse_mountinfo(mountinfo)[0])
        ph.determine_verdict(report)
        return report

    def test_no_acl_preserves_dac_decision_and_quiet_output(self):
        with patch.object(ph, "read_access_acl", return_value=None):
            node = ph.inspect_inode("/srv/file", metadata(0o644, uid=9000, gid=999), SUBJECT, "r")
        self.assertEqual(node.decision, node.dac_decision)
        self.assertFalse(ph.acl_relevant(node))
        self.assertEqual(ph.render_acl(node), [])

    def test_minimal_acl_preserves_mode_bit_result(self):
        node = self.inspect(make_acl(group=4, mask=None), gid=100)
        self.assertEqual(node.decision, node.dac_decision)
        self.assertFalse(ph.acl_relevant(node))

    def test_acl_can_allow_when_mode_only_denies(self):
        node = self.inspect(make_acl(users=((1001, 4),), mask=4))
        self.assertFalse(node.dac_decision.allowed)
        self.assertTrue(node.decision.allowed)
        self.assertEqual(self.diagnosis(node).code, 0)

    def test_acl_can_deny_when_mode_only_allows(self):
        node = self.inspect(make_acl(users=((1001, 0),), mask=4, other=4))
        self.assertTrue(node.dac_decision.allowed)
        self.assertFalse(node.decision.allowed)
        self.assertEqual(self.diagnosis(node).code, 1)

    def test_owner_does_not_need_acl_inspection(self):
        with patch.object(ph, "read_access_acl", side_effect=pa.ACLInspectionError("unsupported")) as read:
            for mode, allowed in (("r", True), ("w", False)):
                node = ph.inspect_inode("/file", metadata(0o444), SUBJECT, mode)
                self.assertEqual(node.decision.allowed, allowed)
                self.assertIn("unmasked user::", node.acl_note)
            read.assert_not_called()

    def test_root_with_restrictive_acl_keeps_bypass_and_execute_rule(self):
        acl = make_acl(owner=0, users=((0, 0),), mask=0, other=0)
        for mode, allowed in (("r", True), ("w", True), ("x", False)):
            with self.subTest(mode=mode):
                node = self.inspect(acl, mode=mode, subject=ROOT)
                self.assertEqual(node.decision.allowed, allowed)
                self.assertIn("root bypasses ACL DAC", node.acl_note)
        self.assertTrue(self.inspect(acl, mode="x", subject=ROOT, directory=True).decision.allowed)

    def test_unknown_acl_stops_diagnosis_instead_of_dac_guess(self):
        for permissions in (0o000, 0o777):
            with self.subTest(permissions=permissions), \
                    patch.object(ph.os, "lstat", return_value=metadata(permissions, uid=9000, kind=stat.S_IFDIR)), \
                    patch.object(ph, "read_access_acl", side_effect=pa.ACLInspectionError("unsupported")):
                result = ph.diagnose("/srv/file", SUBJECT, "r")
            self.assertEqual(result.code, 3)
            self.assertIn("ACL inspection failed at '/'", result.reasons[0])
            self.assertNotIn("ACCESS PERMITTED", ph.render_report(result))
            self.assertIsNone(result.trace.target)

    def test_mode_acl_mismatch_is_diagnostic_error(self):
        with patch.object(ph, "read_access_acl", return_value=make_acl(mask=4)), \
                self.assertRaisesRegex(ph.DiagnosticError, "disagree"):
            ph.inspect_inode("/file", metadata(0o777, uid=9000), SUBJECT, "r")

    def test_target_acl_read_failure_preserves_trace_and_mount_report(self):
        nodes = {"/": metadata(0o755, uid=1001, kind=stat.S_IFDIR),
                 "/file": metadata(0o777, uid=9000)}
        with patch.object(ph.os, "lstat", side_effect=lambda path: nodes[path]), \
                patch.object(ph, "read_access_acl", side_effect=pa.ACLInspectionError("unreadable")), \
                patch.object(ph, "read_mounts", return_value=ph.parse_mountinfo(MOUNTINFO)):
            result = ph.diagnose("/file", SUBJECT, "r")
        self.assertEqual(result.code, 3)
        self.assertEqual(len(result.trace.events), 1)
        self.assertIn("ACL inspection failed at '/file'", result.reasons[0])
        self.assertIn("Target access not evaluated", ph.render_report(result))
        self.assertIsNotNone(result.mount)

    def test_malformed_xattr_reaches_diagnostic_error_without_false_verdict(self):
        with patch.object(ph.os, "lstat", return_value=metadata(0o777, uid=9000, kind=stat.S_IFDIR)), \
                patch.object(pa.os, "getxattr", return_value=b"invalid", create=True):
            result = ph.diagnose("/file", SUBJECT, "r")
        self.assertEqual(result.code, 3)
        self.assertIn("Malformed ACL", result.reasons[0])
        self.assertIn("DIAGNOSIS INCOMPLETE", ph.render_report(result))

    def test_acl_denied_directory_stops_before_target_lookup(self):
        acl = make_acl(users=((1001, 4),), mask=4, other=7)
        nodes = {"/": metadata(0o755, uid=1001, kind=stat.S_IFDIR),
                 "/srv": acl_metadata(acl, directory=True)}
        with patch.object(ph.os, "lstat", side_effect=lambda path: nodes[path]) as lookup, \
                patch.object(ph, "read_access_acl", return_value=acl):
            result = ph.diagnose("/srv/file", SUBJECT, "r")
        self.assertEqual(result.code, 1)
        self.assertIsNone(result.trace.target)
        self.assertNotIn("/srv/file", [call.args[0] for call in lookup.call_args_list])
        text = ph.render_report(result)
        self.assertIn("FAIL '/srv'  ACL NAMED USER r--  <-- BLOCKED HERE", text)
        self.assertIn("Selected ACL permissions lack EXECUTE/SEARCH", text)

    def test_acl_granted_directory_search_reaches_target(self):
        acl = make_acl(users=((1001, 1),), mask=1)
        nodes = {"/": metadata(0o755, uid=1001, kind=stat.S_IFDIR),
                 "/srv": acl_metadata(acl, directory=True), "/srv/file": metadata()}
        with patch.object(ph.os, "lstat", side_effect=lambda path: nodes[path]), \
                patch.object(ph, "read_access_acl", return_value=acl), \
                patch.object(ph, "read_mounts", return_value=ph.parse_mountinfo(MOUNTINFO)):
            result = ph.diagnose("/srv/file", SUBJECT, "r")
        self.assertEqual(result.code, 0)
        self.assertFalse(result.trace.events[-1].dac_decision.allowed)
        self.assertIn("ACL NAMED USER --x", ph.render_report(result))

    def test_mask_can_block_directory_search(self):
        node = self.inspect(make_acl(users=((1001, 5),), mask=4), mode="x", directory=True)
        self.assertFalse(node.decision.allowed)
        self.assertIn("mask removes EXECUTE/SEARCH", ph.acl_explanation(node))

    def test_readonly_and_noexec_still_override_acl_grants(self):
        for mode, mountinfo in (("w", MOUNTINFO.replace("rw", "ro")),
                                ("x", MOUNTINFO.replace("rw,relatime", "rw,noexec"))):
            node = self.inspect(make_acl(users=((1001, 7),)), mode=mode)
            self.assertTrue(node.decision.allowed)
            self.assertEqual(self.diagnosis(node, mode=mode, mountinfo=mountinfo).code, 1)

    def test_concise_named_user_mask_explanation(self):
        node = self.inspect(make_acl(users=((1001, 6),), mask=4), mode="w")
        result = self.diagnosis(node, mode="w")
        text = ph.render_report(result)
        self.assertIn("user:1001:rw-", text)
        self.assertIn("Mask: r--; effective: r--", text)
        self.assertIn("ACL mask removes WRITE", text)
        self.assertIn("BLOCKED HERE", text)
        self.assertNotIn("Scope:", text)

    def test_concise_group_union_and_mask(self):
        node = self.inspect(make_acl(group=4, groups=((200, 2),), mask=4), mode="w", gid=100)
        text = ph.render_report(self.diagnosis(node, mode="w"))
        self.assertIn("group::r--, group:200:-w-", text)
        self.assertIn("Group union: rw-", text)
        self.assertIn("effective: r--", text)

    def test_unrelated_extended_acl_does_not_clutter_other_result(self):
        node = self.inspect(make_acl(users=((555, 0),), other=4))
        self.assertEqual(node.acl_match.selection, "OTHER")
        self.assertEqual(ph.render_acl(node), [])
        self.assertIn("Access: OTHER r--", ph.render_report(self.diagnosis(node)))

    def test_verbose_shows_all_entries_including_unmatched(self):
        node = self.inspect(make_acl(users=((555, 0), (1001, 6)), group=4, mask=4), mode="w")
        text = ph.render_report(self.diagnosis(node, mode="w"), verbose=True)
        for line in ("user::rwx", "user:555:---", "user:1001:rw- [matched]", "group::r--", "mask::r--", "other::---"):
            self.assertIn(line, text)
        self.assertIn("Mode group bits represent mask::", text)
        self.assertIn("Mode-only comparison:", text)
        self.assertIn("ACL mask removes WRITE", text)
        self.assertNotIn("Not modeled: POSIX ACLs", text)

    def test_rendering_does_not_change_acl_result(self):
        node = self.inspect(make_acl(users=((1001, 6),), mask=4), mode="w")
        result = self.diagnosis(node, mode="w")
        before = copy.deepcopy(result)
        ph.render_report(result)
        ph.render_report(result, verbose=True)
        self.assertEqual(result, before)

    def test_cli_acl_result_exit_codes(self):
        for permissions, expected in ((4, 0), (0, 1)):
            node = self.inspect(make_acl(users=((1001, permissions),), mask=4))
            result = self.diagnosis(node)
            with patch.object(ph.sys, "platform", "linux"), \
                    patch.object(ph, "resolve_subject", return_value=SUBJECT), \
                    patch.object(ph, "diagnose", return_value=result), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(ph.main(["diagnose", "/srv/file", "--as", "alice"]), expected)


@unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "setxattr"), "Linux xattr integration")
class LinuxACLIntegrationTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="permissionhell-acl-")
        self.addCleanup(temporary.cleanup)
        self.directory = temporary.name
        self.uid = 60001 if os.getuid() != 60001 else 60002
        self.subject = ph.Subject("acl-test", self.uid, 60003, "test", (60004,), ("extra",))
        self.path = os.path.join(self.directory, "file")
        with open(self.path, "w") as output:
            output.write("temporary ACL test fixture\n")
        try:
            # Only test-owned temporary inodes are modified. No root or tools needed.
            os.setxattr(self.directory, pa.ACCESS_XATTR, acl_data(users=((self.uid, 1),), mask=1))
            pa.read_access_acl(self.directory)
        except OSError as exc:
            if exc.errno in (errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS, errno.EPERM, errno.EACCES):
                self.skipTest(f"Temporary filesystem cannot manipulate POSIX ACLs: {exc}")
            raise
        except pa.ACLInspectionError as exc:
            cause = exc.__cause__
            if isinstance(cause, OSError) and cause.errno in (
                    errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS, errno.EPERM, errno.EACCES):
                self.skipTest(f"Temporary filesystem cannot inspect POSIX ACLs: {exc}")
            raise  # Malformed data/parser failures must not be hidden by a skip.

    def set_file_acl(self, **kwargs):
        os.setxattr(self.path, pa.ACCESS_XATTR, acl_data(**kwargs))

    def test_real_named_user_grant_and_mask_denial(self):
        self.set_file_acl(users=((self.uid, 6),), mask=4)
        allowed = ph.diagnose(self.path, self.subject, "r")
        denied = ph.diagnose(self.path, self.subject, "w")
        self.assertEqual(allowed.code, 0, ph.render_report(allowed))
        self.assertEqual(denied.code, 1, ph.render_report(denied))
        self.assertEqual(denied.trace.target.acl_match.effective, 4)
        self.assertIn("mask removes WRITE", ph.render_report(denied))

    def test_real_directory_acl_blocks_before_file(self):
        os.setxattr(self.directory, pa.ACCESS_XATTR, acl_data(users=((self.uid, 0),), mask=1))
        result = ph.diagnose(self.path, self.subject, "r")
        self.assertEqual(result.code, 1, ph.render_report(result))
        self.assertIsNone(result.trace.target)
        self.assertEqual(result.trace.events[-1].path, self.directory)

    def test_real_named_groups_union_and_mask(self):
        self.set_file_acl(groups=((60003, 4), (60004, 2)), mask=6)
        for mode in ("r", "w"):
            result = ph.diagnose(self.path, self.subject, mode)
            self.assertEqual(result.code, 0, ph.render_report(result))
            self.assertEqual(result.trace.target.acl_match.specified, 6)
        self.set_file_acl(groups=((60003, 4), (60004, 2)), mask=4)
        self.assertEqual(ph.diagnose(self.path, self.subject, "w").code, 1)

    def test_real_symlink_uses_destination_acl(self):
        self.set_file_acl(users=((self.uid, 4),), mask=4)
        alias = os.path.join(self.directory, "alias")
        os.symlink("file", alias)
        result = ph.diagnose(alias, self.subject, "r")
        self.assertEqual(result.code, 0, ph.render_report(result))
        self.assertEqual(result.trace.resolved_path, self.path)
        self.assertIsNotNone(result.trace.target.acl_match)

    def test_real_owner_and_root_are_not_restricted_by_named_entries(self):
        self.set_file_acl(owner=4, users=((os.getuid(), 0),), mask=0)
        actual_owner = ph.Subject("owner", os.getuid(), os.getgid(), "group", (), ())
        self.assertTrue(ph.inspect_inode(self.path, os.lstat(self.path), actual_owner, "r").decision.allowed)
        for mode, allowed in (("r", True), ("w", True), ("x", False)):
            self.assertEqual(ph.inspect_inode(self.path, os.lstat(self.path), ROOT, mode).decision.allowed, allowed)

    def test_real_default_acl_does_not_control_existing_directory(self):
        # Default ACLs describe inheritance, not the directory's access rights.
        os.setxattr(self.directory, "system.posix_acl_default", acl_data(users=((self.uid, 0),), mask=0))
        result = ph.diagnose(self.directory, self.subject, "x")
        self.assertEqual(result.code, 0, ph.render_report(result))


if __name__ == "__main__":
    unittest.main()
