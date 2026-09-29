"""Capability parsing and live-process DAC/ACL overrides, without privilege mutation."""

from dataclasses import replace
import json
import os
import stat
import sys
import unittest
from unittest.mock import patch

import capabilities as caps
import json_output as jo
import permissionhell as ph
import process_subject as ps
from test_permissionhell import metadata, MOUNTINFO, ROOT
from test_posix_acl import make_acl, acl_metadata
from test_process_subject import snapshot, STATUS, PID


def process_with(mask=0, *, root=False, extra=""):
    text = STATUS.replace("0000000000000000", format(mask, "x")) if mask is not None else STATUS.replace("CapEff:\t0000000000000000\n", "")
    if root:
        text = text.replace("1000 1001 1002 9000", "0 0 0 0")
    return snapshot(text + extra)


def evaluate(mask=0, *, process=None, mode="r", permissions=0, parent_permissions=0o755,
             acl=None, readonly=False, noexec=False, root=False):
    observed = process or process_with(mask, root=root)
    def st(path):
        if path in ("/", "/data"):
            return metadata(parent_permissions if path == "/data" else 0o755, uid=555, gid=666, kind=stat.S_IFDIR)
        if path == "/data/file":
            return acl_metadata(acl, uid=555, gid=666) if acl else metadata(permissions, uid=555, gid=666)
        raise AssertionError(path)
    mount = ph.parse_mountinfo(MOUNTINFO)[0]
    mount = replace(mount, options=frozenset({"ro" if readonly else "rw"} | ({"noexec"} if noexec else set())))
    with patch.object(ph, "inspect_process", return_value=observed), \
            patch.object(ph.os, "stat", side_effect=st), patch.object(ph.os, "lstat", side_effect=st), \
            patch.object(ph, "read_mounts", return_value=[mount]), \
            patch.object(ph, "read_access_acl", side_effect=lambda p: acl if p == "/data/file" else None), \
            patch.object(ph, "owner_name", side_effect=str), patch.object(ph, "group_name", side_effect=str):
        return ph.diagnose_process("/data/file", PID, mode)


class CapabilityParsingTests(unittest.TestCase):
    def test_canonical_bit_positions(self):
        self.assertEqual(caps.CAPABILITY_NAMES[1], "CAP_DAC_OVERRIDE")
        self.assertEqual(caps.CAPABILITY_NAMES[2], "CAP_DAC_READ_SEARCH")
        self.assertEqual(caps.CAPABILITY_NAMES[3], "CAP_FOWNER")
        self.assertEqual(caps.CAPABILITY_NAMES[10], "CAP_NET_BIND_SERVICE")
        self.assertEqual(caps.CAPABILITY_NAMES[40], "CAP_CHECKPOINT_RESTORE")

    def test_all_status_sets(self):
        status = ps.parse_status(STATUS.replace("0000000000000000", "402") +
                                 "CapInh: 4\nCapPrm: 6\nCapBnd: 1fffffffff\nCapAmb: 0\n")
        self.assertEqual(status.capabilities.effective.names, ("CAP_DAC_OVERRIDE", "CAP_NET_BIND_SERVICE"))
        self.assertEqual(status.capabilities.inheritable.names, ("CAP_DAC_READ_SEARCH",))
        self.assertEqual(status.capabilities.permitted.mask, 6)
        self.assertEqual(status.capabilities.bounding.mask, 0x1fffffffff)
        self.assertEqual(status.capabilities.ambient.names, ())

    def test_zero_and_unavailable_are_distinct(self):
        self.assertEqual(ps.parse_status(STATUS).capabilities.effective.names, ())
        self.assertIsNone(ps.parse_status(STATUS).capabilities.ambient)

    def test_unknown_bits_preserved(self):
        parsed = caps.parse_capability_fields({"CapEff": format((1 << 63) | (1 << 80) | 2, "x")})
        self.assertEqual(parsed.effective.names, ("CAP_DAC_OVERRIDE",))
        self.assertEqual(parsed.effective.unknown_bits, (63, 80))

    def test_malformed_fields_and_duplicates(self):
        for field in caps.STATUS_FIELDS:
            for bad in ("xyz", "-1", "0x2", "", "1" * 257):
                with self.subTest(field=field, bad=bad), self.assertRaises(ps.ProcessInspectionError):
                    ps.parse_status(STATUS.replace("CapEff:\t0000000000000000\n", "") + f"{field}: {bad}\n")
            with self.subTest(field=field), self.assertRaises(ps.ProcessInspectionError):
                ps.parse_status(STATUS + f"{field}: 0\n{field}: 0\n")

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux proc capability integration")
    def test_real_current_process_fields_read_only(self):
        try:
            text = ps.read_text(f"/proc/{os.getpid()}/status")
        except OSError as exc:
            self.skipTest(str(exc))
        parsed = ps.parse_status(text)
        if parsed.capabilities.effective is None:
            self.skipTest("CapEff unavailable")
        raw = dict(line.split(":", 1) for line in text.splitlines() if ":" in line)
        for field, name in caps.STATUS_FIELDS.items():
            if field in raw:
                self.assertEqual(getattr(parsed.capabilities, name).mask, int(raw[field].strip(), 16))


class CapabilityEvaluationTests(unittest.TestCase):
    def test_dac_override_read_and_write(self):
        for mode in ("r", "w"):
            with self.subTest(mode=mode):
                report = evaluate(2, mode=mode)
                inode = report.diagnosis.trace.target
                self.assertEqual(report.code, 0)
                self.assertFalse(inode.base_decision.allowed)
                self.assertTrue(inode.decision.allowed)
                self.assertEqual(inode.capability_decision.capability, "CAP_DAC_OVERRIDE")

    def test_directory_search_override(self):
        report = evaluate(2, parent_permissions=0)
        self.assertEqual(report.code, 0)
        parent = report.diagnosis.trace.events[-1]
        self.assertEqual(parent.path, "/data")
        self.assertFalse(parent.base_decision.allowed)
        self.assertTrue(parent.capability_decision.applied)

    def test_acl_mask_override_preserves_base(self):
        report = evaluate(2, mode="w", acl=make_acl(users=((9000, 6),), mask=4))
        inode = report.diagnosis.trace.target
        self.assertEqual(report.code, 0)
        self.assertFalse(inode.base_decision.allowed)
        self.assertFalse(inode.acl_match.allowed)
        self.assertEqual(inode.acl_match.specified, 6)
        self.assertEqual(inode.acl_match.effective, 4)
        self.assertTrue(inode.decision.allowed)

    def test_execute_requires_any_execute_bit(self):
        self.assertEqual(evaluate(2, mode="x", permissions=0o644).code, 1)
        self.assertEqual(evaluate(2, mode="x", permissions=0o100).code, 0)

    def test_readonly_mount_wins_after_capability(self):
        report = evaluate(2, mode="w", readonly=True)
        self.assertEqual(report.code, 1)
        self.assertTrue(report.diagnosis.trace.target.capability_decision.applied)
        data = jo.process_document(report, ph.__version__)
        self.assertEqual(data["first_blocker"]["stage"], "mount")
        self.assertEqual(data["target_inode"]["result"], "permitted")
        self.assertEqual(data["mount"]["result"], "denied")

    def test_noexec_mount_wins(self):
        report = evaluate(2, mode="x", permissions=0o100, noexec=True)
        self.assertEqual(report.code, 1)
        self.assertTrue(report.diagnosis.trace.target.capability_decision.applied)
        self.assertIn("noexec", report.diagnosis.reasons[0])

    def test_read_search_read_and_traversal(self):
        report = evaluate(4, parent_permissions=0)
        self.assertEqual(report.code, 0)
        self.assertEqual(report.diagnosis.trace.events[-1].capability_decision.capability, "CAP_DAC_READ_SEARCH")
        self.assertEqual(report.diagnosis.trace.target.capability_decision.capability, "CAP_DAC_READ_SEARCH")

    def test_read_search_directory_read(self):
        decision = caps.evaluate_capabilities(False, stat.S_IFDIR, 4, caps.CapabilitySet(4))
        self.assertTrue(decision.allowed)

    def test_read_search_no_write_or_file_execute(self):
        self.assertEqual(evaluate(4, mode="w").code, 1)
        self.assertEqual(evaluate(4, mode="x", permissions=0o100).code, 1)

    def test_read_search_acl_read(self):
        report = evaluate(4, acl=make_acl(users=((9000, 6),), mask=2))
        self.assertEqual(report.code, 0)
        self.assertFalse(report.diagnosis.trace.target.acl_match.allowed)
        self.assertEqual(report.diagnosis.trace.target.capability_decision.capability, "CAP_DAC_READ_SEARCH")

    def test_read_search_does_not_erase_mount_restriction(self):
        report = evaluate(4, mode="w", permissions=0o222, parent_permissions=0, readonly=True)
        self.assertEqual(report.code, 1)
        self.assertTrue(report.diagnosis.trace.events[-1].capability_decision.applied)
        self.assertIn("READ-ONLY", report.diagnosis.reasons[0])

    def test_root_requires_effective_capability_for_bypass(self):
        self.assertEqual(evaluate(0, root=True).code, 1)
        report = evaluate(2, root=True)
        self.assertEqual(report.code, 0)
        self.assertFalse(report.diagnosis.trace.target.decision.root_override)
        self.assertTrue(report.diagnosis.trace.target.capability_decision.applied)

    def test_root_can_still_pass_ordinary_bits_without_capabilities(self):
        report = evaluate(0, root=True, permissions=0o444)
        self.assertEqual(report.code, 0)
        self.assertFalse(report.diagnosis.trace.target.capability_decision.applied)

    def test_root_uses_named_acl_when_not_owner(self):
        report = evaluate(0, root=True, acl=make_acl(users=((0, 0),), mask=7, other=7))
        self.assertEqual(report.code, 1)
        self.assertEqual(report.diagnosis.trace.target.acl_match.selection, "NAMED USER")

    def test_account_root_unchanged(self):
        decision = ph.evaluate_permission(ROOT, metadata(0, uid=9999), "w")
        self.assertTrue(decision.allowed)
        self.assertTrue(decision.root_override)

    def test_non_effective_sets_cannot_grant(self):
        process = process_with(0, extra="CapPrm: 6\nCapInh: 6\nCapBnd: 6\nCapAmb: 6\n")
        self.assertEqual(evaluate(process=process).code, 1)

    def test_fowner_chown_fsetid_do_not_grant_rw_access(self):
        for mask in (1 << 3, 1 << 0, 1 << 4):
            with self.subTest(mask=mask):
                self.assertEqual(evaluate(mask).code, 1)
                self.assertEqual(evaluate(mask, mode="w").code, 1)

    def test_foreign_user_namespace_not_evaluated(self):
        process = replace(process_with(2), user_namespace=ps.NamespaceObservation("user:[9]", "user:[2]", False))
        with patch.object(ph, "inspect_process", return_value=process), \
                patch.object(ph, "diagnose", side_effect=AssertionError("foreign namespace")):
            report = ph.diagnose_process("/data/file", PID)
        self.assertEqual(report.code, 3)
        self.assertIsNone(report.diagnosis)
        self.assertFalse(jo.process_document(report, ph.__version__)["process"]["capabilities_used_for_authorization"])

    def test_uninterpreted_maps_do_not_authorize_override(self):
        process = replace(process_with(2), uid_map=(ps.IDMapEntry(0, 100000, 65536),))
        report = evaluate(process=process)
        self.assertEqual(report.code, 3)
        self.assertIn("namespace mappings", report.diagnosis.trace.failure)

    def test_unknown_effective_bits_are_not_silently_ignored_for_denial(self):
        self.assertEqual(evaluate(1 << 63).code, 3)
        self.assertEqual(evaluate(1 << 63, permissions=0o444).code, 0)
        self.assertEqual(evaluate((1 << 63) | 2).code, 0)

    def test_missing_effective_set_is_unknown_when_bypass_needed(self):
        self.assertEqual(evaluate(process=process_with(None)).code, 3)
        self.assertEqual(evaluate(process=process_with(None), permissions=0o444).code, 0)

    def test_unknown_bounding_bits_are_not_effective(self):
        process = process_with(0, extra=f"CapBnd: {1 << 63:x}\n")
        self.assertEqual(evaluate(process=process).code, 1)

    def test_ordinary_allow_needs_no_override(self):
        inode = evaluate(2, permissions=0o444).diagnosis.trace.target
        self.assertTrue(inode.base_decision.allowed)
        self.assertFalse(inode.capability_decision.applied)


class CapabilityOutputTests(unittest.TestCase):
    def test_live_root_group_membership_explained_without_shortcut(self):
        subject = ph.process_filesystem_subject(process_with(0, root=True))
        with patch.object(ph, "read_access_acl", return_value=None):
            inode = ph.inspect_inode("/file", metadata(0o040, uid=555, gid=500), subject, "r")
        text = "\n".join(ph.explanation_inode_lines(inode, subject, "READ", False))
        self.assertIn("GROUP r--", text)
        self.assertIn("via primary group g500 (GID 500)", text)
        self.assertNotIn("ROOT", text)

    def test_concise_capability_section_and_base_acl(self):
        report = evaluate(2, mode="w", acl=make_acl(users=((9000, 6),), mask=4))
        text = ph.render_process_report(report)
        self.assertIn("CAPABILITIES", text)
        self.assertIn("Effective: CAP_DAC_OVERRIDE", text)
        self.assertIn("DAC/ACL would DENY; capability override: CAP_DAC_OVERRIDE", text)
        self.assertIn("ACL mask removes WRITE", text)
        self.assertIn("Effective result: PASS", text)
        self.assertIn("RESULT: PERMITTED", text)
        self.assertNotIn("UID 0 assumes traditional", text)

    def test_read_search_explains_scope(self):
        self.assertIn("READ/SEARCH only", ph.render_process_report(evaluate(4)))

    def test_verbose_full_sets(self):
        report = evaluate(process=process_with(2, extra="CapPrm: 402\nCapInh: 0\nCapBnd: 6\nCapAmb: 0\n"))
        text = ph.render_process_report(report, verbose=True)
        self.assertIn("permitted: CAP_DAC_OVERRIDE, CAP_NET_BIND_SERVICE", text)
        self.assertIn("ambient: none", text)
        self.assertIn("Base DAC/ACL: DENIED", text)

    def test_json_preserves_base_and_applied_override(self):
        report = evaluate(2, mode="w", acl=make_acl(users=((9000, 6),), mask=4))
        data = json.loads(jo.render_json(jo.process_document(report, ph.__version__)))
        self.assertEqual(data["schema_version"], "1")
        self.assertEqual(data["process"]["capabilities"]["effective"], ["CAP_DAC_OVERRIDE"])
        inode = data["target_inode"]
        self.assertEqual(inode["base_result"], "denied")
        self.assertEqual(inode["acl"]["result"], "denied")
        self.assertEqual(inode["result"], "permitted")
        self.assertEqual(inode["capability_override"]["capability"], "CAP_DAC_OVERRIDE")
        self.assertTrue(inode["capability_override"]["applied"])
        self.assertEqual(inode["mechanism"], "capability")

    def test_json_unknown_bits_and_raw_mask(self):
        report = evaluate((1 << 63) | 2)
        data = jo.process_document(report, ph.__version__)["process"]["capabilities"]
        self.assertEqual(data["unknown_bits"], [63])
        self.assertEqual(data["unknown_bits_by_set"]["effective"], [63])
        self.assertEqual(int(data["hex_masks"]["effective"], 16), (1 << 63) | 2)
        self.assertIsNone(data["permitted"])

    def test_root_denial_not_traditional_root_in_json(self):
        data = jo.process_document(evaluate(0, root=True), ph.__version__)
        self.assertEqual(data["verdict"], "denied")
        self.assertIsNone(data["target_inode"]["root_assumption"])
        self.assertEqual(data["target_inode"]["mechanism"], "unix_dac")

    def test_no_capability_remediation_or_execution(self):
        with patch("os.system", side_effect=AssertionError("execution")), \
                patch("os.kill", side_effect=AssertionError("process mutation")), \
                patch("os.chmod", side_effect=AssertionError("filesystem mutation")):
            report = evaluate(2)
            suggestions = ph.suggest_remediations(report.diagnosis)
        self.assertFalse(any(s.commands for s in suggestions))
