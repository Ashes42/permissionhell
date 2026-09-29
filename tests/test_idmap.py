"""Namespace mapping without namespace creation or credential changes."""

from dataclasses import replace
import json
import os
import stat
import sys
import unittest
from unittest.mock import patch

from idmap import IDMap, IDMapEntry, IDMapError, namespace_identity
import json_output as jo
import permissionhell as ph
import process_subject as ps
from test_permissionhell import metadata, MOUNTINFO, ROOT
from test_posix_acl import make_acl, acl_metadata
from test_process_subject import snapshot, PID
from test_capabilities import evaluate as evaluate_same_namespace


MAP = (IDMapEntry(0, 100000, 65536),)


def foreign(*, uid=100000, gid=100000, groups=(100010,), capability=0, uid_map=MAP, gid_map=MAP):
    # Linux exports these in the READER's namespace, not the target namespace.
    text = (f"Name: worker\nUid: {uid} {uid} {uid} {uid}\nGid: {gid} {gid} {gid} {gid}\n"
            f"Groups: {' '.join(map(str, groups))}\nCapEff: {capability:x}\n")
    return replace(snapshot(text), user_namespace=ps.NamespaceObservation("user:[9]", "user:[2]", False),
                   uid_map=uid_map, gid_map=gid_map, overflow_uid=65534, overflow_gid=65534, setgroups="deny")


def evaluate(process=None, *, owner=0, group=0, permissions=0o600, acl=None, mode="r", readonly=False):
    process = process or foreign()
    def st(path):
        if path in ("/", "/data"):
            return metadata(0o755, uid=9999, gid=9999, kind=stat.S_IFDIR)
        if path == "/data/file":
            return acl_metadata(acl, uid=owner, gid=group) if acl else metadata(permissions, uid=owner, gid=group)
        raise AssertionError(path)
    mount = ph.parse_mountinfo(MOUNTINFO)[0]
    if readonly:
        mount = replace(mount, options=frozenset({"ro"}))
    with patch.object(ph, "inspect_process", return_value=process), \
            patch.object(ph.os, "stat", side_effect=st), patch.object(ph.os, "lstat", side_effect=st), \
            patch.object(ph, "read_mounts", return_value=[mount]), \
            patch.object(ph, "owner_name", side_effect=str), patch.object(ph, "group_name", side_effect=str), \
            patch.object(ph, "read_access_acl", side_effect=lambda p: acl if p == "/data/file" else None):
        return ph.diagnose_process("/data/file", PID, mode)


class IDMapTests(unittest.TestCase):
    def test_single_uid_and_gid_maps(self):
        for text in ("0 100000 65536", "0 200000 100"):
            mapping = IDMap.parse(text)
            self.assertEqual(mapping.entries[0].inside, 0)
            self.assertEqual(mapping.translate(0).translated_id, mapping.entries[0].outside)

    def test_multiple_disjoint_ranges_and_order(self):
        mapping = IDMap.parse("1000 7000 10\n0 100000 100\n")
        self.assertEqual(mapping.translate(1005).translated_id, 7005)
        self.assertEqual(mapping.translate(5).translated_id, 100005)
        self.assertIsNone(mapping.translate(200).translated_id)

    def test_rootless_single_id_plus_range(self):
        mapping = IDMap.parse("0 1000 1\n1 100000 65535")
        self.assertEqual(mapping.translate(0).translated_id, 1000)
        self.assertEqual(mapping.translate(1).translated_id, 100000)
        self.assertEqual(mapping.translate(65535).translated_id, 165534)

    def test_range_boundaries(self):
        mapping = IDMap(MAP)
        for local, mapped in ((0, 100000), (100, 100100), (65535, 165535)):
            result = mapping.translate(local)
            self.assertEqual(result.translated_id, mapped)
            self.assertEqual(result.matched_range, MAP[0])
            self.assertTrue(result.mapped_ok)
            self.assertEqual(result.direction, "inside_to_outside")
        self.assertFalse(mapping.translate(65536).mapped_ok)

    def test_inverse_translation(self):
        result = IDMap(MAP).translate(100010, "outside_to_inside")
        self.assertEqual(result.input_id, 100010)
        self.assertEqual(result.translated_id, 10)
        self.assertEqual(result.direction, "outside_to_inside")

    def test_large_valid_ids(self):
        mapping = IDMap.parse("4294967294 4294967294 1")
        self.assertEqual(mapping.translate(4294967294).translated_id, 4294967294)
        self.assertEqual(IDMap.parse("0 0 4294967295").translate(4294967294).translated_id, 4294967294)

    def test_empty_map(self):
        self.assertEqual(IDMap.parse("\n").entries, ())
        self.assertFalse(IDMap.parse("").translate(0).mapped_ok)

    def test_malformed_and_overlapping_maps(self):
        for text in ("0 0", "0 0 1 2", "x 0 1", "0 -1 1", "0 0 0", "0 0 4294967296",
                     "0 1000 10\n5 2000 10", "0 1000 10\n100 1005 10", "4294967295 0 1"):
            with self.subTest(text=text), self.assertRaises(IDMapError):
                IDMap.parse(text)

    def test_invalid_translation_inputs(self):
        for identifier in (-1, 4294967295, True, "0"):
            with self.subTest(identifier=identifier), self.assertRaises(IDMapError):
                IDMap(MAP).translate(identifier)
        with self.assertRaises(IDMapError):
            IDMap(MAP).translate(0, "guess")


class NamespaceIdentityTests(unittest.TestCase):
    def test_fsuid_fsgid_and_supplementary_round_trip(self):
        identity = namespace_identity(foreign())
        self.assertEqual((identity.fsuid.observed, identity.fsuid.local, identity.fsuid.mapped), (100000, 0, 100000))
        self.assertEqual((identity.fsgid.local, identity.fsgid.mapped), (0, 100000))
        self.assertEqual((identity.supplementary[0].local, identity.supplementary[0].mapped), (10, 100010))

    def test_status_is_not_mapped_twice(self):
        report = evaluate(owner=100000)
        self.assertEqual(report.code, 0)
        self.assertEqual(report.diagnosis.subject.uid, 100000)
        self.assertNotEqual(report.diagnosis.subject.uid, 200000)

    def test_local_zero_is_not_assumed_from_raw_status_zero(self):
        report = evaluate(foreign(uid=0))
        self.assertEqual(report.code, 3)
        self.assertEqual(report.namespace_identity.fsuid.reason, "unmapped")
        self.assertEqual(report.indeterminate_reason, "uid_mapping_unresolved")

    def test_unmapped_supplementary_preserved(self):
        value = namespace_identity(foreign(groups=(200000,))).supplementary[0]
        self.assertEqual(value.observed, 200000)
        self.assertIsNone(value.local)
        self.assertIsNone(value.mapped)
        self.assertEqual(value.reason, "unmapped")

    def test_setgroups_parser(self):
        self.assertEqual(ps.parse_setgroups("allow\n"), "allow")
        self.assertEqual(ps.parse_setgroups("deny\n"), "deny")
        for value in ("", "unknown", "allow deny"):
            with self.subTest(value=value), self.assertRaises(ps.ProcessInspectionError):
                ps.parse_setgroups(value)

    def test_setgroups_unavailable(self):
        with patch("pathlib.Path.read_text", side_effect=PermissionError):
            self.assertEqual(ps.read_setgroups(PID), "unavailable")

    def test_overflow_id_cannot_become_owner(self):
        process = foreign(uid=65534, uid_map=(IDMapEntry(0, 65534, 100),))
        report = evaluate(process, owner=65534)
        self.assertEqual(report.code, 3)
        self.assertEqual(report.namespace_identity.fsuid.reason, "overflow_id_ambiguous")

    def test_same_namespace_is_direct_even_with_nonidentity_parent_map(self):
        process = replace(snapshot(), uid_map=MAP, gid_map=MAP)
        identity = namespace_identity(process)
        self.assertEqual(identity.fsuid.local, 9000)
        self.assertEqual(identity.fsuid.mapped, 9000)
        self.assertEqual(identity.fsuid.direction, "direct")


class MappedPermissionTests(unittest.TestCase):
    def test_container_root_is_not_host_root(self):
        report = evaluate(owner=0)
        self.assertEqual(report.code, 1)
        self.assertEqual(report.diagnosis.trace.target.decision.permission_class, "OTHER")
        self.assertEqual(report.namespace_identity.fsuid.local, 0)
        self.assertEqual(report.diagnosis.subject.uid, 100000)
        self.assertFalse(report.diagnosis.trace.target.decision.root_override)

    def test_mapped_owner_grant(self):
        report = evaluate(owner=100000)
        self.assertEqual(report.code, 0)
        self.assertEqual(report.diagnosis.trace.target.decision.permission_class, "OWNER")

    def test_mapped_primary_group_grant(self):
        report = evaluate(group=100000, permissions=0o640)
        self.assertEqual(report.code, 0)
        self.assertEqual(report.diagnosis.trace.target.decision.permission_class, "GROUP")

    def test_mapped_supplementary_grant_with_setgroups_deny(self):
        report = evaluate(group=100010, permissions=0o640)
        self.assertEqual(report.process.setgroups, "deny")
        self.assertEqual(report.code, 0)

    def test_other_access(self):
        self.assertEqual(evaluate(permissions=0o644).code, 0)

    def test_unmapped_primary_cannot_falsely_grant(self):
        report = evaluate(foreign(gid=200000, groups=()), group=200000, permissions=0o640)
        self.assertEqual(report.code, 3)
        self.assertEqual(report.indeterminate_reason, "group_mapping_unresolved")
        self.assertNotIn(200000, report.diagnosis.subject.gids)

    def test_unknown_group_can_also_remove_other_grant(self):
        report = evaluate(foreign(groups=(200000,)), permissions=0o004)
        self.assertEqual(report.code, 3)

    def test_missing_uid_map_is_indeterminate(self):
        report = evaluate(foreign(uid_map=None), owner=100000)
        self.assertEqual(report.code, 3)
        self.assertEqual(report.indeterminate_reason, "uid_mapping_unresolved")

    def test_unrelated_missing_gid_map_does_not_poison_owner(self):
        report = evaluate(foreign(gid_map=None), owner=100000)
        self.assertEqual(report.code, 0)
        self.assertEqual(report.diagnosis.trace.target.decision.permission_class, "OWNER")

    def test_irrelevant_unmapped_group_does_not_poison_deny(self):
        report = evaluate(foreign(groups=(200000,)), permissions=0)
        self.assertEqual(report.code, 1)

    def test_named_user_acl_uses_mapped_uid(self):
        report = evaluate(acl=make_acl(users=((100000, 4),), mask=4))
        self.assertEqual(report.code, 0)
        self.assertEqual(report.diagnosis.trace.target.acl_match.entries[0].qualifier, 100000)

    def test_named_group_acl_uses_mapped_gid(self):
        report = evaluate(acl=make_acl(groups=((100010, 4),), mask=4))
        self.assertEqual(report.code, 0)
        self.assertEqual(report.diagnosis.trace.target.acl_match.selection, "GROUP")

    def test_acl_mask_still_denies(self):
        report = evaluate(acl=make_acl(users=((100000, 6),), mask=4), mode="w")
        self.assertEqual(report.code, 1)
        self.assertEqual(report.diagnosis.trace.target.acl_match.effective, 4)

    def test_unmapped_group_never_matches_acl_entry(self):
        report = evaluate(foreign(groups=(200000,)), acl=make_acl(groups=((200000, 4),), mask=4))
        self.assertEqual(report.code, 3)
        self.assertNotIn(200000, report.diagnosis.subject.gids)

    def test_named_user_acl_independent_of_unknown_groups(self):
        report = evaluate(foreign(gid_map=None), acl=make_acl(users=((100000, 4),), mask=4))
        self.assertEqual(report.code, 0)

    def test_known_group_acl_grant_not_poisoned_by_extra_unmapped_group(self):
        report = evaluate(foreign(groups=(100010, 200000)), acl=make_acl(groups=((100010, 4),), mask=4))
        self.assertEqual(report.code, 0)

    def test_foreign_capability_not_needed_for_ordinary_allow(self):
        self.assertEqual(evaluate(foreign(capability=2), owner=100000).code, 0)

    def test_foreign_capability_cannot_override_host_denial(self):
        for cap in (2, 4):
            with self.subTest(cap=cap):
                report = evaluate(foreign(capability=cap), owner=0)
                self.assertEqual(report.code, 3)
                self.assertEqual(report.indeterminate_reason, "capability_scope_unestablished")
                self.assertFalse(report.diagnosis.trace.partial_inode.base_decision.allowed)

    def test_irrelevant_foreign_read_search_does_not_poison_write_denial(self):
        self.assertEqual(evaluate(foreign(capability=4), mode="w").code, 1)

    def test_foreign_user_same_mount_can_evaluate(self):
        self.assertEqual(evaluate(owner=100000).code, 0)

    def test_foreign_mount_and_root_still_block(self):
        process = foreign()
        for changed in (replace(process, mount_namespace=ps.NamespaceObservation("mnt:[9]", "mnt:[1]", False)),
                        replace(process, root=replace(process.root, path="/jail", matches_debugger=False))):
            with self.subTest(process=changed), patch.object(ph, "inspect_process", return_value=changed), \
                    patch.object(ph, "diagnose", side_effect=AssertionError("ambiguous path")):
                report = ph.diagnose_process("/file", PID)
            self.assertEqual(report.code, 3)
            self.assertEqual(report.namespace_identity.fsuid.mapped, 100000)
            self.assertEqual(report.indeterminate_reason, "path_context_unresolved")

    def test_mount_still_wins_after_mapped_dac_grant(self):
        report = evaluate(owner=100000, mode="w", readonly=True)
        self.assertEqual(report.code, 1)
        self.assertTrue(report.diagnosis.trace.target.base_decision.allowed)

    def test_same_namespace_capability_and_root_preserved(self):
        self.assertEqual(evaluate_same_namespace(2).code, 0)
        self.assertEqual(evaluate_same_namespace(0, root=True).code, 1)
        self.assertTrue(ph.evaluate_permission(ROOT, metadata(0, uid=100000), "r").allowed)


class NamespaceOutputTests(unittest.TestCase):
    def test_concise_local_mapped_class_explanation(self):
        text = ph.render_process_report(evaluate())
        self.assertIn("local 0 -> debugger ID 100000", text)
        self.assertIn("OTHER ---", text)
        self.assertIn("never namespace-local root as host root", text)
        self.assertIn("setgroups: deny", text)

    def test_unmapped_output(self):
        text = ph.render_process_report(evaluate(foreign(groups=(200000,)), group=200000, permissions=0o640))
        self.assertIn("unmapped/unresolved (observed 200000; unmapped)", text)
        self.assertIn("RESULT: INDETERMINATE", text)

    def test_large_maps_compact_and_verbose(self):
        maps = tuple(IDMapEntry(i * 100, 100000 + i * 100, 100) for i in range(5))
        report = evaluate(foreign(uid_map=maps, gid_map=maps), owner=100000)
        compact = ph.render_process_report(report)
        full = ph.render_process_report(report, verbose=True)
        self.assertIn("+2 ranges", compact)
        self.assertIn("400-499 -> 100400-100499", full)
        self.assertIn("UID map (observed only)", full)

    def test_json_identity_and_setgroups(self):
        data = json.loads(jo.render_json(jo.process_document(evaluate(owner=100000), ph.__version__)))
        self.assertEqual(data["schema_version"], "1")
        process = data["process"]
        self.assertEqual(process["credentials"]["uids"]["filesystem"]["id"], 100000)
        value = process["filesystem_identity"]["fsuid"]
        self.assertEqual((value["local"], value["mapped"], value["mapped_ok"]), (0, 100000, True))
        self.assertEqual(value["direction"], "outside_to_inside_to_outside")
        self.assertEqual(process["user_namespace"]["setgroups"], "deny")
        self.assertEqual(data["target_inode"]["identity_used"]["uid"], 100000)
        self.assertEqual(data["target_inode"]["identity_used"]["source"], "mapped_foreign_user_namespace")

    def test_json_scope_uncertainty_preserves_base(self):
        data = jo.process_document(evaluate(foreign(capability=2)), ph.__version__)
        self.assertEqual(data["verdict"], "indeterminate")
        self.assertEqual(data["indeterminate_reason"], "capability_scope_unestablished")
        self.assertEqual(data["unresolved_inode"]["base_result"], "denied")
        self.assertEqual(data["unresolved_inode"]["result"], "unknown")
        self.assertFalse(data["unresolved_inode"]["capability_override"]["applied"])

    def test_json_unknown_gid_is_null_not_sentinel(self):
        data = jo.process_document(evaluate(foreign(gid_map=None), owner=100000), ph.__version__)
        self.assertIsNone(data["subject"]["primary_gid"])
        self.assertIsNone(data["target_inode"]["identity_used"]["gid"])

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux proc map integration")
    def test_current_process_maps_and_direct_identity(self):
        try:
            process = ps.inspect_process(os.getpid())
            uid_map = IDMap.parse(ps.read_text("/proc/self/uid_map"))
            gid_map = IDMap.parse(ps.read_text("/proc/self/gid_map"))
        except (OSError, ps.ProcessInspectionError) as exc:
            self.skipTest(f"proc unavailable: {exc}")
        identity = namespace_identity(process)
        self.assertTrue(identity.same_as_debugger)
        self.assertEqual(identity.fsuid.mapped, process.status.uids.used)
        self.assertEqual(identity.fsgid.mapped, process.status.gids.used)
        self.assertEqual(uid_map.entries, process.uid_map)
        self.assertEqual(gid_map.entries, process.gid_map)
