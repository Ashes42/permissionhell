"""Read and evaluate Linux POSIX access ACLs; no filesystem mutation or rendering."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import errno
import os
import struct


ACCESS_XATTR = "system.posix_acl_access"
UNDEFINED_ID = 0xFFFFFFFF


class ACLInspectionError(Exception):
    """ACL state is unavailable or inconsistent; do not assume it is absent."""


class Tag(IntEnum):
    OWNER = 0x01
    USER = 0x02
    GROUP_OBJ = 0x04
    GROUP = 0x08
    MASK = 0x10
    OTHER = 0x20


@dataclass(frozen=True)
class ACLEntry:
    tag: Tag
    permissions: int
    qualifier: int | None = None


@dataclass(frozen=True)
class AccessACL:
    entries: tuple[ACLEntry, ...]

    def entry(self, tag: Tag) -> ACLEntry | None:
        return next((entry for entry in self.entries if entry.tag == tag), None)

    @property
    def extended(self) -> bool:
        return self.entry(Tag.MASK) is not None


@dataclass(frozen=True)
class ACLMatch:
    selection: str
    entries: tuple[ACLEntry, ...]
    specified: int
    mask: int | None
    effective: int
    required: int
    allowed: bool


def parse_access_acl(data: bytes) -> AccessACL:
    """Decode the Linux version-2 little-endian xattr ABI, rejecting invalid ACLs."""
    if len(data) < 4 or (len(data) - 4) % 8:
        raise ACLInspectionError("Malformed ACL xattr length.")
    if struct.unpack_from("<I", data)[0] != 2:
        raise ACLInspectionError("Unsupported ACL xattr version (expected 2).")
    entries = []
    seen = set()
    previous_tag = 0
    for tag_value, permissions, identifier in struct.iter_unpack("<HHI", data[4:]):
        try:
            tag = Tag(tag_value)
        except ValueError:
            raise ACLInspectionError(f"Malformed ACL: unknown tag {tag_value}.") from None
        if permissions & ~7:
            raise ACLInspectionError("Malformed ACL permission bits.")
        named = tag in (Tag.USER, Tag.GROUP)
        if named == (identifier == UNDEFINED_ID):
            raise ACLInspectionError("Malformed ACL entry identifier.")
        qualifier = identifier if named else None
        key = (tag, qualifier)
        if key in seen or tag < previous_tag:
            raise ACLInspectionError("Malformed ACL: duplicate or out-of-order entries.")
        seen.add(key)
        previous_tag = tag
        entries.append(ACLEntry(tag, permissions, qualifier))
    acl = AccessACL(tuple(entries))
    if any(acl.entry(tag) is None for tag in (Tag.OWNER, Tag.GROUP_OBJ, Tag.OTHER)):
        raise ACLInspectionError("Malformed ACL: missing owner, owning-group, or other entry.")
    if any(entry.tag in (Tag.USER, Tag.GROUP) for entry in entries) and not acl.extended:
        raise ACLInspectionError("Malformed ACL: named entries require a mask.")
    return acl


def read_access_acl(path: str) -> AccessACL | None:
    """None means ENODATA only, never unsupported/unreadable/malformed."""
    try:
        data = os.getxattr(path, ACCESS_XATTR, follow_symlinks=False)
    except (AttributeError, NotImplementedError) as exc:
        raise ACLInspectionError("Python does not provide Linux ACL xattr inspection.") from exc
    except OSError as exc:
        if exc.errno == errno.ENODATA:
            return None
        if exc.errno in (errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS):
            raise ACLInspectionError("Access-ACL inspection is unsupported; ACL absence is unconfirmed.") from exc
        raise ACLInspectionError(f"Cannot read access ACL: {exc}") from exc
    return parse_access_acl(data)


def validate_acl_mode(acl: AccessACL, mode: int) -> None:
    """Detect inconsistent snapshots instead of combining incompatible observations."""
    group = acl.entry(Tag.MASK) or acl.entry(Tag.GROUP_OBJ)
    expected = (acl.entry(Tag.OWNER).permissions << 6) | (group.permissions << 3) | acl.entry(Tag.OTHER).permissions
    if expected != mode & 0o777:
        raise ACLInspectionError("ACL and mode bits disagree; metadata may have changed during inspection.")


def evaluate_acl(acl: AccessACL, uid: int, gids: frozenset[int], owner_uid: int,
                 owner_gid: int, required: int) -> ACLMatch:
    """Evaluate one r/w/x bit. Root bypass is applied by the existing DAC layer.

    Linux tests a complete requested mask against an individual matching group
    entry, not a union of split multi-bit grants. For this CLI's single-bit
    requests, the union below is equivalent and describes available individual
    permissions. Reject combined requests rather than generalizing incorrectly.
    """
    if required not in (1, 2, 4):
        raise ValueError("ACL evaluation requires exactly one of r, w, or x.")
    mask_entry = acl.entry(Tag.MASK)
    mask = None
    if uid == owner_uid:
        selection, matches = "OWNER", (acl.entry(Tag.OWNER),)
    else:
        named_user = next((entry for entry in acl.entries if entry.tag == Tag.USER and entry.qualifier == uid), None)
        groups = tuple(entry for entry in acl.entries
                       if (entry.tag == Tag.GROUP_OBJ and owner_gid in gids)
                       or (entry.tag == Tag.GROUP and entry.qualifier in gids))
        if named_user is not None:
            selection, matches = "NAMED USER", (named_user,)
            mask = mask_entry.permissions
        elif groups:
            selection, matches = "GROUP", groups
            mask = mask_entry.permissions if mask_entry else None
        else:
            selection, matches = "OTHER", (acl.entry(Tag.OTHER),)
    specified = 0
    for entry in matches:
        specified |= entry.permissions
    effective = specified if mask is None else specified & mask
    return ACLMatch(selection, matches, specified, mask, effective, required, bool(effective & required))
