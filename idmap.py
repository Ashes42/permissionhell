"""User-namespace ID ranges and explicit bidirectional translations.

Proc status and stat expose reader-namespace IDs. For a foreign namespace,
uid_map/gid_map's outside column is also relative to the reader. Recover the
local ID in reverse, then validate it forward; never double-map status values.
"""

from dataclasses import dataclass
import re


LIMIT = 0xFFFFFFFF  # -1 is deliberately excluded by Linux's ID maps.


class IDMapError(ValueError):
    pass


@dataclass(frozen=True)
class IDMapEntry:
    inside: int
    outside: int
    length: int


@dataclass(frozen=True)
class IDTranslation:
    input_id: int
    direction: str
    translated_id: int | None
    matched_range: IDMapEntry | None = None

    @property
    def mapped_ok(self) -> bool:
        return self.translated_id is not None


@dataclass(frozen=True)
class IDMap:
    entries: tuple[IDMapEntry, ...]

    def __post_init__(self):
        for index, entry in enumerate(self.entries):
            if (any(type(value) is not int for value in (entry.inside, entry.outside, entry.length))
                    or min(entry.inside, entry.outside) < 0 or entry.length <= 0
                    or entry.inside + entry.length > LIMIT or entry.outside + entry.length > LIMIT):
                raise IDMapError("Invalid process UID/GID map range")
            for previous in self.entries[:index]:
                if any(max(getattr(entry, key), getattr(previous, key)) <
                       min(getattr(entry, key) + entry.length, getattr(previous, key) + previous.length)
                       for key in ("inside", "outside")):
                    raise IDMapError("Overlapping process UID/GID map ranges")

    @classmethod
    def parse(cls, text: str) -> "IDMap":
        entries = []
        for line in text.splitlines():
            fields = line.split()
            if not fields:
                continue
            if len(fields) != 3 or any(not re.fullmatch(r"[0-9]{1,10}", field) for field in fields):
                raise IDMapError("Malformed process UID/GID map")
            entries.append(IDMapEntry(*map(int, fields)))
        return cls(tuple(entries))

    def translate(self, identifier: int, direction: str = "inside_to_outside") -> IDTranslation:
        if type(identifier) is not int or not 0 <= identifier < LIMIT:
            raise IDMapError("Invalid ID to translate")
        if direction not in ("inside_to_outside", "outside_to_inside"):
            raise IDMapError("Unknown translation direction")
        source, target = ("inside", "outside") if direction == "inside_to_outside" else ("outside", "inside")
        for entry in self.entries:
            if getattr(entry, source) <= identifier < getattr(entry, source) + entry.length:
                return IDTranslation(identifier, direction, getattr(entry, target) + identifier - getattr(entry, source), entry)
        return IDTranslation(identifier, direction, None)


@dataclass(frozen=True)
class NamespaceID:
    observed: int
    local: int | None
    mapped: int | None
    direction: str
    matched_range: IDMapEntry | None = None
    reason: str | None = None

    @property
    def mapped_ok(self) -> bool:
        return self.mapped is not None


@dataclass(frozen=True)
class NamespaceIdentity:
    same_as_debugger: bool | None
    fsuid: NamespaceID
    fsgid: NamespaceID
    supplementary: tuple[NamespaceID, ...]


def observed_identity(identifier: int, entries: tuple[IDMapEntry, ...] | None,
                      same_namespace: bool | None, overflow: int | None) -> NamespaceID:
    if same_namespace is True:
        return NamespaceID(identifier, identifier, identifier, "direct")
    reason = None
    if same_namespace is None:
        reason = "user_namespace_unknown"
    elif entries is None:
        reason = "map_unavailable"
    elif overflow is None or identifier == overflow:
        # _munged proc exports may collapse many unmapped kernel IDs to this
        # value. Do not authorize a file owned by that overflow/nobody ID.
        reason = "overflow_id_ambiguous"
    if reason:
        return NamespaceID(identifier, None, None, "outside_to_inside_to_outside", reason=reason)
    mapping = IDMap(entries)
    local = mapping.translate(identifier, "outside_to_inside")
    if not local.mapped_ok:
        return NamespaceID(identifier, None, None, "outside_to_inside_to_outside", reason="unmapped")
    translated = mapping.translate(local.translated_id)
    return NamespaceID(identifier, local.translated_id, translated.translated_id,
                       "outside_to_inside_to_outside", translated.matched_range)


def namespace_identity(process) -> NamespaceIdentity:
    same = process.user_namespace.matches_debugger
    return NamespaceIdentity(same,
        observed_identity(process.status.uids.used, process.uid_map, same, process.overflow_uid),
        observed_identity(process.status.gids.used, process.gid_map, same, process.overflow_gid),
        tuple(observed_identity(g, process.gid_map, same, process.overflow_gid) for g in process.status.supplementary_gids))
