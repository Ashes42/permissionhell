"""Linux UAPI capability numbering and pure filesystem DAC bypass decisions.

Names match include/uapi/linux/capability.h through CAP_CHECKPOINT_RESTORE (40,
Linux 5.9). Future bits remain numeric. Only effective bits 1 and 2 are modeled;
FOWNER/CHOWN/FSETID affect operations outside the current r/w/x interface.
"""

from dataclasses import dataclass
import re
import stat


CAPABILITY_NAMES = tuple("CAP_" + name for name in (
    "CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID", "KILL", "SETGID", "SETUID", "SETPCAP",
    "LINUX_IMMUTABLE", "NET_BIND_SERVICE", "NET_BROADCAST", "NET_ADMIN", "NET_RAW", "IPC_LOCK", "IPC_OWNER",
    "SYS_MODULE", "SYS_RAWIO", "SYS_CHROOT", "SYS_PTRACE", "SYS_PACCT", "SYS_ADMIN", "SYS_BOOT", "SYS_NICE",
    "SYS_RESOURCE", "SYS_TIME", "SYS_TTY_CONFIG", "MKNOD", "LEASE", "AUDIT_WRITE", "AUDIT_CONTROL", "SETFCAP",
    "MAC_OVERRIDE", "MAC_ADMIN", "SYSLOG", "WAKE_ALARM", "BLOCK_SUSPEND", "AUDIT_READ", "PERFMON", "BPF",
    "CHECKPOINT_RESTORE"))
CAP_DAC_OVERRIDE = 1
CAP_DAC_READ_SEARCH = 2
STATUS_FIELDS = {"CapEff": "effective", "CapPrm": "permitted", "CapInh": "inheritable",
                 "CapBnd": "bounding", "CapAmb": "ambient"}


class CapabilityError(ValueError):
    pass


@dataclass(frozen=True)
class CapabilitySet:
    mask: int

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(name for bit, name in enumerate(CAPABILITY_NAMES) if self.mask & (1 << bit))

    @property
    def unknown_bits(self) -> tuple[int, ...]:
        return tuple(bit for bit in range(len(CAPABILITY_NAMES), self.mask.bit_length()) if self.mask & (1 << bit))

    def contains(self, bit: int) -> bool:
        return bool(self.mask & (1 << bit))


@dataclass(frozen=True)
class ProcessCapabilities:
    effective: CapabilitySet | None = None
    permitted: CapabilitySet | None = None
    inheritable: CapabilitySet | None = None
    bounding: CapabilitySet | None = None
    ambient: CapabilitySet | None = None


def parse_capability_fields(fields: dict[str, str]) -> ProcessCapabilities:
    parsed = {}
    for field, name in STATUS_FIELDS.items():
        if field in fields:
            value = fields[field]
            # Accept future widths beyond today's 64 bits, with a bounded input.
            if not re.fullmatch(r"[0-9a-fA-F]{1,256}", value):
                raise CapabilityError(f"Malformed {field} field in process status")
            parsed[name] = CapabilitySet(int(value, 16))
    return ProcessCapabilities(**parsed)


@dataclass(frozen=True)
class CapabilityDecision:
    base_allowed: bool
    allowed: bool
    capability: str | None
    reason: str

    @property
    def applied(self) -> bool:
        return self.capability is not None


def evaluate_capabilities(base_allowed: bool, inode_mode: int, required: int,
                          effective: CapabilitySet | None, context_supported: bool = True, *,
                          context_reason: str | None = None) -> CapabilityDecision:
    """Apply Linux generic_permission's DAC bypasses after a known DAC/ACL result.

    Mount restrictions remain the verdict engine's responsibility. Unknown ACLs
    are not passed here as denials. Directory read/search prefers READ_SEARCH,
    matching generic_permission's ordering when both capabilities are effective.
    """
    if base_allowed:
        return CapabilityDecision(True, True, None, "Ordinary DAC/ACL permits access; no capability override needed.")
    if effective is None:
        raise CapabilityError("CapEff is unavailable; cannot determine whether capabilities bypass the DAC/ACL denial.")
    directory = stat.S_ISDIR(inode_mode)
    capability = None
    if effective.contains(CAP_DAC_READ_SEARCH) and (required == 4 or directory and required == 1):
        capability = "CAP_DAC_READ_SEARCH"
    elif effective.contains(CAP_DAC_OVERRIDE) and (directory or required != 1 or inode_mode & 0o111):
        capability = "CAP_DAC_OVERRIDE"
    if capability:
        if not context_supported:
            raise CapabilityError(context_reason or "Capability bypass requires supported UID/GID namespace mappings; "
                                  "non-identity or unavailable maps are not interpreted.")
        detail = " (READ/SEARCH only)" if capability == "CAP_DAC_READ_SEARCH" else ""
        return CapabilityDecision(False, True, capability, f"{capability}{detail} bypasses the ordinary DAC/ACL denial.")
    if effective.unknown_bits:
        raise CapabilityError(f"Unknown effective capability bits {effective.unknown_bits}; cannot resolve this DAC/ACL denial conservatively.")
    reason = "No effective capability applicable to this request bypasses the DAC/ACL denial."
    if required == 1 and not directory and not inode_mode & 0o111:
        reason += " CAP_DAC_OVERRIDE still requires at least one execute bit on a non-directory inode."
    return CapabilityDecision(False, False, None, reason)
