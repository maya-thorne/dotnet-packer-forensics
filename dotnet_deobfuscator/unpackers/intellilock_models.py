"""
IntelliLock Forensic Data Models, Licensing State & Hardware Fingerprinting.
Engineered & Audited by Maya Thorne.
"""

from dataclasses import asdict, dataclass, field
from enum import Enum, IntFlag
import hashlib
import json
import os
import struct
import time
from typing import Any, Dict, List, Optional


class SecurityError(Exception):
    """Raised when malicious path traversal, tampering, or resource exhaustion is detected."""
    pass


class LockType(IntFlag):
    """IntelliLock restriction bitmasks governing license enforcement."""
    NONE = 0x00
    HARDWARE_ID = 0x01       # Bound to host hardware fingerprint
    EXPIRATION_DATE = 0x02   # Enforces trial calendar deadline
    MAX_RUNS = 0x04          # Enforces execution count ceiling
    RUNTIME_LIMIT = 0x08     # Enforces per-session execution minutes
    GLOBAL_TIME = 0x10       # Requires NTP network time synchronization
    FEATURE_FLAGS = 0x20     # Custom feature license bits enabled


class LicenseStatus(str, Enum):
    """Licensing evaluation state for target assembly."""
    UNLICENSED = "UNLICENSED"
    TRIAL_ACTIVE = "TRIAL_ACTIVE"
    TRIAL_EXPIRED = "TRIAL_EXPIRED"
    HARDWARE_MISMATCH = "HARDWARE_MISMATCH"
    FULL_LICENSED = "FULL_LICENSED"
    TAMPERED = "TAMPERED"
    BLACKLISTED = "BLACKLISTED"


@dataclass
class HardwareProfile:
    """
    Host machine hardware fingerprint representation for IntelliLock validation.
    Generates deterministic hardware hashes used to bypass machine locking.
    """
    cpu_id: str = "BFEBFBFF000906EA"
    hdd_serial: str = "WD-WCC4N7VF4L1K"
    mac_address: str = "00:15:5D:84:A2:1F"
    motherboard_uuid: str = "4C4C4544-004E-4A10-8032-B2C04F383232"
    machine_guid: str = "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d"

    def compute_hardware_id(self) -> str:
        """
        Computes the canonical IntelliLock 16-character hardware identifier hash
        in 'XXXX-XXXX-XXXX-XXXX' hex format.
        """
        seed = f"{self.cpu_id}|{self.hdd_serial}|{self.mac_address}|{self.motherboard_uuid}|{self.machine_guid}"
        raw_hash = hashlib.sha256(seed.encode("utf-8")).hexdigest().upper()
        # Format as 4 groups of 4 characters
        return f"{raw_hash[0:4]}-{raw_hash[4:8]}-{raw_hash[8:12]}-{raw_hash[12:16]}"

    @classmethod
    def default_profile(cls) -> "HardwareProfile":
        """Returns standard sandbox evaluation hardware profile."""
        return cls()

    @classmethod
    def from_string(cls, hardware_id: str) -> "HardwareProfile":
        """Constructs synthetic profile matching an arbitrary hardware identifier."""
        clean_id = hardware_id.replace("-", "").strip()
        return cls(
            cpu_id=f"CPU-{clean_id[:8]}",
            hdd_serial=f"HDD-{clean_id[8:16]}",
            mac_address="00:15:5D:FF:FF:FF",
            motherboard_uuid=f"UUID-{clean_id}",
            machine_guid=f"GUID-{clean_id}",
        )


@dataclass
class VirtualLicense:
    """
    Synthetic master license structure used to bypass hardware locking and trial deadlines.
    Can serialize to IntelliLock binary (.lic) container format.
    """
    licensee: str = "Forensic Security Research Sandbox"
    company: str = "Enterprise Malware Forensics Lab"
    hardware_id: str = "*"  # Wildcard denotes unlocked for all machines
    lock_type: int = int(LockType.NONE)
    expiration_date: str = "2099-12-31"
    runs_allowed: int = 999999
    runs_remaining: int = 999999
    features_mask: int = 0xFFFFFFFF
    project_id: str = "EZR-ILOCK-2026"
    custom_data: str = "UNLOCKED_MASTER_FORENSIC_KEY"
    status: LicenseStatus = LicenseStatus.FULL_LICENSED
    signature: bytes = field(default_factory=lambda: hashlib.sha256(b"VIRTUAL_MASTER_SIG").digest())

    MAGIC_HEADER = b"ILIC\x01\x00"  # IntelliLock binary license magic

    def to_dict(self) -> Dict[str, Any]:
        """Converts license parameters to dictionary."""
        data = asdict(self)
        data["status"] = self.status.value
        data["signature"] = self.signature.hex()
        return data

    def to_bytes(self) -> bytes:
        """
        Serializes virtual license into an IntelliLock-compatible binary .lic file.
        Header:
          [0:6]   Magic 'ILIC\x01\x00'
          [6:8]   Header Version (0x0001)
          [8:12]  Flags & LockType
          [12:16] Payload JSON length
          [16:48] SHA-256 HMAC signature of payload
          [48:..] UTF-8 JSON payload
        """
        payload_dict = self.to_dict()
        payload_bytes = json.dumps(payload_dict, sort_keys=True).encode("utf-8")
        sig = hashlib.sha256(payload_bytes + b"INTELLILOCK_HMAC_SECRET").digest()

        buf = bytearray()
        buf.extend(self.MAGIC_HEADER)
        buf.extend(struct.pack("<H", 1))                # Version
        buf.extend(struct.pack("<I", self.lock_type))   # LockType flags
        buf.extend(struct.pack("<I", len(payload_bytes)))  # Payload length
        buf.extend(sig)                                 # 32 bytes HMAC
        buf.extend(payload_bytes)                       # Payload
        return bytes(buf)

    @classmethod
    def from_bytes(cls, data: bytes) -> "VirtualLicense":
        """
        Deserializes binary .lic container and verifies HMAC signature integrity.
        """
        if len(data) < 48:
            raise SecurityError("Invalid license container: buffer too small (< 48 bytes)")

        magic = data[0:6]
        if magic != cls.MAGIC_HEADER:
            raise SecurityError(f"Invalid license header magic: {magic!r}")

        version, lock_type, payload_len = struct.unpack_from("<HII", data, 6)
        expected_sig = data[16:48]

        if 48 + payload_len > len(data):
            raise SecurityError("License container payload truncated or length corrupted")

        payload_bytes = data[48 : 48 + payload_len]
        computed_sig = hashlib.sha256(payload_bytes + b"INTELLILOCK_HMAC_SECRET").digest()

        if computed_sig != expected_sig:
            # Tampering detected
            parsed = json.loads(payload_bytes.decode("utf-8", errors="replace"))
            lic = cls(
                licensee=parsed.get("licensee", "Unknown"),
                company=parsed.get("company", "Unknown"),
                hardware_id=parsed.get("hardware_id", "*"),
                lock_type=lock_type,
                status=LicenseStatus.TAMPERED,
                signature=expected_sig,
            )
            return lic

        parsed = json.loads(payload_bytes.decode("utf-8"))
        return cls(
            licensee=parsed.get("licensee", "Licensed User"),
            company=parsed.get("company", "Licensed Org"),
            hardware_id=parsed.get("hardware_id", "*"),
            lock_type=parsed.get("lock_type", 0),
            expiration_date=parsed.get("expiration_date", "2099-12-31"),
            runs_allowed=parsed.get("runs_allowed", 999999),
            runs_remaining=parsed.get("runs_remaining", 999999),
            features_mask=parsed.get("features_mask", 0xFFFFFFFF),
            project_id=parsed.get("project_id", "EZR-ILOCK-2026"),
            custom_data=parsed.get("custom_data", ""),
            status=LicenseStatus(parsed.get("status", "FULL_LICENSED")),
            signature=bytes.fromhex(parsed.get("signature", computed_sig.hex())),
        )

    @classmethod
    def generate_unlimited_license(cls, hardware_id: str = "*") -> "VirtualLicense":
        """Synthesizes a master perpetual license bypassing all hardware and trial checks."""
        return cls(
            licensee="Forensic Security Analyst",
            company="Forensic Reverse Engineering Lab",
            hardware_id=hardware_id,
            lock_type=int(LockType.NONE),
            expiration_date="2099-12-31",
            runs_allowed=999999,
            runs_remaining=999999,
            features_mask=0xFFFFFFFF,
            project_id="EZR-MASTER-UNLOCKED",
            status=LicenseStatus.FULL_LICENSED,
        )


@dataclass
class IntelliLockMetadata:
    """Forensic metadata parsed from protected IntelliLock envelope."""
    version: str = "Unknown"
    project_id: str = ""
    is_enveloped: bool = False
    has_hardware_lock: bool = False
    has_trial_expiration: bool = False
    original_entry_point: int = 0
    envelope_entry_point: int = 0
    encrypted_payload_rva: int = 0
    encrypted_payload_size: int = 0
    encryption_algorithm: str = "XOR-PRNG"
    license_status: LicenseStatus = LicenseStatus.UNLICENSED
    hardware_id_required: Optional[str] = None
    embedded_assembly_name: Optional[str] = None
    markers_found: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Converts metadata to dictionary format."""
        data = asdict(self)
        data["license_status"] = self.license_status.value
        data["original_entry_point"] = hex(self.original_entry_point)
        data["envelope_entry_point"] = hex(self.envelope_entry_point)
        data["encrypted_payload_rva"] = hex(self.encrypted_payload_rva)
        return data
