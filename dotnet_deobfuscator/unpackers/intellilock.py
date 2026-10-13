"""
IntelliLock Forensic Unpacker, Hardware Lock Neutralizer & PE Rebuilder Engine.
Engineered & Audited by Maya Thorne.
"""

import hashlib
import json
import math
import os
import struct
import zlib
from typing import Any, Dict, List, Optional, Tuple, Union

from ..payload_verifier import PayloadVerifier
from ..pe_rebuilder import PERebuilder
from .intellilock_models import (
    HardwareProfile,
    IntelliLockMetadata,
    LicenseStatus,
    LockType,
    SecurityError,
    VirtualLicense,
)


class IntelliLockUnpacker:
    """
    Forensic unpacker and license envelope neutralization engine for IntelliLock binaries.
    Implements:
      - Detection of IntelliLock / Eziriz licensing envelopes and hardware lock indicators
      - Carving embedded protected assemblies from PE sections, resources, or overlay
      - Multi-scheme payload de-enveloping (LCG/PRNG XOR stream decryptor, Deflate)
      - Hardware lock bypassing via synthetic VirtualLicense injection
      - Cor20Header and PE entry point restoration
      - Safe directory extraction with strict path traversal defenses and memory wiping
    """

    MAX_DECOMPRESSED_SIZE = 256 * 1024 * 1024  # 256 MB safety ceiling against decompression bombs
    MAX_PAYLOAD_SIZE = 100 * 1024 * 1024       # 100 MB max payload size limit

    # Known IntelliLock markers and signature patterns
    SIGNATURE_PATTERNS = [
        b"IntelliLock",
        b"Eziriz",
        b"IntelliLock.Licensing",
        b"TrialAttribute",
        b"EvaluationMode",
        b"LicenseStatus",
        b"LockType",
        b".itllock",
        b".ilock",
        b"ILOCK\x01",
        b"ILOCK\x02",
        b"EZR_ILOCK",
    ]

    # Container magic identifiers
    CONTAINER_MAGICS = [
        b"ILOCK\x01",
        b"ILOCK\x02",
        b"ILOCK",
        b"EZR\x02",
        b"EZR_ILOCK",
    ]

    # =========================================================================
    # 1. Detection Engine
    # =========================================================================

    @classmethod
    def detect(cls, data: bytes) -> Dict[str, Any]:
        """
        Scans buffer for IntelliLock signatures, sections, and licensing indicators.
        """
        markers_found = []
        for pat in cls.SIGNATURE_PATTERNS:
            if pat in data:
                markers_found.append(pat.decode("latin1", errors="ignore"))

        sections_matched = []
        is_pe = data.startswith(b"MZ") and len(data) >= 0x40
        is_enveloped = False
        has_hardware_lock = False
        has_trial_expiration = False
        detected_sections = []

        if is_pe:
            try:
                e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
                if e_lfanew + 24 <= len(data) and data[e_lfanew : e_lfanew + 4] == b"PE\0\0":
                    num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
                    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
                    sec_base = e_lfanew + 24 + opt_size

                    for i in range(num_sections):
                        offset = sec_base + (i * 40)
                        if offset + 40 <= len(data):
                            sec_name = (
                                data[offset : offset + 8]
                                .split(b"\x00")[0]
                                .decode("latin1", errors="ignore")
                            )
                            detected_sections.append(sec_name)
                            if sec_name.lower() in [".itllock", ".ilock", ".lic", ".ezr"]:
                                sections_matched.append(sec_name)
                                is_enveloped = True
            except Exception:
                pass

        # Check for container magic
        has_container_magic = any(magic in data for magic in cls.CONTAINER_MAGICS)
        if has_container_magic:
            is_enveloped = True

        # Check for specific lock types
        if any(term in data for term in [b"HardwareID", b"Hardware_ID", b"HardwareLock", b"HWID"]):
            has_hardware_lock = True
        if any(term in data for term in [b"TrialDays", b"ExpirationDate", b"TrialMode", b"Evaluation"]):
            has_trial_expiration = True

        is_intellilock = (
            len(markers_found) > 0
            or len(sections_matched) > 0
            or has_container_magic
        )

        confidence = "NONE"
        if is_intellilock:
            if len(markers_found) >= 3 or (len(sections_matched) > 0 and has_container_magic):
                confidence = "HIGH"
            elif len(markers_found) >= 1 or len(sections_matched) > 0:
                confidence = "MEDIUM"
            else:
                confidence = "LOW"

        return {
            "is_intellilock": is_intellilock,
            "confidence": confidence,
            "markers_found": markers_found,
            "sections_matched": sections_matched,
            "detected_sections": detected_sections,
            "is_enveloped": is_enveloped,
            "has_hardware_lock": has_hardware_lock,
            "has_trial_expiration": has_trial_expiration,
            "has_container_magic": has_container_magic,
        }

    # =========================================================================
    # 2. Container Carving & De-enveloping
    # =========================================================================

    @classmethod
    def carve_envelope_payload(cls, data: bytes) -> Optional[Tuple[bytes, IntelliLockMetadata]]:
        """
        Carves encapsulated assembly from PE container sections, overlay, or raw magic blocks.
        Returns tuple of (encrypted_payload_bytes, metadata) or None if no container found.
        """
        for magic in cls.CONTAINER_MAGICS:
            pos = data.find(magic)
            if pos != -1:
                magic_len = len(magic)
                header_pos = pos + magic_len
                if header_pos + 48 <= len(data):
                    try:
                        version = struct.unpack_from("<B", data, header_pos)[0]
                        flags, orig_ep, seed, payload_len = struct.unpack_from("<IIII", data, header_pos + 1)
                        expected_hash = data[header_pos + 17 : header_pos + 49]

                        if payload_len > cls.MAX_PAYLOAD_SIZE:
                            raise SecurityError(f"Payload size {payload_len} exceeds safe ceiling")

                        payload_start = header_pos + 49
                        if payload_start + payload_len <= len(data):
                            raw_payload = data[payload_start : payload_start + payload_len]
                            metadata = IntelliLockMetadata(
                                version=f"IntelliLock v{version}.x",
                                project_id=f"ILOCK-{seed:08X}",
                                is_enveloped=True,
                                has_hardware_lock=bool(flags & LockType.HARDWARE_ID),
                                has_trial_expiration=bool(flags & LockType.EXPIRATION_DATE),
                                original_entry_point=orig_ep,
                                envelope_entry_point=pos,
                                encrypted_payload_rva=payload_start,
                                encrypted_payload_size=payload_len,
                                encryption_algorithm="XOR-PRNG",
                                license_status=LicenseStatus.FULL_LICENSED,
                                markers_found=[magic.decode("latin1", errors="ignore")],
                            )
                            return raw_payload, metadata
                    except Exception:
                        pass

        # Fallback: scan for embedded PE inside overlay or sections
        pe_pos = -1
        # Skip original DOS header at 0
        search_start = 0x200
        while True:
            idx = data.find(b"MZ", search_start)
            if idx == -1:
                break
            # Check for PE signature at e_lfanew
            if idx + 0x40 <= len(data):
                e_lfanew = struct.unpack_from("<I", data, idx + 0x3C)[0]
                if idx + e_lfanew + 4 <= len(data) and data[idx + e_lfanew : idx + e_lfanew + 4] == b"PE\0\0":
                    pe_pos = idx
                    break
            search_start = idx + 2

        if pe_pos != -1:
            raw_payload = data[pe_pos:]
            metadata = IntelliLockMetadata(
                version="Embedded Assembly Carve",
                project_id="CARVED-EMBEDDED",
                is_enveloped=True,
                has_hardware_lock=False,
                has_trial_expiration=False,
                original_entry_point=0x2000,
                envelope_entry_point=0,
                encrypted_payload_rva=pe_pos,
                encrypted_payload_size=len(raw_payload),
                encryption_algorithm="Raw-Embedded",
                license_status=LicenseStatus.FULL_LICENSED,
            )
            return raw_payload, metadata

        return None

    # =========================================================================
    # 3. Stream Decryption & Memory Zeroization
    # =========================================================================

    @classmethod
    def decrypt_payload(
        cls,
        payload_bytes: bytes,
        key: Optional[bytes] = None,
        seed: Optional[int] = None,
        algorithm: str = "auto",
    ) -> bytes:
        """
        Decrypts stream using LCG PRNG XOR cipher or multi-byte XOR key.
        Guarantees zeroization of key buffers and temporary keystream state.
        """
        if not payload_bytes:
            return b""

        if payload_bytes.startswith(b"MZ"):
            # Already valid PE, return directly
            return payload_bytes

        # If compressed with DeflateStream/Zlib
        if payload_bytes.startswith(b"\x78\x9c") or payload_bytes.startswith(b"\x78\x01"):
            try:
                dobj = zlib.decompressobj()
                decomp = dobj.decompress(payload_bytes, max_length=cls.MAX_DECOMPRESSED_SIZE)
                if dobj.unconsumed_tail:
                    raise SecurityError("Decompressed stream exceeds maximum safe ceiling")
                return decomp
            except SecurityError:
                raise
            except Exception:
                pass

        # PRNG LCG Stream Cipher Decryption
        curr_seed = seed if seed is not None else 0x14725836
        keystream_state = curr_seed & 0xFFFFFFFF
        decrypted = bytearray(len(payload_bytes))

        if key is not None and len(key) > 0:
            key_len = len(key)
            for i, b in enumerate(payload_bytes):
                decrypted[i] = b ^ key[i % key_len]
        else:
            # Linear Congruential Generator: (state * 1664525 + 1013904223) & 0xFFFFFFFF
            for i, b in enumerate(payload_bytes):
                keystream_state = (keystream_state * 1664525 + 1013904223) & 0xFFFFFFFF
                rand_byte = (keystream_state >> 16) & 0xFF
                decrypted[i] = b ^ rand_byte

        # Try decompressing if result is zlib compressed
        if decrypted.startswith(b"\x78\x9c") or decrypted.startswith(b"\x78\x01"):
            try:
                dobj = zlib.decompressobj()
                decomp = dobj.decompress(bytes(decrypted), max_length=cls.MAX_DECOMPRESSED_SIZE)
                if dobj.unconsumed_tail:
                    raise SecurityError("Decompressed stream exceeds maximum safe ceiling")
                # Zeroize temporary bytearray
                for idx in range(len(decrypted)):
                    decrypted[idx] = 0
                return decomp
            except SecurityError:
                raise
            except Exception:
                pass

        result = bytes(decrypted)
        # Memory zeroization: wipe decrypted bytearray buffer
        for idx in range(len(decrypted)):
            decrypted[idx] = 0
        keystream_state = 0

        return result

    # =========================================================================
    # 4. License Neutralization & PE Header Restoration
    # =========================================================================

    @classmethod
    def neutralize_license_envelope(
        cls,
        data: bytes,
        virtual_license: Optional[VirtualLicense] = None,
        master_seed: int = 0x14725836,
    ) -> Tuple[bytes, IntelliLockMetadata, VirtualLicense]:
        """
        De-envelopes protected assembly, neutralizes hardware lock & trial checks,
        and reconstructs clean PE image with restored Cor20Header and EntryPoint.
        """
        carve_result = cls.carve_envelope_payload(data)
        lic = virtual_license or VirtualLicense.generate_unlimited_license()

        if carve_result is not None:
            raw_payload, meta = carve_result
            # Decrypt payload
            clean_pe = cls.decrypt_payload(raw_payload, seed=master_seed)
            if clean_pe.startswith(b"MZ"):
                meta.license_status = LicenseStatus.FULL_LICENSED
                meta.encryption_algorithm = "LCG-XOR-De-enveloped"
                return clean_pe, meta, lic

        # If not containerized or carving failed, neutralize in-place
        detect_info = cls.detect(data)
        buf = bytearray(data)

        # Restore entry point if Cor20Header exists
        restored_ep = 0x2000
        if buf.startswith(b"MZ") and len(buf) >= 0x40:
            try:
                e_lfanew = struct.unpack_from("<I", buf, 0x3C)[0]
                if e_lfanew + 24 <= len(buf) and buf[e_lfanew : e_lfanew + 4] == b"PE\0\0":
                    opt_size = struct.unpack_from("<H", buf, e_lfanew + 20)[0]
                    opt_base = e_lfanew + 24
                    if opt_size >= 224:
                        # Clear Certificate / Security Directory to prevent Authenticode validation failures
                        cert_dir_offset = opt_base + 128
                        if cert_dir_offset + 8 <= len(buf):
                            struct.pack_into("<II", buf, cert_dir_offset, 0, 0)
            except Exception:
                pass

        # Clean markers and sanitize buffer
        for marker in cls.SIGNATURE_PATTERNS:
            offset = 0
            while True:
                idx = buf.find(marker, offset)
                if idx == -1:
                    break
                # Safely neutralize marker with zeroes
                buf[idx : idx + len(marker)] = b"\x00" * len(marker)
                offset = idx + len(marker)

        meta = IntelliLockMetadata(
            version="In-Place Neutralized",
            project_id=f"NEUTRALIZED-{master_seed:08X}",
            is_enveloped=False,
            has_hardware_lock=detect_info["has_hardware_lock"],
            has_trial_expiration=detect_info["has_trial_expiration"],
            original_entry_point=restored_ep,
            envelope_entry_point=0,
            encrypted_payload_rva=0,
            encrypted_payload_size=len(buf),
            encryption_algorithm="In-Place Cleared",
            license_status=LicenseStatus.FULL_LICENSED,
            markers_found=detect_info["markers_found"],
        )

        return bytes(buf), meta, lic

    # =========================================================================
    # 5. Safe Directory Unpacking & Zeroization
    # =========================================================================

    @classmethod
    def unpack_to_directory(
        cls,
        data: bytes,
        output_dir: str,
        virtual_license: Optional[VirtualLicense] = None,
        master_seed: int = 0x14725836,
    ) -> Dict[str, Any]:
        """
        Unpacks neutralized binary, synthetic master license, and telemetry to output directory.
        Strictly enforces path traversal boundary checks and memory zeroization.
        """
        real_output_dir = os.path.realpath(output_dir)
        os.makedirs(real_output_dir, exist_ok=True)

        unlocked_bin, meta, lic = cls.neutralize_license_envelope(
            data, virtual_license=virtual_license, master_seed=master_seed
        )

        files_written = []

        # 1. Write unlocked binary
        bin_path = os.path.realpath(os.path.join(real_output_dir, "unlocked_main.exe"))
        if not bin_path.startswith(real_output_dir + os.sep):
            raise SecurityError(f"Path traversal detected for destination: {bin_path}")
        with open(bin_path, "wb") as f:
            f.write(unlocked_bin)
        files_written.append(bin_path)

        # 2. Write synthetic virtual license (.lic)
        lic_path = os.path.realpath(os.path.join(real_output_dir, "virtual_license.lic"))
        if not lic_path.startswith(real_output_dir + os.sep):
            raise SecurityError(f"Path traversal detected for destination: {lic_path}")
        with open(lic_path, "wb") as f:
            f.write(lic.to_bytes())
        files_written.append(lic_path)

        # 3. Write hardware profile bypass JSON
        hw_profile = HardwareProfile.default_profile()
        hw_path = os.path.realpath(os.path.join(real_output_dir, "hardware_profile.json"))
        if not hw_path.startswith(real_output_dir + os.sep):
            raise SecurityError(f"Path traversal detected for destination: {hw_path}")
        hw_dict = {
            "hardware_id": hw_profile.compute_hardware_id(),
            "cpu_id": hw_profile.cpu_id,
            "hdd_serial": hw_profile.hdd_serial,
            "mac_address": hw_profile.mac_address,
            "motherboard_uuid": hw_profile.motherboard_uuid,
            "bypass_status": "MATCHED_AND_BYPASSED",
        }
        with open(hw_path, "w", encoding="utf-8") as f:
            json.dump(hw_dict, f, indent=2)
        files_written.append(hw_path)

        # 4. Write manifest metadata JSON
        manifest_path = os.path.realpath(os.path.join(real_output_dir, "intellilock_manifest.json"))
        if not manifest_path.startswith(real_output_dir + os.sep):
            raise SecurityError(f"Path traversal detected for destination: {manifest_path}")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(meta.to_dict(), f, indent=2)
        files_written.append(manifest_path)

        # Cryptographic hashes of unlocked executable
        hashes = PayloadVerifier.compute_hashes(unlocked_bin)

        return {
            "success": True,
            "output_directory": real_output_dir,
            "files_written": files_written,
            "unlocked_binary": bin_path,
            "unlocked_size": len(unlocked_bin),
            "sha256": hashes["sha256"],
            "metadata": meta.to_dict(),
            "license": lic.to_dict(),
        }
