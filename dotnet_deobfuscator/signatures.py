"""
Heuristic Signatures & Detection Rules for 8 Major .NET Protectors.
Engineered & Audited by Maya Thorne.
"""

from typing import Dict, List


class ProtectorSignatures:
    """Matches byte patterns and string artifacts against 8 major .NET packers."""

    RULES = [
        {
            "name": "xorPacker",
            "type": "PE Overlay Packer",
            "signatures": [b"***", b"randomkey", b"xorStub"],
            "description": "Two-stage dynamic XOR overlay packer with '***' delimiter and 'randomkey' master secret",
        },
        {
            "name": "ConfuserEx",
            "type": ".NET Modular Protector",
            "signatures": [
                b"ConfuserEx",
                b"Confuser.Core",
                b"ConfusedByAttribute",
                b"AntiDump",
                b"AntiTamper",
            ],
            "description": "Modular CIL protector with dnlib engine, control flow flattening, and JIT anti-tamper",
        },
        {
            "name": ".NET Reactor",
            "type": "Commercial CIL Protector",
            "signatures": [b".NET Reactor", b"Eziriz", b"NecroBit"],
            "description": "Native envelope wrapper with NecroBit method replacement and runtime P/Invoke stubs",
        },
        {
            "name": "Eazfuscator.NET",
            "type": "Commercial VM Protector",
            "signatures": [b"Eazfuscator.NET", b"Eazfuscator"],
            "description": "Proprietary bytecode virtualization and dynamic symbol scrambling",
        },
        {
            "name": "Babel Obfuscator",
            "type": "Enterprise Protector",
            "signatures": [b"BabelObfuscator", b"BabelAttribute"],
            "description": "Cross-assembly dead code injection and string table encryption",
        },
        {
            "name": "ArmDot",
            "type": "VM-Based Protector",
            "signatures": [b"ArmDot", b"ArmDotAttribute"],
            "description": "Method-level virtual machine execution compiler",
        },
        {
            "name": "DeepSea",
            "type": "Commercial Obfuscator",
            "signatures": [b"DeepSeaObfuscator", b"DS_Attribute"],
            "description": "High-level flow transformation and resource obfuscation",
        },
        {
            "name": "IntelliLock",
            "type": "License Management Envelope",
            "signatures": [
                b"IntelliLock",
                b"TrialAttribute",
                b"IntelliLock.Licensing",
                b"EvaluationMode",
                b"LockType",
            ],
            "description": "Hardware locking envelope protector with expiration enforcement",
        },
        {
            "name": "Costura",
            "type": "Embedded Assembly Packer",
            "signatures": [
                b"costura.",
                b"costura32.",
                b"costura64.",
                b"Costura",
                b"costura.costura.",
                b".dll.compressed",
            ],
            "description": "Fody-based embedded assembly packaging with DeflateStream resource compression",
        },
    ]

    @classmethod
    def identify(cls, data: bytes) -> List[Dict[str, any]]:
        """Scans buffer and returns detected protector candidates."""
        detected = []
        for rule in cls.RULES:
            matched_sigs = [sig for sig in rule["signatures"] if sig in data]
            if matched_sigs:
                detected.append({
                    "protector": rule["name"],
                    "type": rule["type"],
                    "confidence": "HIGH" if len(matched_sigs) > 1 else "MEDIUM",
                    "matched_tokens": [s.decode("latin1", errors="ignore") for s in matched_sigs],
                    "description": rule["description"],
                })
        return detected
