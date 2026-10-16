"""
Native AOT (.NET 7/8/9) Symbol & Runtime Metadata Parser.
Extracts Redhawk (Rhp*) runtime helpers, reflection symbols, and demangles AOT method signatures.
Engineered & Audited by Maya Thorne.
"""

import re
import struct
from typing import Any, Dict, List, Optional, Set, Tuple

from .models import (
    AOTVersion,
    NativeSymbol,
    SecurityError,
    TargetArchitecture,
)


class AOTSymbolParser:
    """Parses Native AOT PE metadata, Redhawk runtime helpers, and symbol tables."""

    # Characteristic Redhawk runtime helper names
    REDHAWK_HELPERS: List[str] = [
        "RhpReversePInvoke",
        "RhpReversePInvoke2",
        "RhpPInvoke",
        "RhpPInvokeSetupForInstrumentation",
        "RhpNewFast",
        "RhpNewArray",
        "RhpAllocate",
        "RhpAssignRef",
        "RhpAssignRefEAX",
        "RhpCheckedAssignRef",
        "RhpByRefAssignRef",
        "RhpTypeCast",
        "RhpCheckCast",
        "RhpIsInstanceOf",
        "RhpThrowEx",
        "RhpRethrow",
        "RhpInitialDynamicInterfaceDispatch",
        "RhpUniversalTransition",
        "RhpCallCatchFunclet",
        "RhGetRuntimeVersion",
        "RhInitialize",
        "RhSetThreadDoNotTriggerGC",
    ]

    # Characteristic Native AOT section names
    AOT_SECTIONS: Set[str] = {
        ".managed",
        ".managedcode",
        ".modules",
        ".hydrated",
        ".rhdata",
        ".dotnet",
        ".corclr",
        ".aotdata",
    }

    MAX_SYMBOLS = 32768

    @classmethod
    def scan_for_helpers(cls, data: bytes) -> List[str]:
        """Scans binary byte buffer for presence of Redhawk (Rhp*) runtime helper string identifiers."""
        detected: List[str] = []
        for helper in cls.REDHAWK_HELPERS:
            b_helper = helper.encode("ascii")
            if b_helper in data:
                detected.append(helper)
        return detected

    @classmethod
    def infer_aot_version(
        cls,
        data: bytes,
        detected_helpers: List[str],
        compiler_id: Optional[str] = None,
        sections: Optional[List[str]] = None,
    ) -> AOTVersion:
        """Infers the .NET Native AOT generation (.NET 7, .NET 8, .NET 9) based on runtime markers."""
        # 1. Check compiler identifier if available
        if compiler_id:
            c_lower = compiler_id.lower()
            if "9." in c_lower or "net 9" in c_lower:
                return AOTVersion.DOTNET_9
            if "8." in c_lower or "net 8" in c_lower:
                return AOTVersion.DOTNET_8
            if "7." in c_lower or "net 7" in c_lower:
                return AOTVersion.DOTNET_7

        # 2. Check for explicit version strings embedded in Redhawk metadata
        if b"Microsoft.NETCore.App/9." in data or b"CoreCLR 9." in data or b"NativeAOT 9." in data:
            return AOTVersion.DOTNET_9
        if b"Microsoft.NETCore.App/8." in data or b"CoreCLR 8." in data or b"NativeAOT 8." in data:
            return AOTVersion.DOTNET_8
        if b"Microsoft.NETCore.App/7." in data or b"CoreCLR 7." in data or b"NativeAOT 7." in data:
            return AOTVersion.DOTNET_7

        # 3. Structural section and helper heuristics
        sec_names = set(sections or [])
        if ".dotnet" in sec_names or "RhpInitialDynamicInterfaceDispatch" in detected_helpers:
            if b"FrozenSegment" in data or b"UnmanagedCallersOnly" in data:
                return AOTVersion.DOTNET_8
            return AOTVersion.DOTNET_9

        if len(detected_helpers) >= 2 or any(s in sec_names for s in cls.AOT_SECTIONS):
            return AOTVersion.DOTNET_8

        return AOTVersion.UNKNOWN

    @classmethod
    def demangle_symbol_name(cls, raw_name: str) -> str:
        """
        Demangles Native AOT C-style symbols into clean .NET names.
        Examples:
          'System_Private_CoreLib_System_Console_WriteLine' -> 'System.Console.WriteLine'
          'Program_Main' -> 'Program.Main'
          'MyNamespace_MyClass__ctor' -> 'MyNamespace.MyClass..ctor'
        """
        if not raw_name:
            return ""

        # Remove known prefixes
        name = raw_name
        for prefix in ["__managed_", "__native_", "Rhp_", "Rh_"]:
            if name.startswith(prefix):
                name = name[len(prefix):]

        # Handle constructor
        name = name.replace("__ctor", "..ctor")

        # Convert underscores between camel/pascal case tokens into dots
        # E.g. System_Private_CoreLib -> strip common library prefix if present
        if name.startswith("System_Private_CoreLib_"):
            name = name[len("System_Private_CoreLib_"):]

        # Transform identifiers: split on single underscores, leave double underscores
        parts = re.split(r"(?<!_)_(?!_)", name)
        clean_name = ".".join(parts)
        return clean_name

    @classmethod
    def parse_pe_exports(
        cls,
        data: bytes,
        export_rva: int,
        export_size: int,
        sec_rva_map: List[Tuple[int, int, int, int]],
    ) -> List[NativeSymbol]:
        """
        Parses PE IMAGE_EXPORT_DIRECTORY to extract exported native symbols (e.g. UnmanagedCallersOnly methods).
        """
        symbols: List[NativeSymbol] = []
        if export_rva <= 0 or export_size < 40:
            return symbols

        def _rva_to_offset(rva: int) -> Optional[int]:
            if rva <= 0:
                return None
            for v_addr, v_size, raw_ptr, raw_size in sec_rva_map:
                span = max(v_size, raw_size)
                if v_addr <= rva < v_addr + span:
                    delta = rva - v_addr
                    if delta < raw_size:
                        return raw_ptr + delta
            return None

        exp_offset = _rva_to_offset(export_rva)
        if exp_offset is None or exp_offset + 40 > len(data):
            return symbols

        # IMAGE_EXPORT_DIRECTORY:
        # Characteristics: uint32 (0)
        # TimeDateStamp: uint32 (4)
        # MajorVersion: uint16 (8)
        # MinorVersion: uint16 (10)
        # Name: uint32 (12)
        # Base: uint32 (16)
        # NumberOfFunctions: uint32 (20)
        # NumberOfNames: uint32 (24)
        # AddressOfFunctions: uint32 (28)
        # AddressOfNames: uint32 (32)
        # AddressOfNameOrdinals: uint32 (36)
        num_funcs = struct.unpack_from("<I", data, exp_offset + 20)[0]
        num_names = struct.unpack_from("<I", data, exp_offset + 24)[0]
        addr_funcs_rva = struct.unpack_from("<I", data, exp_offset + 28)[0]
        addr_names_rva = struct.unpack_from("<I", data, exp_offset + 32)[0]
        addr_ordinals_rva = struct.unpack_from("<I", data, exp_offset + 36)[0]

        funcs_off = _rva_to_offset(addr_funcs_rva)
        names_off = _rva_to_offset(addr_names_rva)
        ords_off = _rva_to_offset(addr_ordinals_rva)

        if not (funcs_off and names_off and ords_off):
            return symbols

        count = min(num_names, cls.MAX_SYMBOLS)
        for i in range(count):
            name_ptr_off = names_off + (i * 4)
            ord_ptr_off = ords_off + (i * 2)
            if name_ptr_off + 4 > len(data) or ord_ptr_off + 2 > len(data):
                break

            name_rva = struct.unpack_from("<I", data, name_ptr_off)[0]
            ordinal = struct.unpack_from("<H", data, ord_ptr_off)[0]

            name_raw = _rva_to_offset(name_rva)
            if not name_raw or name_raw >= len(data):
                continue

            null_pos = data.find(b"\x00", name_raw, min(name_raw + 256, len(data)))
            raw_str = (
                data[name_raw:null_pos].decode("ascii", errors="replace")
                if null_pos != -1
                else ""
            )

            func_ptr_off = funcs_off + (ordinal * 4)
            func_rva = 0
            if func_ptr_off + 4 <= len(data):
                func_rva = struct.unpack_from("<I", data, func_ptr_off)[0]

            is_helper = raw_str.startswith("Rhp") or raw_str.startswith("Rh")
            demangled = cls.demangle_symbol_name(raw_str)

            symbols.append(
                NativeSymbol(
                    token=None,
                    name=raw_str,
                    demangled_name=demangled,
                    rva=func_rva,
                    size_bytes=0,
                    symbol_type="runtime_helper" if is_helper else "unmanaged_caller_export",
                    is_runtime_helper=is_helper,
                )
            )

        return symbols

    @classmethod
    def scan_embedded_reflection_symbols(
        cls,
        data: bytes,
        sec_rva_map: List[Tuple[int, int, int, int]],
    ) -> List[NativeSymbol]:
        """
        Scans binary for embedded reflection type and method descriptor tokens.
        Identifies identifiers formatted like 'Namespace_Class_Method' or 'Type__Method'.
        """
        symbols: List[NativeSymbol] = []
        # Pattern for typical AOT symbol tokens: letters/digits with underscores and colons
        pattern = re.compile(rb"([A-Za-z0-9_]{3,32}_[A-Za-z0-9_]{3,32})")
        seen_names: Set[str] = set()

        for v_addr, v_size, raw_ptr, raw_size in sec_rva_map:
            sec_end = min(raw_ptr + raw_size, len(data))
            if raw_ptr >= sec_end:
                continue
            chunk = data[raw_ptr:sec_end]
            for match in pattern.finditer(chunk):
                raw_str = match.group(1).decode("ascii", errors="ignore")
                if raw_str in seen_names or len(raw_str) < 6:
                    continue
                # Exclude purely standard C runtime strings
                if raw_str.startswith("__") or raw_str.endswith("_std"):
                    continue
                seen_names.add(raw_str)
                rel_offset = match.start()
                rva = v_addr + rel_offset

                is_helper = raw_str.startswith("Rhp") or raw_str.startswith("Rh")
                demangled = cls.demangle_symbol_name(raw_str)
                symbols.append(
                    NativeSymbol(
                        token=None,
                        name=raw_str,
                        demangled_name=demangled,
                        rva=rva,
                        size_bytes=0,
                        symbol_type="runtime_helper" if is_helper else "reflection_symbol",
                        is_runtime_helper=is_helper,
                    )
                )
                if len(symbols) >= cls.MAX_SYMBOLS:
                    break
            if len(symbols) >= cls.MAX_SYMBOLS:
                break

        return symbols
