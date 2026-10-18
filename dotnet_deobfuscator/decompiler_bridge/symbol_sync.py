"""
Forensic Symbol & Annotation Synchronizer.
Engineered & Audited by Maya Thorne.
"""

import struct
from typing import Any, Dict, List, Optional, Set, Tuple
from .models import (
    CommentType,
    DecompilerBookmark,
    DecompilerComment,
    DecompilerBridgeOptions,
    DecompilerSymbol,
    SymbolType,
)


class SymbolSynchronizer:
    """Correlates and synchronizes forensic findings into unified decompiler annotations."""

    _TYPE_PRIORITY = {
        SymbolType.ENTRY_POINT: 100, SymbolType.RUNTIME_HELPER: 90,
        SymbolType.VM_DISPATCHER: 80, SymbolType.DECRYPTOR: 70,
        SymbolType.NATIVE_TRANSITION: 60, SymbolType.FUNCTION: 50,
        SymbolType.METADATA_TOKEN: 30, SymbolType.ANOMALY_BLOCK: 10,
    }

    @classmethod
    def synchronize(
        cls, data: bytes, options: Optional[DecompilerBridgeOptions] = None,
        forensic_context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[DecompilerSymbol], List[DecompilerComment], List[DecompilerBookmark]]:
        """Extracts and synchronizes symbols, comments, and bookmarks across all subsystems."""
        opts = options or DecompilerBridgeOptions()
        ctx = forensic_context or {}
        raw_symbols: List[DecompilerSymbol] = []
        raw_comments: List[DecompilerComment] = []
        raw_bookmarks: List[DecompilerBookmark] = []

        cls._sync_pe_structures(data, ctx, raw_symbols, raw_comments, raw_bookmarks)
        cls._sync_cor20_structures(data, ctx, raw_symbols, raw_comments, raw_bookmarks)
        cls._sync_protector_artifacts(data, ctx, raw_symbols, raw_comments, raw_bookmarks)
        if opts.include_vtfixups:
            cls._sync_mixed_mode(data, ctx, raw_symbols, raw_comments, raw_bookmarks)
        if opts.include_runtime_helpers:
            cls._sync_native_aot(data, ctx, raw_symbols, raw_comments, raw_bookmarks)
        cls._sync_carved_methods(data, ctx, raw_symbols, raw_comments, raw_bookmarks)
        if opts.include_entropy_anomalies:
            cls._sync_cfg_anomalies(data, ctx, raw_symbols, raw_comments, raw_bookmarks)

        symbols = cls._deduplicate_symbols(raw_symbols, opts.min_confidence)
        comments = cls._deduplicate_comments(raw_comments)
        bookmarks = cls._deduplicate_bookmarks(raw_bookmarks)
        return symbols, comments, bookmarks

    @classmethod
    def _sync_pe_structures(
        cls, data: bytes, ctx: Dict[str, Any],
        symbols: List[DecompilerSymbol], comments: List[DecompilerComment],
        bookmarks: List[DecompilerBookmark],
    ) -> None:
        try:
            entry = (ctx.get("assembly_info") or {}).get("entry_point", 0)
            if not entry and len(data) >= 64 and data[:2] == b"MZ":
                e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
                if e_lfanew + 44 <= len(data) and data[e_lfanew:e_lfanew+4] == b"PE\x00\x00":
                    entry = struct.unpack_from("<I", data, e_lfanew + 40)[0]
            if entry > 0:
                symbols.append(DecompilerSymbol(
                    name="PE_EntryPoint", rva=entry, symbol_type=SymbolType.ENTRY_POINT,
                    is_function=True, confidence=1.0, tags=["pe", "entry"],
                ))
                comments.append(DecompilerComment(rva=entry, text=f"PE Native EntryPoint (RVA: 0x{entry:X})"))
                bookmarks.append(DecompilerBookmark(rva=entry, category="Entry Point", comment=f"PE EntryPoint @ 0x{entry:X}"))
            from ..dotnet_analyzer import DotNetAnalyzer
            asm = ctx.get("assembly_info") or DotNetAnalyzer.inspect_assembly(data)
            for s in asm.get("sections", []):
                vaddr = s.get("virtual_address", 0)
                if isinstance(vaddr, str):
                    try:
                        vaddr = int(vaddr, 0)
                    except ValueError:
                        vaddr = 0
                sname = s.get("name", "").strip().strip("\x00")
                if vaddr > 0 and sname:
                    symbols.append(DecompilerSymbol(
                        name=f"SECTION_{sname.replace('.', '')}", rva=vaddr,
                        size=s.get("raw_size", 0), symbol_type=SymbolType.METADATA_TOKEN,
                        is_function=False, confidence=0.85, tags=["pe", "section"],
                    ))
                    comments.append(DecompilerComment(
                        rva=vaddr, text=f"Section [{sname}] (Raw: {s.get('raw_size', 0):,}b, H: {s.get('entropy', 0.0)})",
                    ))
        except Exception:
            pass

    @classmethod
    def _sync_cor20_structures(
        cls, data: bytes, ctx: Dict[str, Any],
        symbols: List[DecompilerSymbol], comments: List[DecompilerComment],
        bookmarks: List[DecompilerBookmark],
    ) -> None:
        try:
            if len(data) < 64 or data[:2] != b"MZ":
                return
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            if e_lfanew + 28 > len(data) or data[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
                return
            opt_hdr = e_lfanew + 24
            magic = struct.unpack_from("<H", data, opt_hdr)[0]
            dd_offset = opt_hdr + (96 if magic == 0x10B else 112)
            cor20_dd = dd_offset + (14 * 8)
            if cor20_dd + 8 <= len(data):
                cor20_rva, cor20_sz = struct.unpack_from("<II", data, cor20_dd)
                if cor20_rva > 0:
                    symbols.append(DecompilerSymbol(
                        name="IMAGE_COR20_HEADER", rva=cor20_rva, size=cor20_sz,
                        symbol_type=SymbolType.METADATA_TOKEN, is_function=False,
                        confidence=1.0, tags=["clr", "cor20"],
                    ))
                    comments.append(DecompilerComment(rva=cor20_rva, text=f"CLR Cor20Header (RVA: 0x{cor20_rva:X}, Size: {cor20_sz}b)"))
                    bookmarks.append(DecompilerBookmark(rva=cor20_rva, category="CLR", comment="Cor20Header Descriptor"))
        except Exception:
            pass

    @classmethod
    def _sync_protector_artifacts(
        cls, data: bytes, ctx: Dict[str, Any],
        symbols: List[DecompilerSymbol], comments: List[DecompilerComment],
        bookmarks: List[DecompilerBookmark],
    ) -> None:
        try:
            from ..unpackers.reactor import DotNetReactorUnpacker
            methods = ctx.get("reactor_methods") or DotNetReactorUnpacker.extract_necrobit_methods(data)
            for tok, m in methods.items():
                if m.get("rva"):
                    symbols.append(DecompilerSymbol(
                        name=f"NecroBit_Method_{tok:08X}", rva=m["rva"], size=m.get("code_size", 0),
                        symbol_type=SymbolType.DECRYPTOR, token=tok, confidence=0.95, tags=["reactor", "necrobit"],
                    ))
                    comments.append(DecompilerComment(
                        rva=m["rva"], text=f"NecroBit Method (Token: 0x{tok:08X}, Size: {m.get('code_size', 0)}b)",
                    ))
        except Exception:
            pass

        try:
            from ..unpackers.eazfuscator import EazfuscatorUnpacker
            for i, c in enumerate(ctx.get("eaz_containers") or EazfuscatorUnpacker.extract_vm_containers(data)):
                if c.get("rva"):
                    symbols.append(DecompilerSymbol(
                        name=f"Eazfuscator_VMContainer_{i+1}", rva=c["rva"],
                        symbol_type=SymbolType.VM_DISPATCHER, confidence=0.95, tags=["eazfuscator", "vm"],
                    ))
                    bookmarks.append(DecompilerBookmark(rva=c["rva"], category="VM", comment="Eazfuscator VM"))
        except Exception:
            pass

        try:
            from ..unpackers.armdot import ArmDotUnpacker
            for i, c in enumerate(ctx.get("armdot_containers") or ArmDotUnpacker.extract_vm_containers(data)):
                if c.get("rva"):
                    symbols.append(DecompilerSymbol(
                        name=f"ArmDot_VMDispatcher_{i+1}", rva=c["rva"],
                        symbol_type=SymbolType.VM_DISPATCHER, confidence=0.95, tags=["armdot", "vm"],
                    ))
                    bookmarks.append(DecompilerBookmark(rva=c["rva"], category="VM", comment="ArmDot VM"))
        except Exception:
            pass

        try:
            from ..unpackers.babel import BabelUnpacker
            for m in ctx.get("babel_merged") or BabelUnpacker.extract_merged_assemblies(data):
                rva = m.get("rva") or m.get("offset")
                if rva:
                    symbols.append(DecompilerSymbol(
                        name=f"Babel_Satellite_{m.get('name', 'asm')}", rva=rva,
                        symbol_type=SymbolType.FUNCTION, confidence=0.9, tags=["babel"],
                    ))
        except Exception:
            pass

    @classmethod
    def _sync_mixed_mode(
        cls, data: bytes, ctx: Dict[str, Any],
        symbols: List[DecompilerSymbol], comments: List[DecompilerComment],
        bookmarks: List[DecompilerBookmark],
    ) -> None:
        try:
            from ..mixed_mode import MixedModeAnalyzer
            mm = ctx.get("mixed_mode_res") or MixedModeAnalyzer.analyze(data)
            for slot in mm.vtfixup_slots:
                symbols.append(DecompilerSymbol(
                    name=f"VTFixup_Slot_{slot.slot_index}", rva=slot.slot_rva,
                    symbol_type=SymbolType.NATIVE_TRANSITION, token=slot.token,
                    confidence=0.95, tags=["mixed_mode", "vtfixup"],
                ))
                comments.append(DecompilerComment(
                    rva=slot.slot_rva, text=f"VTFixup Slot #{slot.slot_index} -> 0x{slot.token:08X}",
                    comment_type=CommentType.EOL,
                ))
            for cb in mm.tls_callbacks:
                symbols.append(DecompilerSymbol(
                    name=f"TLS_Callback_{cb.callback_index}", rva=cb.callback_rva,
                    symbol_type=SymbolType.NATIVE_TRANSITION, is_function=True, confidence=1.0, tags=["mixed_mode", "tls"],
                ))
                bookmarks.append(DecompilerBookmark(rva=cb.callback_rva, category="TLS", comment=f"TLS Callback #{cb.callback_index}"))
        except Exception:
            pass

    @classmethod
    def _sync_native_aot(
        cls, data: bytes, ctx: Dict[str, Any],
        symbols: List[DecompilerSymbol], comments: List[DecompilerComment],
        bookmarks: List[DecompilerBookmark],
    ) -> None:
        try:
            from ..native_aot import NativeAOTAnalyzer
            aot = ctx.get("native_aot_res") or NativeAOTAnalyzer.analyze(data)
            for s in aot.symbols:
                is_hlp = s.symbol_type.value == "rhp_helper" or "Rhp" in s.demangled_name
                stype = SymbolType.RUNTIME_HELPER if is_hlp else SymbolType.FUNCTION
                symbols.append(DecompilerSymbol(
                    name=s.demangled_name, rva=s.rva, size=s.size, symbol_type=stype,
                    is_function=True, token=s.token, confidence=0.95,
                    tags=["native_aot"] + (["rhp_helper"] if is_hlp else []), demangled_name=s.demangled_name,
                ))
                comments.append(DecompilerComment(rva=s.rva, text=f"Native AOT: {s.demangled_name} ({s.symbol_type.value})"))
                if is_hlp:
                    bookmarks.append(DecompilerBookmark(rva=s.rva, category="Runtime Helper", comment=s.demangled_name))
        except Exception:
            pass

    @classmethod
    def _sync_carved_methods(
        cls, data: bytes, ctx: Dict[str, Any],
        symbols: List[DecompilerSymbol], comments: List[DecompilerComment],
        bookmarks: List[DecompilerBookmark],
    ) -> None:
        try:
            from ..dump_carver import KernelDumpCarver
            dc = ctx.get("dump_carver_res") or KernelDumpCarver.analyze(data)
            for m in dc.residual_methods:
                symbols.append(DecompilerSymbol(
                    name=f"CarvedMethod_{m.token:08X}", rva=m.offset, size=m.code_size,
                    symbol_type=SymbolType.FUNCTION, is_function=True, token=m.token,
                    confidence=m.confidence, tags=["dump_carver", m.format],
                ))
                comments.append(DecompilerComment(rva=m.offset, text=f"Carved Method (0x{m.token:08X}, {m.format}, H: {m.entropy})"))
        except Exception:
            pass

    @classmethod
    def _sync_cfg_anomalies(
        cls, data: bytes, ctx: Dict[str, Any],
        symbols: List[DecompilerSymbol], comments: List[DecompilerComment],
        bookmarks: List[DecompilerBookmark],
    ) -> None:
        try:
            from ..cfg import CFGAnalyzer
            cfg = ctx.get("cfg_res") or CFGAnalyzer.analyze(data)
            for b in getattr(cfg, "high_entropy_blocks", []):
                rva = getattr(b, "start_rva", None) or getattr(b, "offset", None)
                if rva:
                    ent = getattr(b, "entropy", 0.0)
                    symbols.append(DecompilerSymbol(
                        name=f"Entropy_Anomaly_{rva:08X}", rva=rva,
                        symbol_type=SymbolType.ANOMALY_BLOCK, is_function=False,
                        confidence=0.75, tags=["cfg", "anomaly", "high_entropy"],
                    ))
                    comments.append(DecompilerComment(rva=rva, text=f"High-Entropy Block (Entropy: {ent:.2f})"))
                    bookmarks.append(DecompilerBookmark(rva=rva, category="Anomaly", comment=f"High-Entropy Block @ 0x{rva:X}"))
        except Exception:
            pass

    @classmethod
    def _deduplicate_symbols(cls, raw: List[DecompilerSymbol], min_confidence: float = 0.5) -> List[DecompilerSymbol]:
        """Resolves colliding RVAs and returns filtered, sorted symbol list."""
        by_rva: Dict[int, DecompilerSymbol] = {}
        for s in [x for x in raw if x.confidence >= min_confidence]:
            if s.rva not in by_rva:
                by_rva[s.rva] = s
            else:
                cur = by_rva[s.rva]
                p_new = cls._TYPE_PRIORITY.get(s.symbol_type, 0)
                p_old = cls._TYPE_PRIORITY.get(cur.symbol_type, 0)
                if p_new > p_old or (p_new == p_old and s.confidence > cur.confidence):
                    s.tags = list(dict.fromkeys(cur.tags + s.tags))
                    if not s.token and cur.token:
                        s.token = cur.token
                    by_rva[s.rva] = s
                else:
                    cur.tags = list(dict.fromkeys(cur.tags + s.tags))
                    if not cur.token and s.token:
                        cur.token = s.token
        return sorted(by_rva.values(), key=lambda x: x.rva)

    @classmethod
    def _deduplicate_comments(cls, raw: List[DecompilerComment]) -> List[DecompilerComment]:
        """Combines multiple comments at the same RVA."""
        by_rva: Dict[int, List[DecompilerComment]] = {}
        for c in raw:
            by_rva.setdefault(c.rva, []).append(c)
        combined = [
            g[0] if len(g) == 1 else DecompilerComment(
                rva=rva, text="\n---\n".join(x.text for x in g),
                comment_type=g[0].comment_type, is_repeatable=any(x.is_repeatable for x in g)
            )
            for rva, g in by_rva.items()
        ]
        return sorted(combined, key=lambda x: x.rva)

    @classmethod
    def _deduplicate_bookmarks(cls, raw: List[DecompilerBookmark]) -> List[DecompilerBookmark]:
        """Deduplicates bookmarks targeting identical RVAs."""
        seen: Set[int] = set()
        deduped = [b for b in raw if not (b.rva in seen or seen.add(b.rva))]
        return sorted(deduped, key=lambda x: x.rva)
