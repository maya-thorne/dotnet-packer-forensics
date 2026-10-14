"""
CIL & Native Execution Boundary Transition Tracer.
Traces call thunks, unmanaged exports, TLS callbacks, and native entry points.
Engineered & Audited by Maya Thorne.
"""

import struct
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    CILNativeTransition,
    TLSCallbackInfo,
    TransitionDirection,
    TransitionType,
    UnmanagedExportBridge,
    VTFixupTable,
)


class TransitionTracer:
    """Traces execution flow transitions across managed CIL and native machine code boundaries."""

    @staticmethod
    def _rva_to_offset(rva: int, sec_rva_map: List[Tuple[int, int, int, int]]) -> Optional[int]:
        """Translates Relative Virtual Address (RVA) to raw file offset."""
        if rva <= 0:
            return None
        for v_addr, v_size, raw_ptr, raw_size in sec_rva_map:
            span = max(v_size, raw_size)
            if v_addr <= rva < v_addr + span:
                delta = rva - v_addr
                if delta < raw_size:
                    return raw_ptr + delta
        return None

    @staticmethod
    def _find_section_for_rva(rva: int, sections: List[Dict[str, Any]]) -> str:
        """Finds section name containing specified RVA."""
        for s in sections:
            vaddr = int(s.get("virtual_address", "0x0"), 16) if isinstance(s.get("virtual_address"), str) else s.get("virtual_address", 0)
            vsize = s.get("virtual_size", 0)
            rsize = s.get("raw_size", 0)
            span = max(vsize, rsize)
            if vaddr <= rva < vaddr + span:
                return s.get("name", "UNKNOWN")
        return "UNKNOWN_SECTION"

    @classmethod
    def trace_transitions(
        cls,
        data: bytes,
        cor20_info: Dict[str, Any],
        vtfixup_tables: List[VTFixupTable],
        sec_rva_map: List[Tuple[int, int, int, int]],
        pe_info: Dict[str, Any],
        sections: List[Dict[str, Any]],
    ) -> Tuple[List[CILNativeTransition], List[UnmanagedExportBridge], List[TLSCallbackInfo]]:
        """
        Extracts all CIL <-> Native transitions:
        1. Native Entrypoint Transition
        2. Native TLS Callbacks
        3. Unmanaged Export Thunks
        4. VTableFixup Native-to-Managed Call Thunks
        5. Managed-to-Native P/Invoke & Calli Markers
        """
        transitions: List[CILNativeTransition] = []
        export_bridges: List[UnmanagedExportBridge] = []
        tls_callbacks: List[TLSCallbackInfo] = []

        # 1. Native Entrypoint Transition
        if cor20_info.get("has_native_entrypoint"):
            entry_rva = cor20_info.get("native_entrypoint_rva") or pe_info.get("entry_point_rva", 0)
            sec_name = cls._find_section_for_rva(entry_rva, sections)
            transitions.append(
                CILNativeTransition(
                    transition_id="TR-NATIVE-EP",
                    direction=TransitionDirection.NATIVE_TO_MANAGED,
                    transition_type=TransitionType.NATIVE_ENTRYPOINT,
                    source_location=f"Native EntryPoint RVA 0x{entry_rva:08X} ({sec_name})",
                    target_location="Managed CLR Initialization Stub / CRT Bootstrap",
                    description="PE executes native bootstrap prior to CLR runtime initialization (C++/CLI startup pattern)",
                    is_suspicious=False,
                    risk_factor="Normal C++/CLI startup, but permits early native code execution before managed inspection",
                )
            )

        # 2. Native TLS Callbacks
        tls_rva = pe_info.get("tls_rva", 0)
        tls_size = pe_info.get("tls_size", 0)
        image_base = pe_info.get("image_base", 0x400000)
        is_pe32_plus = pe_info.get("is_pe32_plus", False)

        if tls_rva > 0 and tls_size >= (24 if not is_pe32_plus else 40):
            tls_off = cls._rva_to_offset(tls_rva, sec_rva_map)
            if tls_off is not None and tls_off + 24 <= len(data):
                cb_array_va = 0
                if not is_pe32_plus and tls_off + 16 <= len(data):
                    # AddressOfCallBacks is at offset 12 in IMAGE_TLS_DIRECTORY32
                    cb_array_va = struct.unpack_from("<I", data, tls_off + 12)[0]
                elif is_pe32_plus and tls_off + 32 <= len(data):
                    # AddressOfCallBacks is at offset 24 in IMAGE_TLS_DIRECTORY64
                    cb_array_va = struct.unpack_from("<Q", data, tls_off + 24)[0]

                if cb_array_va > image_base:
                    cb_array_rva = cb_array_va - image_base
                    cb_array_off = cls._rva_to_offset(cb_array_rva, sec_rva_map)
                    if cb_array_off is not None and cb_array_off < len(data):
                        ptr_size = 8 if is_pe32_plus else 4
                        fmt = "<Q" if is_pe32_plus else "<I"
                        curr_cb_off = cb_array_off
                        cb_idx = 0

                        while curr_cb_off + ptr_size <= len(data) and cb_idx < 64:
                            val = struct.unpack_from(fmt, data, curr_cb_off)[0]
                            if val == 0:
                                break
                            cb_rva = val - image_base if val > image_base else val
                            cb_sec = cls._find_section_for_rva(cb_rva, sections)
                            cb_file_off = cls._rva_to_offset(cb_rva, sec_rva_map)

                            tls_info = TLSCallbackInfo(
                                callback_rva=cb_rva,
                                callback_offset=cb_file_off,
                                section_name=cb_sec,
                                is_in_code_section=(cb_sec.lower() in [".text", ".code", ".native"]),
                            )
                            tls_callbacks.append(tls_info)

                            transitions.append(
                                CILNativeTransition(
                                    transition_id=f"TR-TLS-{cb_idx+1:02d}",
                                    direction=TransitionDirection.INTERNAL_NATIVE,
                                    transition_type=TransitionType.TLS_CALLBACK,
                                    source_location=f"TLS Callback #{cb_idx+1} RVA 0x{cb_rva:08X} ({cb_sec})",
                                    target_location="Native Pre-Runtime Execution Hook",
                                    description="Native TLS callback executes prior to PE entrypoint and CLR engine initialization",
                                    is_suspicious=True,
                                    risk_factor="High-risk evasion vector: native code executes before CLR security controls or monitoring hooks activate",
                                )
                            )
                            curr_cb_off += ptr_size
                            cb_idx += 1

        # 3. Unmanaged Export Bridges
        export_rva = pe_info.get("export_rva", 0)
        export_size = pe_info.get("export_size", 0)

        # Build mapping of VTFixup slot RVAs to tokens for fast O(1) matching
        slot_rva_to_token: Dict[int, Tuple[str, str, int]] = {}
        for tbl in vtfixup_tables:
            for s in tbl.slots:
                slot_rva_to_token[s.slot_rva] = (s.target_token_hex, s.token_type_name, s.flags_int)

        if export_rva > 0 and export_size >= 40:
            exp_off = cls._rva_to_offset(export_rva, sec_rva_map)
            if exp_off is not None and exp_off + 40 <= len(data):
                (
                    _,
                    _,
                    _,
                    _,
                    _,
                    base_ordinal,
                    num_functions,
                    num_names,
                    addr_functions_rva,
                    addr_names_rva,
                    addr_ordinals_rva,
                ) = struct.unpack_from("<IIHHIIIIIII", data, exp_off)

                num_functions = min(num_functions, 1024)
                num_names = min(num_names, 1024)

                funcs_off = cls._rva_to_offset(addr_functions_rva, sec_rva_map)
                names_off = cls._rva_to_offset(addr_names_rva, sec_rva_map)
                ords_off = cls._rva_to_offset(addr_ordinals_rva, sec_rva_map)

                if funcs_off is not None and names_off is not None and ords_off is not None:
                    # Map ordinal index to name
                    ordinal_to_name: Dict[int, str] = {}
                    for i in range(num_names):
                        if names_off + (i * 4) + 4 <= len(data) and ords_off + (i * 2) + 2 <= len(data):
                            name_rva = struct.unpack_from("<I", data, names_off + (i * 4))[0]
                            ord_idx = struct.unpack_from("<H", data, ords_off + (i * 2))[0]
                            n_off = cls._rva_to_offset(name_rva, sec_rva_map)
                            if n_off is not None and n_off < len(data):
                                end_z = data.find(b"\x00", n_off)
                                if end_z != -1:
                                    exp_name = data[n_off:end_z].decode("latin1", errors="ignore")
                                    ordinal_to_name[ord_idx] = exp_name

                    for f_idx in range(num_functions):
                        if funcs_off + (f_idx * 4) + 4 > len(data):
                            break
                        fn_rva = struct.unpack_from("<I", data, funcs_off + (f_idx * 4))[0]
                        if fn_rva == 0:
                            continue

                        fn_ordinal = base_ordinal + f_idx
                        exp_name = ordinal_to_name.get(f_idx, f"Ordinal_{fn_ordinal}")
                        fn_sec = cls._find_section_for_rva(fn_rva, sections)
                        fn_off = cls._rva_to_offset(fn_rva, sec_rva_map)

                        # Check if function matches VTFixup slot
                        is_thunk = False
                        linked_token = None
                        if fn_rva in slot_rva_to_token:
                            is_thunk = True
                            linked_token = slot_rva_to_token[fn_rva][0]
                        else:
                            # Check if function is within any VTFixup table slot range
                            for tbl in vtfixup_tables:
                                width = 8 if tbl.fixup_type.value == "slot_64bit" else 4
                                tbl_end = tbl.table_rva + (tbl.slot_count * width)
                                if tbl.table_rva <= fn_rva < tbl_end:
                                    is_thunk = True
                                    offset_in_tbl = (fn_rva - tbl.table_rva) // width
                                    if offset_in_tbl < len(tbl.slots):
                                        linked_token = tbl.slots[offset_in_tbl].target_token_hex
                                    break

                        bridge = UnmanagedExportBridge(
                            export_name=exp_name,
                            ordinal=fn_ordinal,
                            function_rva=fn_rva,
                            function_offset=fn_off,
                            is_vtfixup_thunk=is_thunk,
                            linked_token_hex=linked_token,
                            section_name=fn_sec,
                        )
                        export_bridges.append(bridge)

                        if is_thunk and linked_token:
                            transitions.append(
                                CILNativeTransition(
                                    transition_id=f"TR-EXP-THUNK-{fn_ordinal}",
                                    direction=TransitionDirection.NATIVE_TO_MANAGED,
                                    transition_type=TransitionType.UNMANAGED_EXPORT,
                                    source_location=f"Unmanaged Export '{exp_name}' (Ord {fn_ordinal}, RVA 0x{fn_rva:08X})",
                                    target_location=f"Managed Method Token {linked_token}",
                                    description=f"Exported C-linkage symbol '{exp_name}' routes unmanaged caller into managed CIL method",
                                    is_suspicious=False,
                                    risk_factor="Permits external unmanaged code / DLL injection to trigger internal CIL method logic",
                                )
                            )

        # 4. VTableFixup Slot Transitions
        for tbl in vtfixup_tables:
            for s in tbl.slots:
                if s.is_from_unmanaged:
                    is_susp = (s.token_type_name == "UnknownToken")
                    transitions.append(
                        CILNativeTransition(
                            transition_id=f"TR-VTF-{tbl.table_index:02d}-{s.slot_index:03d}",
                            direction=TransitionDirection.NATIVE_TO_MANAGED,
                            transition_type=TransitionType.VTFIXUP_THUNK,
                            source_location=f"VTable Slot RVA 0x{s.slot_rva:08X} (Tbl {tbl.table_index})",
                            target_location=f"Managed {s.token_type_name} {s.target_token_hex}",
                            description=f"Unmanaged caller invokes managed {s.token_type_name} {s.target_token_hex} via CLR generated transition thunk",
                            is_suspicious=is_susp,
                            risk_factor="Corrupted or non-standard token in VTFixup slot" if is_susp else "Standard C++/CLI call thunk transition",
                        )
                    )

        # 5. Managed-to-Native P/Invoke & Calli Markers
        if b"kernel32.dll" in data.lower() or b"ntdll.dll" in data.lower():
            # Scan for P/Invoke metadata or native imports
            transitions.append(
                CILNativeTransition(
                    transition_id="TR-PINVOKE-BRIDGE",
                    direction=TransitionDirection.MANAGED_TO_NATIVE,
                    transition_type=TransitionType.PINVOKE_CALL,
                    source_location="Managed CIL P/Invoke Thunk / Native IAT",
                    target_location="Win32 Native API (kernel32 / ntdll)",
                    description="Binary references native Win32 platform libraries alongside CLR metadata",
                    is_suspicious=False,
                    risk_factor="Allows managed CIL or native thunks to invoke low-level OS system primitives directly",
                )
            )

        return transitions, export_bridges, tls_callbacks
