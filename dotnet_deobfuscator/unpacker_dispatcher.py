"""
Unpacker Dispatcher & Embedded Payload Extraction Manager.
Engineered & Audited by Maya Thorne.
"""

from typing import Any, Dict, List, Optional
import os

from .pe_overlay import PEOverlayParser
from .unpackers.antidump import AntiDumpUnpacker
from .unpackers.antitamper import AntiTamperUnpacker
from .unpackers.armdot import ArmDotUnpacker
from .unpackers.babel import BabelUnpacker
from .unpackers.confuserex import ConfuserExUnpacker
from .unpackers.costura import CosturaUnpacker
from .unpackers.deepsea import DeepSeaUnpacker
from .unpackers.eazfuscator import EazfuscatorUnpacker
from .unpackers.reactor import DotNetReactorUnpacker


def unpack_payload_to_file(
    data: bytes, output_path: str, master_key: str = "randomkey"
) -> bool:
    """Extracts and writes decrypted payload to disk across all supported protector types."""
    xor_result = PEOverlayParser.decrypt_xor_packer(data, master_key=master_key)
    if xor_result:
        with open(output_path, "wb") as f:
            f.write(xor_result["decrypted_payload_bytes"])
        return True

    # Check if single Costura payload exists
    costura_payloads = CosturaUnpacker.unpack(data)
    if len(costura_payloads) == 1:
        with open(output_path, "wb") as f:
            f.write(costura_payloads[0]["payload_bytes"])
        return True

    # Check if single ConfuserEx payload exists
    confuser_payloads = ConfuserExUnpacker.unpack(data)
    if len(confuser_payloads) == 1:
        with open(output_path, "wb") as f:
            f.write(confuser_payloads[0]["payload_bytes"])
        return True

    # Check if single .NET Reactor payload exists
    reactor_payloads = DotNetReactorUnpacker.unpack(data)
    if len(reactor_payloads) == 1:
        with open(output_path, "wb") as f:
            f.write(reactor_payloads[0]["payload_bytes"])
        return True

    # Check if Eazfuscator VM containers exist
    eaz_containers = EazfuscatorUnpacker.extract_vm_containers(data)
    if eaz_containers:
        rebuilt_pe, rep = EazfuscatorUnpacker.devirtualize_assembly(data)
        if rep.get("success") or rep.get("methods_devirtualized_count", 0) > 0:
            with open(output_path, "wb") as f:
                f.write(rebuilt_pe)
            return True

    # Check if single Babel merged assembly exists
    babel_merged = BabelUnpacker.extract_merged_assemblies(data)
    if len(babel_merged) == 1:
        with open(output_path, "wb") as f:
            f.write(babel_merged[0]["payload_bytes"])
        return True

    # Check if ArmDot VM containers exist
    armdot_containers = ArmDotUnpacker.extract_vm_containers(data)
    if armdot_containers:
        rebuilt_pe, rep = ArmDotUnpacker.devirtualize_assembly(data)
        if rep.get("success") or rep.get("methods_devirtualized_count", 0) > 0:
            with open(output_path, "wb") as f:
                f.write(rebuilt_pe)
            return True

    # Check if DeepSea flattened methods exist
    deepsea_detect = DeepSeaUnpacker.detect(data)
    if deepsea_detect["is_deepsea"]:
        rebuilt_pe, rep = DeepSeaUnpacker.deflatten_assembly(data)
        with open(output_path, "wb") as f:
            f.write(rebuilt_pe)
        return True

    # Check if AntiDump memory dump needs healing
    antidump_detect = AntiDumpUnpacker.detect(data)
    if antidump_detect["is_anti_dump"]:
        healed_pe, rep = AntiDumpUnpacker.heal_dump(data)
        if rep.get("is_healed"):
            with open(output_path, "wb") as f:
                f.write(healed_pe)
            return True

    return False


def unpack_all_to_dir(data: bytes, output_dir: str) -> List[Dict[str, Any]]:
    """Extracts all embedded Costura, ConfuserEx, .NET Reactor, Eazfuscator, Babel, ArmDot, DeepSea, AntiTamper, and AntiDump assemblies into directory."""
    written: List[Dict[str, Any]] = []
    written.extend(CosturaUnpacker.unpack_to_directory(data, output_dir))
    written.extend(ConfuserExUnpacker.unpack_to_directory(data, output_dir))
    written.extend(DotNetReactorUnpacker.unpack_to_directory(data, output_dir))
    written.extend(EazfuscatorUnpacker.unpack_to_directory(data, output_dir))
    written.extend(BabelUnpacker.unpack_to_directory(data, output_dir))
    written.extend(ArmDotUnpacker.unpack_to_directory(data, output_dir))
    if DeepSeaUnpacker.detect(data)["is_deepsea"]:
        DeepSeaUnpacker.unpack_to_directory(data, output_dir)
    if AntiTamperUnpacker.detect(data)["is_tampered"]:
        AntiTamperUnpacker.unpack_to_directory(data, output_dir)
    if AntiDumpUnpacker.detect(data)["is_anti_dump"]:
        AntiDumpUnpacker.unpack_to_directory(data, output_dir)
    return written
