"""
Virtual Volume Mount and In-Memory File System for .NET Single-File Host Bundles.
Engineered & Audited by Maya Thorne.
"""

import hashlib
import os
from typing import Any, Dict, List, Optional, Tuple

from .decompressor import BundleDecompressor
from .models import (
    BundleEntry,
    BundleFileType,
    BundleHeader,
    CompressionKind,
    SecurityError,
    calculate_entropy,
)


class VirtualVolumeNode:
    """Represents a node in the virtual directory tree of the mounted volume."""

    def __init__(self, name: str, is_dir: bool = False, entry: Optional[BundleEntry] = None):
        self.name = name
        self.is_dir = is_dir
        self.entry = entry
        self.children: Dict[str, "VirtualVolumeNode"] = {}

    def add_child(self, path_parts: List[str], entry: BundleEntry) -> None:
        if not path_parts:
            return
        head = path_parts[0]
        tail = path_parts[1:]
        if not tail:
            # Leaf file node
            self.children[head] = VirtualVolumeNode(name=head, is_dir=False, entry=entry)
        else:
            if head not in self.children:
                self.children[head] = VirtualVolumeNode(name=head, is_dir=True)
            self.children[head].add_child(tail, entry)

    def render_tree(self, prefix: str = "", is_last: bool = True) -> List[str]:
        lines: List[str] = []
        if self.name:  # Skip root node's empty name
            connector = "└── " if is_last else "├── "
            if self.is_dir:
                lines.append(f"{prefix}{connector}{self.name}/")
            else:
                sz = f"{self.entry.size:,} B" if self.entry else "0 B"
                ft = self.entry.file_type.value if self.entry else "unknown"
                lines.append(f"{prefix}{connector}{self.name} ({sz}, {ft})")
            prefix += "    " if is_last else "│   "

        items = list(self.children.items())
        for idx, (child_name, child_node) in enumerate(items):
            child_is_last = idx == len(items) - 1
            lines.extend(child_node.render_tree(prefix=prefix, is_last=child_is_last))
        return lines


class VirtualBundleVolume:
    """
    Mounted in-memory virtual filesystem volume exposing the contents of a .NET Single-File Host.
    """

    def __init__(self, header: BundleHeader, binary_data: bytes):
        self.header = header
        self.binary_data = binary_data
        self.entries_by_path: Dict[str, BundleEntry] = {}
        self.root = VirtualVolumeNode(name="", is_dir=True)
        self._mounted = False
        self._cache: Dict[str, bytes] = {}
        self._mount()

    def _normalize_key(self, path: str) -> str:
        return path.replace("\\", "/").strip("/")

    def _mount(self) -> None:
        """Indexes all bundle entries into the virtual filesystem directory tree."""
        for entry in self.header.entries:
            norm = self._normalize_key(entry.relative_path)
            self.entries_by_path[norm] = entry
            parts = norm.split("/")
            self.root.add_child(parts, entry)
        self._mounted = True

    def list_paths(self) -> List[str]:
        """Returns all relative file paths inside the mounted volume."""
        return list(self.entries_by_path.keys())

    def get_entry(self, path: str) -> Optional[BundleEntry]:
        """Retrieves entry metadata by virtual path."""
        norm = self._normalize_key(path)
        return self.entries_by_path.get(norm)

    def read_file_bytes(self, path: str) -> bytes:
        """
        Extracts and decompresses the bytes of a specific file from the virtual volume.
        """
        norm = self._normalize_key(path)
        if norm in self._cache:
            return self._cache[norm]

        entry = self.entries_by_path.get(norm)
        if not entry:
            raise FileNotFoundError(f"File '{path}' not found in virtual bundle volume.")

        # Bounds checking
        read_len = entry.compressed_size if entry.is_compressed and entry.compressed_size > 0 else entry.size
        if entry.offset < 0 or entry.offset + read_len > len(self.binary_data):
            raise SecurityError(
                f"Entry offset {entry.offset} with length {read_len} out of binary bounds ({len(self.binary_data)})."
            )

        raw_slice = self.binary_data[entry.offset : entry.offset + read_len]

        if entry.is_compressed:
            decompressed, _ = BundleDecompressor.decompress(
                raw_slice, expected_size=entry.size
            )
            data_bytes = decompressed
        else:
            data_bytes = raw_slice

        # Compute hash and entropy if not already computed
        if not entry.sha256:
            entry.sha256 = hashlib.sha256(data_bytes).hexdigest()
            entry.entropy = calculate_entropy(data_bytes)
            if data_bytes.startswith(b"MZ"):
                entry.is_pe = True
                if b"BSJB" in data_bytes or b".text" in data_bytes:
                    entry.is_dotnet = True

        self._cache[norm] = data_bytes
        return data_bytes

    def filter_entries(self, category: str = "all") -> List[BundleEntry]:
        """Filters entries by high-level category."""
        cat = category.lower().strip()
        if cat == "all":
            return list(self.entries_by_path.values())
        if cat in ("assemblies", "assembly", "managed", "dll"):
            return [e for e in self.entries_by_path.values() if e.file_type == BundleFileType.ASSEMBLY]
        if cat in ("native", "native_binary", "so", "dylib"):
            return [e for e in self.entries_by_path.values() if e.file_type in (BundleFileType.NATIVE_BINARY, BundleFileType.EXTRACT_TO_DISK)]
        if cat in ("symbols", "pdb"):
            return [e for e in self.entries_by_path.values() if e.file_type in (BundleFileType.PDB_FILE, BundleFileType.SYMBOLS)]
        if cat in ("configs", "config", "json"):
            return [e for e in self.entries_by_path.values() if e.file_type in (BundleFileType.DEPS_JSON, BundleFileType.RUNTIME_CONFIG_JSON)]
        return list(self.entries_by_path.values())

    def render_tree(self) -> str:
        """Returns visual ASCII representation of the virtual volume filesystem."""
        lines = ["/ (virtual bundle root)"]
        tree_lines = self.root.render_tree()
        lines.extend(tree_lines)
        return "\n".join(lines)

    def get_summary(self) -> Dict[str, Any]:
        """Returns statistics summary of the mounted volume."""
        assemblies = [e for e in self.entries_by_path.values() if e.file_type == BundleFileType.ASSEMBLY]
        natives = [e for e in self.entries_by_path.values() if e.file_type in (BundleFileType.NATIVE_BINARY, BundleFileType.EXTRACT_TO_DISK)]
        pdbs = [e for e in self.entries_by_path.values() if e.file_type in (BundleFileType.PDB_FILE, BundleFileType.SYMBOLS)]
        configs = [e for e in self.entries_by_path.values() if e.file_type in (BundleFileType.DEPS_JSON, BundleFileType.RUNTIME_CONFIG_JSON)]
        total_raw = sum(e.size for e in self.entries_by_path.values())
        total_comp = sum(e.compressed_size if e.is_compressed and e.compressed_size > 0 else e.size for e in self.entries_by_path.values())
        ratio = (total_comp / total_raw) if total_raw > 0 else 1.0

        return {
            "total_files": len(self.entries_by_path),
            "assembly_count": len(assemblies),
            "native_count": len(natives),
            "pdb_count": len(pdbs),
            "config_count": len(configs),
            "total_uncompressed_bytes": total_raw,
            "total_compressed_bytes": total_comp,
            "compression_ratio": round(ratio, 4),
            "has_compressed_files": any(e.is_compressed for e in self.entries_by_path.values()),
        }
