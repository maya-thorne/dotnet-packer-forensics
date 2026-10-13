"""
Babel Obfuscator Cross-Assembly Symbol Demangler & Dependency Graph Restorer.
Engineered & Audited by Maya Thorne.
"""

from dataclasses import dataclass, field
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import xml.etree.ElementTree as ET


@dataclass
class DemangleRule:
    """Represents a specific symbol demangling transformation rule."""

    rule_id: str
    rule_type: str
    description: str
    priority: int = 10

    def apply(self, name: str, context: Optional[Dict[str, Any]] = None) -> Tuple[str, bool]:
        """Applies rule transformation to symbol name. Returns (new_name, applied)."""
        return name, False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_type": self.rule_type,
            "description": self.description,
            "priority": self.priority,
        }


@dataclass
class DemangledSymbol:
    """Represents a restored or normalized identifier with forensic provenance."""

    original_name: str
    demangled_name: str
    symbol_type: str  # "type", "method", "field", "property", "event", "namespace", "parameter", "assembly"
    token: Optional[str] = None
    declaring_type: Optional[str] = None
    rule_applied: str = "NONE"
    confidence: str = "HIGH"  # "HIGH", "MEDIUM", "LOW"
    is_mangled: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_name": self.original_name,
            "demangled_name": self.demangled_name,
            "symbol_type": self.symbol_type,
            "token": self.token,
            "declaring_type": self.declaring_type,
            "rule_applied": self.rule_applied,
            "confidence": self.confidence,
            "is_mangled": self.is_mangled,
            "metadata": self.metadata,
        }


@dataclass
class AssemblyNode:
    """Represents a .NET assembly in the inter-assembly dependency graph."""

    name: str
    version: str = "1.0.0.0"
    culture: str = "neutral"
    public_key_token: Optional[str] = None
    is_merged: bool = False
    is_main: bool = False
    types: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    symbols_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "culture": self.culture,
            "public_key_token": self.public_key_token,
            "is_merged": self.is_merged,
            "is_main": self.is_main,
            "types_count": len(self.types),
            "types": self.types,
            "dependencies": self.dependencies,
            "symbols_count": self.symbols_count,
            "metadata": self.metadata,
        }


class DependencyGraph:
    """
    Directed Acyclic Graph (DAG) modeling cross-assembly references,
    merged satellite assemblies, and assembly load orders.
    """

    def __init__(self) -> None:
        self.nodes: Dict[str, AssemblyNode] = {}
        self.edges: Dict[str, Set[str]] = {}
        self.reverse_edges: Dict[str, Set[str]] = {}

    def add_assembly(self, node: AssemblyNode) -> None:
        """Registers an assembly node in the graph."""
        self.nodes[node.name] = node
        if node.name not in self.edges:
            self.edges[node.name] = set()
        if node.name not in self.reverse_edges:
            self.reverse_edges[node.name] = set()
        # Add initial dependencies declared on the node
        for dep in node.dependencies:
            self.add_dependency(node.name, dep)

    def add_dependency(self, source: str, target: str) -> None:
        """Adds a directed dependency edge: source depends on target."""
        if source not in self.nodes:
            self.nodes[source] = AssemblyNode(name=source)
        if target not in self.nodes:
            self.nodes[target] = AssemblyNode(name=target)

        if source not in self.edges:
            self.edges[source] = set()
        if target not in self.reverse_edges:
            self.reverse_edges[target] = set()

        self.edges[source].add(target)
        self.reverse_edges.setdefault(target, set()).add(source)

        if target not in self.nodes[source].dependencies:
            self.nodes[source].dependencies.append(target)

    def get_assembly(self, name: str) -> Optional[AssemblyNode]:
        """Retrieves an assembly node by name."""
        return self.nodes.get(name)

    def has_assembly(self, name: str) -> bool:
        """Returns True if assembly node exists in graph."""
        return name in self.nodes

    def get_dependencies(self, name: str) -> List[str]:
        """Returns list of assemblies that the given assembly depends on."""
        return sorted(list(self.edges.get(name, set())))

    def get_dependents(self, name: str) -> List[str]:
        """Returns list of assemblies that depend on the given assembly."""
        return sorted(list(self.reverse_edges.get(name, set())))

    def detect_cycles(self) -> List[List[str]]:
        """
        Detects directed dependency cycles using Tarjan-style DFS.
        Returns list of cycle paths (e.g. [['A', 'B', 'A']]).
        """
        visited: Dict[str, int] = {}  # 0: unvisited, 1: visiting, 2: visited
        cycles: List[List[str]] = []
        path: List[str] = []

        def dfs(node: str) -> None:
            visited[node] = 1
            path.append(node)
            for neighbor in sorted(self.edges.get(node, set())):
                if visited.get(neighbor, 0) == 1:
                    cycle_start = path.index(neighbor)
                    cycles.append(path[cycle_start:] + [neighbor])
                elif visited.get(neighbor, 0) == 0:
                    dfs(neighbor)
            path.pop()
            visited[node] = 2

        for node in sorted(self.nodes.keys()):
            if visited.get(node, 0) == 0:
                dfs(node)

        return cycles

    def is_dag(self) -> bool:
        """Returns True if graph is a Directed Acyclic Graph (no cycles)."""
        return len(self.detect_cycles()) == 0

    def topological_sort(self) -> List[str]:
        """
        Computes topological load order (Kahn's Algorithm).
        If cycles exist, returns best-effort sorted order.
        """
        in_degree: Dict[str, int] = {k: 0 for k in self.nodes}
        for u in self.edges:
            for v in self.edges[u]:
                in_degree[v] = in_degree.get(v, 0) + 1

        queue: List[str] = [k for k, deg in in_degree.items() if deg == 0]
        queue.sort()
        order: List[str] = []

        # Local mutable copy of edges
        adj = {u: set(self.edges[u]) for u in self.edges}

        while queue:
            node = queue.pop(0)
            order.append(node)
            for neighbor in sorted(adj.get(node, set())):
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)
                    queue.sort()

        # Handle remaining cyclic nodes if any
        if len(order) < len(self.nodes):
            remaining = [k for k in sorted(self.nodes.keys()) if k not in order]
            order.extend(remaining)

        return order

    def to_dict(self) -> Dict[str, Any]:
        """Serializes graph topology to dictionary format."""
        cycles = self.detect_cycles()
        return {
            "assembly_count": len(self.nodes),
            "edge_count": sum(len(e) for e in self.edges.values()),
            "is_dag": len(cycles) == 0,
            "cycles_detected": cycles,
            "topological_order": self.topological_sort(),
            "nodes": {k: node.to_dict() for k, node in sorted(self.nodes.items())},
            "edges": {k: sorted(list(v)) for k, v in sorted(self.edges.items())},
        }

    def to_dot(self) -> str:
        """Generates Graphviz DOT representation of assembly dependency graph."""
        lines = [
            "digraph DependencyGraph {",
            '  graph [rankdir=LR, bgcolor="transparent"];',
            '  node [shape=box, style="filled,rounded", fontname="Courier", fontsize=10];',
            '  edge [fontname="Courier", fontsize=9, color="#555555"];',
            "",
        ]

        # Define nodes with styling based on assembly characteristics
        for name, node in sorted(self.nodes.items()):
            label_parts = [name]
            if node.version:
                label_parts.append(f"v{node.version}")
            if node.is_main:
                label_parts.append("[Main]")
            elif node.is_merged:
                label_parts.append("[Merged]")

            label = "\\n".join(label_parts)
            if node.is_main:
                fillcolor = "#FFE0B2"
                color = "#E65100"
            elif node.is_merged:
                fillcolor = "#E1BEE7"
                color = "#4A148C"
            else:
                fillcolor = "#E3F2FD"
                color = "#0D47A1"

            lines.append(f'  "{name}" [label="{label}", fillcolor="{fillcolor}", color="{color}"];')

        lines.append("")
        for src in sorted(self.edges.keys()):
            for tgt in sorted(self.edges[src]):
                lines.append(f'  "{src}" -> "{tgt}";')

        lines.append("}")
        return "\n".join(lines)

    def to_mermaid(self) -> str:
        """Generates Mermaid flowchart diagram of assembly dependency graph."""
        lines = [
            "graph TD",
            "  classDef main fill:#ffe0b2,stroke:#e65100,stroke-width:2px;",
            "  classDef merged fill:#e1bee7,stroke:#4a148c,stroke-width:2px;",
            "  classDef external fill:#e3f2fd,stroke:#0d47a1,stroke-width:1px;",
            "",
        ]

        def sanitize_id(raw: str) -> str:
            clean = re.sub(r"[^a-zA-Z0-9_]", "_", raw)
            return f"n_{clean}"

        # Nodes
        for name, node in sorted(self.nodes.items()):
            nid = sanitize_id(name)
            tag = " [Main]" if node.is_main else (" [Merged]" if node.is_merged else "")
            v_tag = f" v{node.version}" if node.version else ""
            display_text = f"{name}{v_tag}{tag}"
            lines.append(f'  {nid}["{display_text}"]')

            if node.is_main:
                lines.append(f"  class {nid} main;")
            elif node.is_merged:
                lines.append(f"  class {nid} merged;")
            else:
                lines.append(f"  class {nid} external;")

        lines.append("")
        # Edges
        for src in sorted(self.edges.keys()):
            sid = sanitize_id(src)
            for tgt in sorted(self.edges[src]):
                tid = sanitize_id(tgt)
                lines.append(f"  {sid} --> {tid}")

        return "\n".join(lines)


class BabelDemangler:
    """
    Forensic symbol demangling and identifier restoration engine for
    Babel Obfuscator protected assemblies.
    """

    # Unicode obfuscation sets (Zero-width, BIDI overrides, formatting marks)
    ZERO_WIDTH_CHARS = {
        0x200B, 0x200C, 0x200D, 0xFEFF, 0x200E, 0x200F,
        0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2060,
    }
    CONTROL_CHARS = set(range(0x00, 0x20)) | {0x7F}

    # Standard ECMA-335 / BCL Interfaces and standard method signatures
    KNOWN_INTERFACES: Dict[str, List[str]] = {
        "IDisposable": ["Dispose"],
        "IEnumerable": ["GetEnumerator"],
        "IEnumerator": ["MoveNext", "Reset", "get_Current"],
        "IComparable": ["CompareTo"],
        "IEquatable": ["Equals"],
        "ICloneable": ["Clone"],
        "ICollection": ["CopyTo", "get_Count", "get_IsSynchronized", "get_SyncRoot"],
        "IList": ["get_Item", "set_Item", "Add", "Contains", "Clear", "IndexOf", "Insert", "Remove", "RemoveAt"],
        "IDictionary": ["get_Item", "set_Item", "get_Keys", "get_Values", "Contains", "Add", "Clear", "Remove"],
        "INotifyPropertyChanged": ["add_PropertyChanged", "remove_PropertyChanged"],
        "IAsyncResult": ["get_IsCompleted", "get_AsyncWaitHandle", "get_AsyncState", "get_CompletedSynchronously"],
        "IConvertible": [
            "GetTypeCode", "ToBoolean", "ToByte", "ToChar", "ToDateTime",
            "ToDecimal", "ToDouble", "ToInt16", "ToInt32", "ToInt64",
            "ToSByte", "ToSingle", "ToString", "ToType", "ToUInt16",
            "ToUInt32", "ToUInt64",
        ],
    }

    # Babel signature identifier regexes
    BABEL_MANGLED_PATTERNS = [
        re.compile(r"^_[0-9a-fA-F]{1,8}$"),
        re.compile(r"^[a-zA-Z]_[0-9a-fA-F]{1,8}$"),
        re.compile(r"^Babel_[0-9a-zA-Z_]+$"),
        re.compile(r"^<Babel>[0-9a-zA-Z_]+$"),
        re.compile(r"^[0-9]+$"),  # Numeric identifier names
    ]

    @classmethod
    def sanitize_unicode(cls, name: str) -> str:
        """
        Strips unprintable, zero-width, bidirectional override, and control
        characters from identifier strings.
        """
        if not name:
            return ""
        cleaned = []
        for char in name:
            code = ord(char)
            if code in cls.ZERO_WIDTH_CHARS or code in cls.CONTROL_CHARS:
                continue
            cleaned.append(char)
        result = "".join(cleaned).strip()
        return result

    @classmethod
    def is_mangled_identifier(cls, name: str) -> bool:
        """
        Determines whether an identifier has been mangled or scrambled by Babel.
        Checks for unprintable characters, length heuristics, and known Babel patterns.
        """
        if not name:
            return False

        # 1. Contains zero-width or unprintable characters
        if any(ord(c) in cls.ZERO_WIDTH_CHARS or ord(c) in cls.CONTROL_CHARS for c in name):
            return True

        # 2. Check sanitized representation
        clean = cls.sanitize_unicode(name)
        if not clean:
            return True

        # 3. Contains non-ASCII characters
        if any(ord(c) > 127 for c in clean):
            return True

        # 4. Extremely short cryptic identifier (single character or two non-standard characters)
        if len(clean) == 1 and clean not in ("I", "T"):  # Exclude standard generics/interfaces
            return True
        if len(clean) == 2 and not clean.isalnum():
            return True

        # 5. Pattern matches Babel obfuscator generator rules
        for pat in cls.BABEL_MANGLED_PATTERNS:
            if pat.match(clean):
                return True

        return False

    @classmethod
    def infer_interface_methods(cls, interface_name: str, method_count: int = 1) -> List[str]:
        """
        Infers meaningful method names from an implemented interface name.
        """
        clean_iface = cls.sanitize_unicode(interface_name).split(".")[-1]
        if clean_iface in cls.KNOWN_INTERFACES:
            known_methods = cls.KNOWN_INTERFACES[clean_iface]
            return known_methods[:method_count]

        # Heuristic inference from interface prefix 'I'
        base_name = clean_iface[1:] if clean_iface.startswith("I") and len(clean_iface) > 1 else clean_iface
        return [f"Execute{base_name}_{i+1}" for i in range(method_count)]

    @classmethod
    def restore_getter_setter(
        cls, method_name: str, property_name: Optional[str] = None
    ) -> Tuple[str, Optional[str]]:
        """
        Pairs and restores getter/setter accessor methods into a clean property representation.
        Returns (restored_method_name, inferred_property_name).
        """
        clean = cls.sanitize_unicode(method_name)

        if clean.startswith("get_"):
            prop = property_name or clean[4:]
            return f"get_{prop}", prop
        elif clean.startswith("set_"):
            prop = property_name or clean[4:]
            return f"set_{prop}", prop
        elif property_name:
            if "get" in clean.lower():
                return f"get_{property_name}", property_name
            elif "set" in clean.lower():
                return f"set_{property_name}", property_name

        return clean, property_name

    @classmethod
    def normalize_pattern(
        cls, name: str, symbol_type: str = "type", index: int = 1, prefix: Optional[str] = None
    ) -> str:
        """
        Generates a clean, systematic, deterministic identifier.
        e.g. Type_0001, Method_0002, Field_0003.
        """
        type_prefixes = {
            "type": "Type",
            "method": "Method",
            "field": "Field",
            "property": "Property",
            "event": "Event",
            "namespace": "Namespace",
            "parameter": "param",
            "assembly": "Assembly",
        }
        pfx = prefix or type_prefixes.get(symbol_type.lower(), "Symbol")
        return f"{pfx}_{index:04d}"

    @classmethod
    def parse_embedded_map(cls, map_content: Union[str, bytes]) -> Dict[str, str]:
        """
        Parses Babel symbol mapping in XML, JSON, or text format.
        Returns a mapping dictionary { obfuscated_name: clean_name }.
        """
        if isinstance(map_content, bytes):
            text = map_content.decode("utf-8", errors="ignore")
        else:
            text = map_content

        mapping: Dict[str, str] = {}
        stripped = text.strip()

        # Security: Enforce map size ceiling to prevent DoS memory exhaustion
        if len(stripped) > 10 * 1024 * 1024:
            return {}

        # 1. Try XML parsing (<BabelMap>, <Type Old="..." New="...">, etc.)
        if stripped.startswith("<"):
            # Security: Defend against XML Entity Expansion (Billion Laughs) and XXE
            upper_prefix = stripped[:1024].upper()
            if "<!ENTITY" in upper_prefix or "<!DOCTYPE" in upper_prefix:
                return {}
            try:
                root = ET.fromstring(stripped)
                # Look for all elements with Old/New or from/to attributes
                for elem in root.iter():
                    old_name = elem.get("Old") or elem.get("old") or elem.get("from") or elem.get("From")
                    new_name = elem.get("New") or elem.get("new") or elem.get("to") or elem.get("To")
                    if old_name and new_name:
                        mapping[old_name] = new_name
                if mapping:
                    return mapping
            except ET.ParseError:
                pass

        # 2. Try JSON parsing
        if stripped.startswith("{"):
            try:
                data = json.loads(stripped)
                if isinstance(data, dict):
                    # Handle flat dict or nested {"types": {...}, "methods": {...}}
                    for k, v in data.items():
                        if isinstance(v, dict):
                            for inner_k, inner_v in v.items():
                                if isinstance(inner_v, str):
                                    mapping[inner_k] = inner_v
                        elif isinstance(v, str):
                            mapping[k] = v
                if mapping:
                    return mapping
            except json.JSONDecodeError:
                pass

        # 3. Line-based text parsing ("Old -> New", "Old = New", "Old,New")
        for line in stripped.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "//", ";")):
                continue
            if "->" in line:
                parts = line.split("->", 1)
                mapping[parts[0].strip()] = parts[1].strip()
            elif "=" in line:
                parts = line.split("=", 1)
                mapping[parts[0].strip()] = parts[1].strip()
            elif "," in line:
                parts = line.split(",", 1)
                mapping[parts[0].strip()] = parts[1].strip()

        return mapping

    @classmethod
    def demangle_symbol(
        cls,
        name: str,
        symbol_type: str = "type",
        index: int = 1,
        custom_map: Optional[Dict[str, str]] = None,
        declaring_type: Optional[str] = None,
        token: Optional[str] = None,
        interface_hints: Optional[List[str]] = None,
    ) -> DemangledSymbol:
        """
        Executes multi-stage demangling pipeline on a single identifier.
        Stages:
          1. Custom map override lookup
          2. Interface method inference
          3. Accessor (getter/setter) restoration
          4. Unicode unprintable sanitization
          5. Mangled identifier pattern normalization
        """
        orig = name
        clean = cls.sanitize_unicode(name)
        is_mangled = cls.is_mangled_identifier(orig)

        # Stage 1: Custom Map Lookup
        if custom_map:
            if orig in custom_map:
                return DemangledSymbol(
                    original_name=orig,
                    demangled_name=custom_map[orig],
                    symbol_type=symbol_type,
                    token=token,
                    declaring_type=declaring_type,
                    rule_applied="MAP_OVERRIDE",
                    confidence="HIGH",
                    is_mangled=is_mangled,
                )
            if clean in custom_map:
                return DemangledSymbol(
                    original_name=orig,
                    demangled_name=custom_map[clean],
                    symbol_type=symbol_type,
                    token=token,
                    declaring_type=declaring_type,
                    rule_applied="MAP_OVERRIDE",
                    confidence="HIGH",
                    is_mangled=is_mangled,
                )

        # Stage 2: Interface Method Inference
        if interface_hints and symbol_type.lower() == "method":
            for iface in interface_hints:
                inferred_list = cls.infer_interface_methods(iface, method_count=1)
                if inferred_list:
                    return DemangledSymbol(
                        original_name=orig,
                        demangled_name=inferred_list[0],
                        symbol_type=symbol_type,
                        token=token,
                        declaring_type=declaring_type,
                        rule_applied="INTERFACE_INFERENCE",
                        confidence="HIGH",
                        is_mangled=is_mangled,
                        metadata={"inferred_from_interface": iface},
                    )

        # Stage 3: Getter / Setter Restoration
        if symbol_type.lower() in ("method", "property"):
            restored_acc, prop_name = cls.restore_getter_setter(clean)
            if prop_name:
                return DemangledSymbol(
                    original_name=orig,
                    demangled_name=restored_acc,
                    symbol_type=symbol_type,
                    token=token,
                    declaring_type=declaring_type,
                    rule_applied="GETTER_SETTER",
                    confidence="HIGH",
                    is_mangled=is_mangled,
                    metadata={"property_name": prop_name},
                )

        # Stage 4: Unicode Sanitization (if name becomes clean and non-empty)
        if not is_mangled:
            return DemangledSymbol(
                original_name=orig,
                demangled_name=clean if clean else cls.normalize_pattern(orig, symbol_type, index),
                symbol_type=symbol_type,
                token=token,
                declaring_type=declaring_type,
                rule_applied="NONE",
                confidence="HIGH",
                is_mangled=False,
            )

        if clean and not cls.is_mangled_identifier(clean):
            return DemangledSymbol(
                original_name=orig,
                demangled_name=clean,
                symbol_type=symbol_type,
                token=token,
                declaring_type=declaring_type,
                rule_applied="UNICODE_CLEAN",
                confidence="MEDIUM",
                is_mangled=True,
            )

        # Stage 5: Pattern Normalization (Deterministic fallback)
        normalized = cls.normalize_pattern(orig, symbol_type=symbol_type, index=index)
        return DemangledSymbol(
            original_name=orig,
            demangled_name=normalized,
            symbol_type=symbol_type,
            token=token,
            declaring_type=declaring_type,
            rule_applied="PATTERN_NORMALIZATION",
            confidence="MEDIUM",
            is_mangled=True,
        )

    @classmethod
    def demangle_symbols(
        cls,
        symbols: List[Dict[str, Any]],
        custom_map: Optional[Dict[str, str]] = None,
    ) -> List[DemangledSymbol]:
        """
        Batch demangles a collection of symbols with deterministic indexing.
        """
        results: List[DemangledSymbol] = []
        type_counters: Dict[str, int] = {}

        for sym in symbols:
            stype = sym.get("symbol_type", "type").lower()
            type_counters[stype] = type_counters.get(stype, 0) + 1
            idx = type_counters[stype]

            demangled = cls.demangle_symbol(
                name=sym["name"],
                symbol_type=stype,
                index=idx,
                custom_map=custom_map,
                declaring_type=sym.get("declaring_type"),
                token=sym.get("token"),
                interface_hints=sym.get("interface_hints"),
            )
            results.append(demangled)

        return results

    @classmethod
    def build_dependency_graph(
        cls,
        assemblies: List[Dict[str, Any]],
        references: Optional[List[Tuple[str, str]]] = None,
    ) -> DependencyGraph:
        """
        Constructs a DependencyGraph from primary and merged assemblies.
        """
        graph = DependencyGraph()

        for a in assemblies:
            node = AssemblyNode(
                name=a["name"],
                version=a.get("version", "1.0.0.0"),
                culture=a.get("culture", "neutral"),
                public_key_token=a.get("public_key_token"),
                is_merged=a.get("is_merged", False),
                is_main=a.get("is_main", False),
                types=a.get("types", []),
                dependencies=a.get("dependencies", []),
                symbols_count=a.get("symbols_count", 0),
            )
            graph.add_assembly(node)

        if references:
            for src, tgt in references:
                graph.add_dependency(src, tgt)

        return graph
