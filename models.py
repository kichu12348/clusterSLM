from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any


@dataclass
class ImportRecord:
    """Represents an import statement with full alias and relative-level provenance."""

    module: str
    imported_name: Optional[str]
    alias: str
    level: int = 0
    line: int = 0


@dataclass
class CallSite:
    """Represents a function or method call occurring inside a symbol's body."""

    callee_expr: str
    line: int
    args_preview: str
    keywords: List[str] = field(default_factory=list)
    is_dynamic_arg: bool = False
    resolved_targets: List[str] = field(default_factory=list)
    resolution_status: str = (
        "UNRESOLVED"  # "EXACT" | "HEURISTIC" | "AMBIGUOUS" | "EXTERNAL" | "BUILTIN_NOISE"
    )


@dataclass
class GuardRecord:
    """Represents an explicit check, assertion, auth check, or exception raise inside a symbol."""

    kind: str  # "raise" | "assert" | "type_check" | "guard_clause"
    preview: str
    line: int


@dataclass
class SymbolNode:
    """Represents an addressable structural entity in the repository."""

    id: str
    name: str
    kind: str  # "module" | "class" | "function" | "method"
    file_path: str
    module_name: str
    parent_id: Optional[str]
    start_line: int
    end_line: int
    signature: str
    decorators: List[str] = field(default_factory=list)
    bases: List[str] = field(default_factory=list)
    docstring_summary: Optional[str] = None
    source_code: str = ""
    calls: List[CallSite] = field(default_factory=list)
    guards: List[GuardRecord] = field(default_factory=list)
    attribute_types: Dict[str, str] = field(default_factory=dict)
    param_types: Dict[str, str] = field(default_factory=dict)
    parameters: List[str] = field(default_factory=list)
    # Local variables assigned via dynamic string formatting (e.g., sql = f"SELECT ... {x}")
    dynamic_locals: List[str] = field(default_factory=list)
    returns_dynamic: bool = False
    cluster_id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GraphEdge:
    """Represents a directed, typed relationship between two internal repository SymbolNodes."""

    source: str
    target: str
    kind: str  # "DEFINES" | "IMPORTS" | "INHERITS" | "CALLS"
    confidence: str = "EXACT"  # "EXACT" | "HEURISTIC" | "AMBIGUOUS"
    line: int = 0
    weight: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BoundaryEdge:
    """
    Represents a cross-cluster CALLS relationship enriched with caller and target
    security contracts so the SLM does not lose context at cluster borders.
    """

    source_symbol: str
    source_cluster: int
    source_signature: str
    caller_guards: List[
        str
    ]  # Guards active in the calling function (e.g., role checks)
    target_symbol: str
    target_cluster: int
    target_signature: str
    target_guards: List[str]  # Guards active in the target function
    target_external_calls: List[str]  # External calls made directly by the target
    line: int
    confidence: str
    args_preview: str
    is_dynamic_arg: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ClusterInfo:
    """Represents a cohesive repository cluster and its metadata."""

    cluster_id: int
    label: str  # Auto-generated descriptive label (e.g., "auth / api.controllers")
    symbol_ids: List[str] = field(default_factory=list)
    modules_covered: List[str] = field(default_factory=list)
    entry_points: List[str] = field(default_factory=list)
    external_sink_symbols: List[str] = field(default_factory=list)
    estimated_code_lines: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FileParseResult:
    """Output of parsing a single source file."""

    file_path: str
    module_name: str
    imports: List[ImportRecord] = field(default_factory=list)
    symbols: Dict[str, SymbolNode] = field(default_factory=dict)
    parse_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
