from typing import Dict, List
from models import BoundaryEdge, GraphEdge, SymbolNode


def extract_boundary_contracts(
    symbols: Dict[str, SymbolNode],
    edges: List[GraphEdge],
) -> List[BoundaryEdge]:
    """
    Identifies all CALLS edges that cross cluster boundaries and enriches them
    with bidirectional security contracts (signatures, caller guards, target guards,
    and target external calls).
    """
    boundaries: List[BoundaryEdge] = []

    for edge in edges:
        if edge.kind != "CALLS":
            continue

        src_sym = symbols.get(edge.source)
        tgt_sym = symbols.get(edge.target)
        if not src_sym or not tgt_sym:
            continue

        if src_sym.cluster_id is None or tgt_sym.cluster_id is None:
            continue

        if src_sym.cluster_id == tgt_sym.cluster_id:
            continue

        # Find matching CallSite on src_sym for argument preview & dynamic flag
        args_preview = ""
        is_dynamic = False
        for call in src_sym.calls:
            if call.line == edge.line and edge.target in call.resolved_targets:
                args_preview = call.args_preview
                is_dynamic = call.is_dynamic_arg
                break

        caller_guards = [
            f"L{g.line} [{g.kind}]: {g.preview}"
            for g in src_sym.guards
            if g.line <= edge.line
        ]
        target_guards = [f"L{g.line} [{g.kind}]: {g.preview}" for g in tgt_sym.guards]
        target_ext_calls = [
            f"L{c.line}: {c.callee_expr}({c.args_preview})"
            + (" [DYNAMIC_ARG]" if c.is_dynamic_arg else "")
            for c in tgt_sym.calls
            if c.resolution_status == "EXTERNAL"
        ]

        boundaries.append(
            BoundaryEdge(
                source_symbol=src_sym.id,
                source_cluster=src_sym.cluster_id,
                source_signature=src_sym.signature,
                caller_guards=caller_guards,
                target_symbol=tgt_sym.id,
                target_cluster=tgt_sym.cluster_id,
                target_signature=tgt_sym.signature,
                target_guards=target_guards,
                target_external_calls=target_ext_calls,
                line=edge.line,
                confidence=edge.confidence,
                args_preview=args_preview,
                is_dynamic_arg=is_dynamic,
            )
        )

    # Sort deterministically by source cluster, target cluster, source symbol, line
    boundaries.sort(
        key=lambda b: (b.source_cluster, b.target_cluster, b.source_symbol, b.line)
    )
    return boundaries
