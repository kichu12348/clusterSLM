import json
from pathlib import Path
from typing import Dict, List, Any

from models import BoundaryEdge, ClusterInfo, GraphEdge, SymbolNode


def build_symbol_card(
    sym: SymbolNode,
    incoming_edges: List[GraphEdge],
    outgoing_edges: List[GraphEdge],
    symbols: Dict[str, SymbolNode],
) -> Dict[str, Any]:
    """
    Constructs a compact, high-signal Symbol Card for Phase 1 Discovery.
    Contains signature, decorators, guards, dynamic local expressions, external calls,
    and resolved internal call relationships—without dumping raw source lines.
    """
    ext_calls = [
        {
            "line": c.line,
            "call": f"{c.callee_expr}({c.args_preview})",
            "is_dynamic_arg": c.is_dynamic_arg,
        }
        for c in sym.calls
        if c.resolution_status == "EXTERNAL"
    ]

    internal_calls = []
    for e in outgoing_edges:
        if e.kind == "CALLS":
            tgt = symbols.get(e.target)
            # Find args preview
            args_prev = ""
            is_dyn = False
            for c in sym.calls:
                if c.line == e.line and e.target in c.resolved_targets:
                    args_prev = c.args_preview
                    is_dyn = c.is_dynamic_arg
                    break
            internal_calls.append(
                {
                    "target": e.target,
                    "target_cluster": tgt.cluster_id if tgt else None,
                    "line": e.line,
                    "args": args_prev,
                    "confidence": e.confidence,
                    "is_dynamic_arg": is_dyn,
                }
            )

    called_by = [
        {
            "source": e.source,
            "source_cluster": (
                symbols[e.source].cluster_id if e.source in symbols else None
            ),
            "line": e.line,
            "confidence": e.confidence,
        }
        for e in incoming_edges
        if e.kind == "CALLS"
    ]

    return {
        "id": sym.id,
        "kind": sym.kind,
        "location": f"{sym.file_path}:{sym.start_line}-{sym.end_line}",
        "signature": sym.signature,
        "decorators": sym.decorators,
        "guards": [f"L{g.line} [{g.kind}]: {g.preview}" for g in sym.guards],
        "dynamic_expressions": sym.dynamic_locals,
        "returns_dynamic": sym.returns_dynamic,
        "calls_internal": internal_calls,
        "calls_external": ext_calls,
        "called_by": called_by,
    }


def export_repository_bundle(
    repo_name: str,
    symbols: Dict[str, SymbolNode],
    edges: List[GraphEdge],
    clusters: List[ClusterInfo],
    boundaries: List[BoundaryEdge],
    resolution_stats: Dict[str, Any],
    cluster_metrics: Dict[str, Any],
    output_path: str = "repo_bundle.json",
) -> Dict[str, Any]:
    """
    Exports a single, self-contained JSON bundle for the Two-Pass Kaggle Workflow.
    Contains:
      1. repository_overview: High-level summary, entry points, high-risk sinks, metrics.
      2. discovery_clusters: Compact Phase 1 Cluster Maps (Symbol Cards + Boundary Contracts).
      3. symbol_index: Full SymbolNode records including exact line-numbered source code for Phase 2.
      4. edges: Full typed dependency graph edges for multi-hop path tracing in Phase 2.
    """
    incoming_by_sym: Dict[str, List[GraphEdge]] = {sid: [] for sid in symbols}
    outgoing_by_sym: Dict[str, List[GraphEdge]] = {sid: [] for sid in symbols}
    for e in edges:
        if e.source in outgoing_by_sym:
            outgoing_by_sym[e.source].append(e)
        if e.target in incoming_by_sym:
            incoming_by_sym[e.target].append(e)

    discovery_clusters = []
    for c in clusters:
        cards = []
        for sid in c.symbol_ids:
            sym = symbols[sid]
            # Include classes, functions, and methods in cluster cards
            if sym.kind in ("class", "function", "method"):
                cards.append(
                    build_symbol_card(
                        sym,
                        incoming_by_sym.get(sid, []),
                        outgoing_by_sym.get(sid, []),
                        symbols,
                    )
                )

        inc_bounds = [
            b.to_dict() for b in boundaries if b.target_cluster == c.cluster_id
        ]
        out_bounds = [
            b.to_dict() for b in boundaries if b.source_cluster == c.cluster_id
        ]

        discovery_clusters.append(
            {
                "cluster_id": c.cluster_id,
                "label": c.label,
                "modules_covered": c.modules_covered,
                "entry_points": c.entry_points,
                "external_sink_symbols": c.external_sink_symbols,
                "estimated_code_lines": c.estimated_code_lines,
                "symbol_cards": cards,
                "boundary_incoming": inc_bounds,
                "boundary_outgoing": out_bounds,
            }
        )

    bundle = {
        "repository_name": repo_name,
        "overview": {
            "resolution_stats": {
                k: v for k, v in resolution_stats.items() if k != "external_calls"
            },
            "cluster_metrics": cluster_metrics,
            "all_entry_points": [ep for c in clusters for ep in c.entry_points],
            "dynamic_sink_candidates": [
                {
                    "symbol": sid,
                    "cluster_id": symbols[sid].cluster_id,
                    "dynamic_locals": symbols[sid].dynamic_locals,
                }
                for sid in sorted(symbols)
                if symbols[sid].dynamic_locals
            ],
        },
        "discovery_clusters": discovery_clusters,
        "symbol_index": {sid: sym.to_dict() for sid, sym in symbols.items()},
        "edges": [e.to_dict() for e in edges],
        "boundaries": [b.to_dict() for b in boundaries],
    }

    out_file = Path(output_path)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)

    print(f"\n[+] Exported self-contained Kaggle bundle to: {out_file.resolve()}")
    return bundle
