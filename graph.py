from typing import Dict, List
import networkx as nx

from models import GraphEdge, SymbolNode


def build_repository_graph(
    symbols: Dict[str, SymbolNode],
    edges: List[GraphEdge],
) -> nx.MultiDiGraph:
    """
    Constructs the complete multi-relational repository graph.
    Nodes are strictly internal SymbolNodes.
    Edges carry kind (DEFINES, IMPORTS, INHERITS, CALLS), confidence, line, and weight.
    """
    G = nx.MultiDiGraph()

    for sym_id, sym in symbols.items():
        G.add_node(
            sym_id,
            kind=sym.kind,
            name=sym.name,
            module_name=sym.module_name,
            file_path=sym.file_path,
            start_line=sym.start_line,
            end_line=sym.end_line,
        )

    for edge in edges:
        if edge.source in G and edge.target in G:
            G.add_edge(
                edge.source,
                edge.target,
                kind=edge.kind,
                confidence=edge.confidence,
                line=edge.line,
                weight=edge.weight,
            )

    return G


def summarize_graph_and_resolution(
    symbols: Dict[str, SymbolNode],
    edges: List[GraphEdge],
) -> Dict[str, any]:
    """Computes diagnostic metrics for symbol resolution and graph connectivity."""
    edge_counts_by_kind: Dict[str, int] = {}
    call_edges_by_conf: Dict[str, int] = {}

    for e in edges:
        edge_counts_by_kind[e.kind] = edge_counts_by_kind.get(e.kind, 0) + 1
        if e.kind == "CALLS":
            call_edges_by_conf[e.confidence] = (
                call_edges_by_conf.get(e.confidence, 0) + 1
            )

    call_site_status: Dict[str, int] = {}
    external_security_calls = []

    for sym in symbols.values():
        for call in sym.calls:
            st = call.resolution_status
            call_site_status[st] = call_site_status.get(st, 0) + 1
            if st == "EXTERNAL":
                external_security_calls.append(
                    (
                        sym.id,
                        call.line,
                        call.callee_expr,
                        call.args_preview,
                        call.is_dynamic_arg,
                    )
                )

    return {
        "total_symbols": len(symbols),
        "total_edges": len(edges),
        "edges_by_kind": edge_counts_by_kind,
        "call_edges_by_confidence": call_edges_by_conf,
        "call_sites_by_status": call_site_status,
        "external_calls": external_security_calls,
    }
