from collections import Counter
from typing import Dict, List, Set, Tuple
import networkx as nx
from networkx.algorithms.community import (
    greedy_modularity_communities,
    modularity,
)

from models import ClusterInfo, GraphEdge, SymbolNode


def _get_clustering_unit(sym_id: str, symbols: Dict[str, SymbolNode]) -> str:
    """
    Maps a method to its enclosing class ID so that a class and all of its
    methods are always kept together in the same cluster.
    Standalone functions, classes, and modules map to themselves.
    """
    sym = symbols[sym_id]
    if sym.kind == "method" and sym.parent_id and sym.parent_id in symbols:
        return sym.parent_id
    return sym_id


def _build_unit_clustering_graph(
    symbols: Dict[str, SymbolNode],
    edges: List[GraphEdge],
) -> nx.Graph:
    """
    Constructs a weighted undirected graph over atomic clustering units
    (Classes, Standalone Functions, and Modules).
    """
    UG = nx.Graph()

    for sym_id, sym in symbols.items():
        unit_id = _get_clustering_unit(sym_id, symbols)
        UG.add_node(unit_id)

    kind_multiplier = {
        "INHERITS": 3.0,
        "CALLS": 2.5,  # Primary driver of vertical feature slices (Controller -> Service -> Repo)
        "DEFINES": 0.8,  # Mild intra-module gravity so unrelated classes in one file can separate
        "IMPORTS": 0.4,
    }

    for edge in edges:
        if edge.source not in symbols or edge.target not in symbols:
            continue
        u = _get_clustering_unit(edge.source, symbols)
        v = _get_clustering_unit(edge.target, symbols)
        if u == v:
            continue

        w = edge.weight * kind_multiplier.get(edge.kind, 1.0)
        if UG.has_edge(u, v):
            UG[u][v]["weight"] += w
        else:
            UG.add_edge(u, v, weight=w)

    return UG


def _consolidate_small_unit_communities(
    communities: List[Set[str]],
    UG: nx.Graph,
    symbols: Dict[str, SymbolNode],
    min_expanded_symbols: int = 10,
) -> List[Set[str]]:
    """
    Merges small communities into the neighboring community with the highest shared edge weight.
    """

    def expanded_size(unit_comm: Set[str]) -> int:
        return sum(
            1 for sid in symbols if _get_clustering_unit(sid, symbols) in unit_comm
        )

    comms = [set(c) for c in communities]
    changed = True

    while changed and len(comms) > 1:
        changed = False
        comms.sort(key=expanded_size)
        smallest = comms[0]
        if expanded_size(smallest) >= min_expanded_symbols:
            break

        best_target_idx = None
        best_weight = -1.0

        for idx in range(1, len(comms)):
            target_comm = comms[idx]
            shared_w = 0.0
            for u in smallest:
                for v in UG.neighbors(u):
                    if v in target_comm:
                        shared_w += UG[u][v].get("weight", 1.0)
            if shared_w > best_weight:
                best_weight = shared_w
                best_target_idx = idx

        if best_target_idx is not None:
            comms[best_target_idx].update(smallest)
            comms.pop(0)
            changed = True

    comms.sort(key=lambda c: (-expanded_size(c), sorted(c)[0]))
    return comms


def partition_repository_graph(
    symbols: Dict[str, SymbolNode],
    edges: List[GraphEdge],
    min_cluster_size: int = 10,
) -> Tuple[List[ClusterInfo], Dict[str, any]]:
    """
    Partitions the repository into class-cohesive vertical feature clusters.
    """
    UG = _build_unit_clustering_graph(symbols, edges)

    raw_unit_comms = list(greedy_modularity_communities(UG, weight="weight"))
    final_unit_comms = _consolidate_small_unit_communities(
        raw_unit_comms, UG, symbols, min_expanded_symbols=min_cluster_size
    )

    # Expand unit communities back to full SymbolNode sets
    expanded_communities: List[Set[str]] = []
    for unit_comm in final_unit_comms:
        full_comm = {
            sid for sid in symbols if _get_clustering_unit(sid, symbols) in unit_comm
        }
        expanded_communities.append(full_comm)

    clusters: List[ClusterInfo] = []
    node_to_cluster: Dict[str, int] = {}

    for idx, comm in enumerate(expanded_communities, start=1):
        sorted_syms = sorted(comm)
        for sid in sorted_syms:
            symbols[sid].cluster_id = idx
            node_to_cluster[sid] = idx

        # Name cluster after its primary classes/modules
        class_names = [
            symbols[sid].name for sid in sorted_syms if symbols[sid].kind == "class"
        ]
        if class_names:
            label = " + ".join(class_names[:4])
            if len(class_names) > 4:
                label += f" (+{len(class_names) - 4})"
        else:
            mod_counts = Counter(symbols[sid].module_name for sid in sorted_syms)
            label = " + ".join(m for m, _ in mod_counts.most_common(3))

        all_mods = sorted({symbols[sid].module_name for sid in sorted_syms})
        entry_points = []
        sink_symbols = []
        code_lines = 0

        for sid in sorted_syms:
            sym = symbols[sid]
            if sym.kind in ("function", "method"):
                code_lines += max(0, sym.end_line - sym.start_line + 1)
                if (
                    sym.name.startswith("handle_")
                    or sym.name in ("dispatch", "main")
                    or any("route" in d or "app." in d for d in sym.decorators)
                ):
                    entry_points.append(sid)

                has_ext_call = any(c.resolution_status == "EXTERNAL" for c in sym.calls)
                if has_ext_call or sym.dynamic_locals:
                    sink_symbols.append(sid)

        clusters.append(
            ClusterInfo(
                cluster_id=idx,
                label=label,
                symbol_ids=sorted_syms,
                modules_covered=all_mods,
                entry_points=entry_points,
                external_sink_symbols=sink_symbols,
                estimated_code_lines=code_lines,
            )
        )

    mod_score = (
        modularity(UG, final_unit_comms, weight="weight")
        if len(final_unit_comms) > 1
        else 0.0
    )
    call_edges = [e for e in edges if e.kind == "CALLS"]
    cross_cluster_calls = [
        e
        for e in call_edges
        if node_to_cluster.get(e.source) != node_to_cluster.get(e.target)
    ]
    call_cut_ratio = len(cross_cluster_calls) / len(call_edges) if call_edges else 0.0

    metrics = {
        "num_clusters": len(clusters),
        "raw_communities_before_consolidation": len(raw_unit_comms),
        "modularity_score": round(mod_score, 4),
        "total_internal_call_edges": len(call_edges),
        "cross_cluster_call_edges": len(cross_cluster_calls),
        "intra_cluster_call_retention": round(1.0 - call_cut_ratio, 4),
        "call_cut_ratio": round(call_cut_ratio, 4),
    }

    return clusters, metrics
