import sys
from pathlib import Path
from parser import discover_repository
from resolver import build_symbol_index, resolve_call_graph
from graph import build_symbol_graph
from partition import partition_graph, print_partitions
from boundary import find_boundaries, print_boundaries  # NEW IMPORT

def main():
    repo_path = Path(sys.argv[1]).resolve()
    
    # 1.0 Repository Ingestion & Parsing
    files = discover_repository(repo_path)
    print(f"\nDiscovered {len(files)} Python files")

    # 2.0 Dependency Graph Construction (Level 3)
    index = build_symbol_index(files, repo_path)
    edges = resolve_call_graph(files, repo_path, index)
    symbol_graph = build_symbol_graph(edges)
    
    print(f"Constructed Level-3 Graph: {symbol_graph.number_of_nodes()} nodes, {symbol_graph.number_of_edges()} edges")

    # 3.0 Graph-Guided Repository Partitioning
    partitions = partition_graph(symbol_graph)
    print_partitions(partitions)

    # NEW: Boundary Identification (Prep for 5.0)
    boundaries = find_boundaries(symbol_graph, partitions)
    print_boundaries(boundaries)

if __name__ == "__main__":
    main()