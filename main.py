import sys
from pathlib import Path
from parser import discover_repository
from resolver import build_symbol_index, resolve_call_graph
from graph import build_symbol_graph
from partition import partition_graph, print_partitions
from boundary import find_boundaries, print_boundaries
from analyzer import run_parallel_analysis 

def main():
    repo_path = Path(sys.argv[1]).resolve()
    
    files = discover_repository(repo_path)
    index = build_symbol_index(files, repo_path)
    edges = resolve_call_graph(files, repo_path, index)
    symbol_graph = build_symbol_graph(edges)
    
    partitions = partition_graph(symbol_graph)
    boundaries = find_boundaries(symbol_graph, partitions)
    
    # Run the new process
    findings = run_parallel_analysis(partitions, boundaries, files, repo_path)

if __name__ == "__main__":
    main()