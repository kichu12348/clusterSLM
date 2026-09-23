import sys
from pathlib import Path
from parser import discover_repository
from resolver import build_symbol_index, resolve_call_graph
from graph import build_symbol_graph
from partition import partition_graph
from boundary import find_boundaries
from analyzer import export_partition_contexts, mock_slm_worker
from reconciler import reconcile_findings
from reporter import generate_report


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py /path/to/repo [--export]")
        return

    repo_path = Path(sys.argv[1]).resolve()
    export_mode = "--export" in sys.argv

    # 1.0 Repository Ingestion & Parsing
    files = discover_repository(repo_path)
    print(f"\nDiscovered {len(files)} Python files")

    # 2.0 Dependency Graph Construction (Level 3)
    index = build_symbol_index(files, repo_path)
    edges = resolve_call_graph(files, repo_path, index)
    symbol_graph = build_symbol_graph(edges)

    # 3.0 Graph-Guided Repository Partitioning
    partitions = partition_graph(symbol_graph)
    boundaries = find_boundaries(symbol_graph, partitions)

    if export_mode:
        # Export mode: generate the payload for Kaggle
        export_partition_contexts(partitions, boundaries, files, repo_path)
        print(
            "[+] Contexts prepared. Upload 'partition_contexts.json' to Kaggle for Process 4.0."
        )
        return

    kaggle_results_file = Path.cwd() / "kaggle_findings.json"

    if kaggle_results_file.exists():
        import json

        print(f"\n[+] Found {kaggle_results_file.name}. Bypassing mock SLM...")
        with open(kaggle_results_file, "r") as f:
            findings = json.load(f)
    else:
        print("\n[-] No kaggle_findings.json found. Running mock SLM...")
        findings = []
        for p in partitions:
            from analyzer import build_partition_context, mock_slm_worker

            ctx = build_partition_context(p, boundaries, files, repo_path)
            res = mock_slm_worker(ctx)
            if res["findings"]:
                findings.append(res)

    reconciled = reconcile_findings(findings, boundaries, partitions)
    generate_report(reconciled)


if __name__ == "__main__":
    main()
