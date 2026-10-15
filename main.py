import json
import sys
from pathlib import Path
from parser import parse_repository
from resolver import RepositoryResolver
from graph import build_repository_graph, summarize_graph_and_resolution
from partition import partition_repository_graph
from boundary import extract_boundary_contracts
from analyzer import export_repository_bundle
from retriever import BundleRetriever
from reconciler import reconcile_findings
from reporter import generate_report


def main():

    repo_path = Path("../Test").resolve()
    if not repo_path.exists():
        print(f"Error: Path does not exist: {repo_path}")
        return

    # 1. Milestone 1: Parse AST & Extract Evidence
    parse_results = parse_repository(repo_path)

    # 2. Milestone 2: Resolve Imports, Types & Call Graph
    resolver = RepositoryResolver(parse_results, repo_path)
    edges = resolver.resolve_all_calls()
    build_repository_graph(resolver.symbols, edges)
    res_stats = summarize_graph_and_resolution(resolver.symbols, edges)

    # 3. Milestone 3: Class-Atomic Vertical Clustering & Boundary Contracts
    clusters, cluster_metrics = partition_repository_graph(resolver.symbols, edges)
    boundaries = extract_boundary_contracts(resolver.symbols, edges)

    # 4. Milestone 4: Export Self-Contained Kaggle Bundle
    bundle = export_repository_bundle(
        repo_name=repo_path.name,
        symbols=resolver.symbols,
        edges=edges,
        clusters=clusters,
        boundaries=boundaries,
        resolution_stats=res_stats,
        cluster_metrics=cluster_metrics,
        output_path="repo_bundle.json",
    )

    retriever = BundleRetriever(bundle)

    print("\n" + "=" * 72)
    print("UPGRADED PASS 2 TRACE PACK (WITH 1-HOP HELPER & GUARD EXPANSION)")
    print("=" * 72)
    print(
        retriever.build_verification_trace_pack(
            "db.connection.DatabaseManager.execute_raw_query"
        )
    )

    # 5. Optional: Reconcile Kaggle Findings if present
    kaggle_file = Path.cwd() / "kaggle_findings.json"
    if "--reconcile" in sys.argv or kaggle_file.exists():
        if kaggle_file.exists():
            print(
                f"\n[+] Found {kaggle_file.name}. Running static provenance reconciliation..."
            )
            with open(kaggle_file, "r", encoding="utf-8") as f:
                raw_findings = json.load(f)
            reconciled = reconcile_findings(raw_findings, bundle)
            generate_report(reconciled, bundle)
        else:
            print(
                f"\n[!] No {kaggle_file.name} found yet. Run the 2-pass notebook on Kaggle first."
            )


if __name__ == "__main__":
    main()
