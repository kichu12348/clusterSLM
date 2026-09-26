import networkx as nx


def reconcile_findings(findings_list, boundaries, partitions):
    """
    Process 5.0: Boundary-Aware Reconciliation.
    Cross-references SLM findings with the cross-partition dependency graph
    by tracing paths through the partition's internal subgraph.
    """
    print("\n" + "=" * 50)
    print("PROCESS 5.0: BOUNDARY-AWARE RECONCILIATION")
    print("=" * 50)

    # Create a quick lookup for partitions
    partition_map = {p["partition_id"]: p for p in partitions}

    all_issues = []
    for f in findings_list:
        for issue in f["findings"]:
            issue["partition_id"] = f["partition_id"]
            all_issues.append(issue)

    reconciled_results = []

    for issue in all_issues:
        print(
            f"\nAnalyzing finding: {issue['vulnerability']} in {issue['symbol']} (Partition {issue['partition_id']})"
        )

        part_id = issue["partition_id"]
        target_func = issue["symbol"]
        subgraph = partition_map[part_id]["subgraph"]

        incoming_vectors = []

        # Scan all boundary edges that enter this partition
        for b in boundaries:
            if b["target_partition"] == part_id:
                entry_node = b["target_node"]

                # Check if there is a path from the boundary entry point to the vulnerability
                if entry_node in subgraph and target_func in subgraph:
                    if nx.has_path(subgraph, entry_node, target_func):
                        path = nx.shortest_path(subgraph, entry_node, target_func)
                        incoming_vectors.append(
                            {
                                "source_node": b["source_node"],
                                "source_partition": b["source_partition"],
                                "entry_node": entry_node,
                                "internal_path": path,
                            }
                        )

        if incoming_vectors:
            print("  [!] WARNING: Cross-Partition Vulnerability Chain Detected!")
            for v in incoming_vectors:
                print(
                    f"      Source: Partition {v['source_partition']} ({v['source_node']})"
                )
                print(f"      Entered Partition {part_id} at: {v['entry_node']}")
                print(f"      Internal Path to Sink: {' -> '.join(v['internal_path'])}")

            issue["cross_boundary"] = True
            issue["vectors"] = incoming_vectors
        else:
            print(
                "  [-] Localized vulnerability (No external partition triggers found)."
            )
            issue["cross_boundary"] = False

        reconciled_results.append(issue)

    return reconciled_results
