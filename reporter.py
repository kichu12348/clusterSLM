import json


def generate_report(reconciled_findings, output_path="clusterslm_report.json"):
    """
    Process 6.0: Result Aggregation & Reporting.
    Generates the final vulnerability report and JSON artifact.
    """
    print("\n" + "=" * 50)
    print("PROCESS 6.0: RESULT AGGREGATION & REPORTING")
    print("=" * 50)

    report = {
        "project": "ClustersLM",
        "total_vulnerabilities": len(reconciled_findings),
        "findings": reconciled_findings,
    }

    # Write the machine-readable artifact
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    print(f"[+] Final report successfully generated: {output_path}")

    # Print a clean, human-readable summary for the CLI
    for i, issue in enumerate(reconciled_findings, 1):
        print(f"\n[{i}] {issue['vulnerability']} ({issue['cwe']})")
        print(f"    Confidence : {issue['confidence'] * 100}%")
        print(f"    Sink Point : {issue['symbol']} (Partition {issue['partition_id']})")

        if issue.get("cross_boundary"):
            print("    Chain Type : Cross-Partition")
            for vec in issue["vectors"]:
                print(
                    f"    Origin     : {vec['source_node']} (Partition {vec['source_partition']})"
                )
                print(f"    Path       : {' -> '.join(vec['internal_path'])}")
        else:
            print("    Chain Type : Localized")

        print(f"    Evidence   : {issue['evidence']}")

    return report
