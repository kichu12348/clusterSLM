import json
from typing import Dict, List, Any


def generate_report(
    reconciled_findings: List[Dict[str, Any]],
    bundle: Dict[str, Any],
    output_path: str = "clusterslm_report.json",
) -> Dict[str, Any]:
    """
    Generates the final evidence-backed vulnerability report and CLI summary.
    Separates confirmed findings from rejected hypotheses and unresolved investigations.
    """
    confirmed = [f for f in reconciled_findings if f.get("final_status") == "CONFIRMED"]
    rejected = [
        f for f in reconciled_findings if "REJECTED" in f.get("final_status", "")
    ]
    unresolved = [
        f for f in reconciled_findings if "UNRESOLVED" in f.get("final_status", "")
    ]

    report = {
        "project": "ClusterSLM",
        "repository": bundle.get("repository_name"),
        "metrics": bundle.get("overview", {}),
        "summary": {
            "total_hypotheses_evaluated": len(reconciled_findings),
            "confirmed_vulnerabilities": len(confirmed),
            "rejected_hypotheses": len(rejected),
            "unresolved_investigations": len(unresolved),
        },
        "confirmed_findings": confirmed,
        "unresolved_investigations": unresolved,
        "rejected_hypotheses": rejected,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("\n" + "=" * 72)
    print("CLUSTERSLM FINAL VERIFICATION REPORT")
    print("=" * 72)
    print(f"Artifact saved to        : {output_path}")
    print(f"Confirmed Vulnerabilities: {len(confirmed)}")
    print(f"Rejected Hypotheses      : {len(rejected)}")
    print(f"Unresolved Investigations: {len(unresolved)}")

    for i, issue in enumerate(confirmed, start=1):
        cwe = issue.get("cwe", "CWE-Unknown")
        vuln = issue.get("vulnerability", "Vulnerability")
        conf = int(float(issue.get("confidence", 0.0)) * 100)
        chain_type = (
            f"Cross-Cluster (Clusters {' -> '.join(map(str, issue['clusters_crossed']))})"
            if issue.get("cross_boundary")
            else f"Intra-Cluster (Cluster {issue.get('sink_cluster')})"
        )

        print(f"\n[{i}] {vuln} ({cwe}) — Confidence: {conf}%")
        print(
            f"    Sink Location : {issue.get('sink_symbol')} ({issue.get('sink_location')})"
        )
        print(f"    Scope / Chain : {chain_type}")
        print(
            f"    Call Path     : {' -> '.join(issue.get('verified_static_path', []))}"
        )
        if issue.get("guards_inspected"):
            print(f"    Safeguards    : {issue['guards_inspected']}")
        print(f"    Evidence      : {issue.get('evidence')}")
        if issue.get("path_uncertainties"):
            print(f"    Uncertainties : {issue['path_uncertainties']}")

    return report
