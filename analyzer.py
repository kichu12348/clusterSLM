import json
import ast
from pathlib import Path
from graph import get_module_name


def extract_symbol_snippet(source_code, symbol_name):
    """
    Extracts only the specific class or function code block from source code using AST.
    """
    try:
        tree = ast.parse(source_code)
        target_name = symbol_name.split(".")[-1]

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.name == target_name:
                    lines = source_code.splitlines()
                    # ast line numbers are 1-indexed
                    start = node.lineno - 1
                    end = node.end_lineno
                    return "\n".join(lines[start:end])
    except Exception:
        pass
    return None


def build_partition_context(partition, boundaries, files_data, repo_path):
    """
    Constructs an optimized, symbol-level context payload for an SLM worker.
    """
    part_id = partition["partition_id"]

    # 1. Filter out built-ins and external calls; retain repository symbols only
    internal_symbols = [n for n in partition["nodes"] if n.startswith(repo_path.name)]

    # Map module names to raw source code
    file_sources = {}
    for f in files_data:
        mod_name = get_module_name(f.path, repo_path.parent)
        try:
            file_sources[mod_name] = Path(f.path).read_text(encoding="utf-8")
        except Exception:
            continue

    # 2. Extract ONLY the relevant function/class code snippets
    scoped_code = {}
    for sym in internal_symbols:
        parts = sym.split(".")
        # Determine the module part (e.g., Test.db.query_builder)
        for i in range(len(parts), 0, -1):
            possible_mod = ".".join(parts[:i])
            if possible_mod in file_sources:
                snippet = extract_symbol_snippet(file_sources[possible_mod], parts[-1])
                if snippet:
                    scoped_code[sym] = snippet
                break

    # 3. Boundaries
    incoming = [
        {
            "source": b["source_node"],
            "target": b["target_node"],
            "from_partition": b["source_partition"],
        }
        for b in boundaries
        if b["target_partition"] == part_id
    ]
    outgoing = [
        {
            "source": b["source_node"],
            "target": b["target_node"],
            "to_partition": b["target_partition"],
        }
        for b in boundaries
        if b["source_partition"] == part_id
    ]

    return {
        "partition_id": part_id,
        "internal_symbols": internal_symbols,
        "boundary_incoming": incoming,
        "boundary_outgoing": outgoing,
        "scoped_code": scoped_code,
    }


def export_partition_contexts(
    partitions, boundaries, files, repo_path, output_path="partition_contexts.json"
):
    contexts = []
    for p in partitions:
        ctx = build_partition_context(p, boundaries, files, repo_path)
        if ctx["scoped_code"]:  # Only export partitions with actual code definitions
            contexts.append(ctx)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(contexts, f, indent=2)

    print(f"\n[+] Exported {len(contexts)} focused partition contexts to {output_path}")
    return contexts


def mock_slm_worker(context_payload):
    """
    Simulates the SLM inference process.
    Eventually, this will be replaced with local model inference.
    """
    findings = []
    part_id = context_payload["partition_id"]
    nodes_str = str(context_payload["internal_nodes"])

    # HARDCODED MOCKS for testing the pipeline architecture
    if "Test.services.admin_service.AdminService.run_network_diagnostic" in nodes_str:
        findings.append(
            {
                "vulnerability": "Command Injection",
                "cwe": "CWE-78",
                "function": "Test.services.admin_service.AdminService.run_network_diagnostic",
                "confidence": 0.95,
                "evidence": "subprocess.run is called with unvalidated input.",
            }
        )

    if (
        "Test.db.query_builder.DynamicQueryBuilder.run_dynamic_audit_search"
        in nodes_str
    ):
        findings.append(
            {
                "vulnerability": "SQL Injection",
                "cwe": "CWE-89",
                "function": "Test.db.query_builder.DynamicQueryBuilder.run_dynamic_audit_search",
                "confidence": 0.92,
                "evidence": "Dynamic string formatting used in execute_raw_query.",
            }
        )

    return {"partition_id": part_id, "findings": findings}


def run_parallel_analysis(partitions, boundaries, files, repo_path):
    print("\n" + "=" * 50)
    print("PROCESS 4.0: PARALLEL SLM VULNERABILITY DETECTION (MOCKED)")
    print("=" * 50)

    all_findings = []

    for p in partitions:
        # Build context
        context = build_partition_context(p, boundaries, files, repo_path)

        # Pass to SLM
        result = mock_slm_worker(context)

        if result["findings"]:
            print(
                f"\n[+] Partition {p['partition_id']} SLM Analysis Complete. Found {len(result['findings'])} potential issues."
            )
            for finding in result["findings"]:
                print(
                    f"    - {finding['vulnerability']} ({finding['cwe']}) in {finding['function']}"
                )
            all_findings.append(result)

    return all_findings
