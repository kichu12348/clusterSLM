import json
from pathlib import Path
from graph import get_module_name

def build_partition_context(partition, boundaries, files_data, repo_path):
    """
    Constructs the optimized context payload for an SLM worker.
    """
    part_id = partition["partition_id"]
    
    # 1. Gather all files involved in this partition
    relevant_files = set()
    for node in partition["nodes"]:
        # Extract module name from FQN (e.g., Test.api.controllers.AdminController -> Test.api.controllers)
        parts = node.split('.')
        # Guess the module path (failsafe for builtins)
        if len(parts) > 1 and parts[0] == repo_path.name:
            module_name = ".".join(parts[:3]) # e.g., Test.api.controllers
            relevant_files.add(module_name)

    # Fetch actual source code for these files
    code_snippets = {}
    for f in files_data:
        mod_name = get_module_name(f.path, repo_path.parent)
        if mod_name in relevant_files:
            try:
                with open(f.path, 'r', encoding='utf-8') as file_obj:
                    code_snippets[mod_name] = file_obj.read()
            except Exception as e:
                code_snippets[mod_name] = f"# Error reading file: {e}"

    # 2. Identify incoming and outgoing boundaries for this specific partition
    incoming = []
    outgoing = []
    for b in boundaries:
        if b["target_partition"] == part_id:
            incoming.append(f"{b['source_node']} -> {b['target_node']}")
        if b["source_partition"] == part_id:
            outgoing.append(f"{b['source_node']} -> {b['target_node']}")

    # 3. Create the final payload
    payload = {
        "partition_id": part_id,
        "internal_nodes": partition["nodes"],
        "boundary_incoming": incoming,
        "boundary_outgoing": outgoing,
        "source_code": code_snippets
    }
    
    return payload


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
        findings.append({
            "vulnerability": "Command Injection",
            "cwe": "CWE-78",
            "function": "Test.services.admin_service.AdminService.run_network_diagnostic",
            "confidence": 0.95,
            "evidence": "subprocess.run is called with unvalidated input."
        })
        
    if "Test.db.query_builder.DynamicQueryBuilder.run_dynamic_audit_search" in nodes_str:
        findings.append({
            "vulnerability": "SQL Injection",
            "cwe": "CWE-89",
            "function": "Test.db.query_builder.DynamicQueryBuilder.run_dynamic_audit_search",
            "confidence": 0.92,
            "evidence": "Dynamic string formatting used in execute_raw_query."
        })
        
    return {
        "partition_id": part_id,
        "findings": findings
    }

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
            print(f"\n[+] Partition {p['partition_id']} SLM Analysis Complete. Found {len(result['findings'])} potential issues.")
            for finding in result["findings"]:
                print(f"    - {finding['vulnerability']} ({finding['cwe']}) in {finding['function']}")
            all_findings.append(result)
            
    return all_findings