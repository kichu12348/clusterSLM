import json
from pathlib import Path
from typing import Dict, List, Optional, Any
import networkx as nx


class BundleRetriever:
    """
    Self-contained query and prompt-context builder over `repo_bundle.json`.
    Designed to run identically on your local machine and inside a Kaggle notebook:
      - Pass 1 (Discovery): Renders compact Cluster Maps for the SLM.
      - Pass 2 (Verification): Traces intra- and cross-cluster call paths and
        assembles exact line-numbered source code + boundary guard contracts.
    """

    def __init__(self, bundle_data: Dict[str, Any]):
        self.bundle = bundle_data
        self.symbols: Dict[str, Dict[str, Any]] = bundle_data["symbol_index"]
        self.clusters: Dict[int, Dict[str, Any]] = {
            c["cluster_id"]: c for c in bundle_data["discovery_clusters"]
        }

        # Build a directed call graph for shortest-path / call-chain retrieval
        self.call_graph = nx.DiGraph()
        for sid in self.symbols:
            self.call_graph.add_node(sid)
        for edge in bundle_data["edges"]:
            if edge["kind"] == "CALLS":
                self.call_graph.add_edge(
                    edge["source"],
                    edge["target"],
                    confidence=edge["confidence"],
                    line=edge["line"],
                )

    @classmethod
    def from_file(cls, path: str | Path) -> "BundleRetriever":
        with open(path, "r", encoding="utf-8") as f:
            return cls(json.load(f))

    # ------------------------------------------------------------------
    # Pass 1: Discovery Cluster Map Renderer
    # ------------------------------------------------------------------
    def format_cluster_discovery_view(self, cluster_id: int) -> str:
        """
        Renders a structured, token-efficient Discovery Map for a single cluster.
        Provides the SLM with signatures, guards, dynamic taint facts, external calls,
        and cross-cluster boundary contracts BEFORE requesting raw source code.
        """
        c = self.clusters[cluster_id]
        lines = [
            f"=== CLUSTER {c['cluster_id']}: {c['label']} ===",
            f"Modules Covered      : {', '.join(c['modules_covered'])}",
            f"Cluster Entry Points : {', '.join(c['entry_points']) or 'None (Internal/Service Cluster)'}",
            "",
            "--- 1. INTERNAL SYMBOL CARDS ---",
        ]

        for card in c["symbol_cards"]:
            if card["kind"] == "class":
                lines.append(f"\nCLASS ({card['location']}) -> {card['signature']}")
                if card["dynamic_expressions"]:
                    lines.append(
                        f"  Class Constants/Dynamic: {card['dynamic_expressions']}"
                    )
                continue

            lines.append(
                f"\n[{card['kind'].upper()}] {card['id']} ({card['location']})"
            )
            lines.append(f"  Signature : {card['signature']}")
            if card["guards"]:
                lines.append(f"  Guards    : {card['guards']}")
            if card["dynamic_expressions"]:
                lines.append(f"  Dynamic   : {card['dynamic_expressions']}")
            if card["calls_external"]:
                ext_strs = [
                    f"L{ec['line']}: {ec['call']}"
                    + (" [DYNAMIC_ARG!]" if ec["is_dynamic_arg"] else "")
                    for ec in card["calls_external"]
                ]
                lines.append(f"  Ext Calls : {ext_strs}")
            if card["calls_internal"]:
                int_strs = [
                    f"L{ic['line']} -> {ic['target']} (C{ic['target_cluster']}, {ic['confidence']})"
                    + (" [DYNAMIC_ARG!]" if ic["is_dynamic_arg"] else "")
                    for ic in card["calls_internal"]
                ]
                lines.append(f"  Int Calls : {int_strs}")

        if c["boundary_incoming"]:
            lines.append(
                "\n--- 2. INCOMING CROSS-CLUSTER BOUNDARIES (Who calls into this cluster) ---"
            )
            for b in c["boundary_incoming"]:
                dyn = " [DYNAMIC_ARG!]" if b["is_dynamic_arg"] else ""
                lines.append(
                    f"  * [From C{b['source_cluster']}] {b['source_symbol']} --(L{b['line']})--> "
                    f"{b['target_symbol']}({b['args_preview']}){dyn}"
                )
                if b["caller_guards"]:
                    lines.append(f"      Caller Pre-Guards: {b['caller_guards']}")

        if c["boundary_outgoing"]:
            lines.append(
                "\n--- 3. OUTGOING CROSS-CLUSTER BOUNDARIES (What this cluster calls externally) ---"
            )
            for b in c["boundary_outgoing"]:
                dyn = " [DYNAMIC_ARG!]" if b["is_dynamic_arg"] else ""
                lines.append(
                    f"  * [To C{b['target_cluster']}] {b['source_symbol']} --(L{b['line']})--> "
                    f"{b['target_symbol']}({b['args_preview']}){dyn}"
                )
                lines.append(f"      Target Signature : {b['target_signature']}")
                if b["target_guards"]:
                    lines.append(f"      Target Guards    : {b['target_guards']}")
                if b["target_external_calls"]:
                    lines.append(
                        f"      Target Ext Sinks : {b['target_external_calls']}"
                    )

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Pass 2: Verification Call-Chain & Source Code Retriever
    # ------------------------------------------------------------------
    def build_verification_trace_pack(
        self,
        target_sink_symbol: str,
        entry_or_caller_symbol: Optional[str] = None,
        max_upstream_depth: int = 4,
    ) -> str:
        """
        Builds a complete Phase 2 Verification Trace Pack for a suspected sink symbol:
          1. Traces upstream caller chains back to entry points across clusters.
          2. Expands 1-hop side-call helpers (functions called along the path that
             construct dynamic data or perform guard/permission checks).
          3. Renders ordered, line-numbered source code for the path + its helpers.
        """
        if target_sink_symbol not in self.symbols:
            return f"[!] Unknown symbol: {target_sink_symbol}"

        paths_to_verify: List[List[str]] = []

        if entry_or_caller_symbol and entry_or_caller_symbol in self.call_graph:
            if nx.has_path(self.call_graph, entry_or_caller_symbol, target_sink_symbol):
                paths_to_verify.append(
                    nx.shortest_path(
                        self.call_graph, entry_or_caller_symbol, target_sink_symbol
                    )
                )

        if not paths_to_verify:
            paths_to_verify = self._find_upstream_chains(
                target_sink_symbol, max_upstream_depth
            )

        # Collect primary path symbols and expand relevant 1-hop helper/guard callees
        ordered_symbols: List[str] = []
        helper_roles: Dict[str, str] = {}

        for path in paths_to_verify:
            for sid in path:
                if sid not in ordered_symbols:
                    ordered_symbols.append(sid)

                sym = self.symbols[sid]
                guard_lines = {g["line"] for g in sym.get("guards", [])}

                # Inspect outgoing internal calls from `sid` for dynamic helpers or guard functions
                for succ in self.call_graph.successors(sid):
                    if succ in path or succ.endswith(".__init__"):
                        continue
                    edge_data = self.call_graph.get_edge_data(sid, succ) or {}
                    call_line = edge_data.get("line", -1)
                    succ_sym = self.symbols.get(succ, {})

                    is_guard_callee = call_line in guard_lines or any(
                        tok in succ.lower()
                        for tok in (
                            "has_role",
                            "check_permission",
                            "validate",
                            "verify",
                            "sanitize",
                        )
                    )
                    is_dynamic_helper = bool(
                        succ_sym.get("returns_dynamic")
                        or succ_sym.get("dynamic_locals")
                    )

                    if is_guard_callee or is_dynamic_helper:
                        role_label = (
                            "GUARD HELPER" if is_guard_callee else "DATA/QUERY HELPER"
                        )
                        helper_roles[succ] = (
                            f"{role_label} called by {sid} at L{call_line}"
                        )
                        if succ not in ordered_symbols:
                            ordered_symbols.append(succ)

        lines = [
            "=" * 72,
            f"VERIFICATION TRACE PACK FOR TARGET: {target_sink_symbol}",
            "=" * 72,
            "Discovered Call Path(s) Across Repository:",
        ]

        for idx, path in enumerate(paths_to_verify, start=1):
            hops = []
            for i in range(len(path)):
                sid = path[i]
                cid = self.symbols[sid].get("cluster_id")
                hop_str = f"{sid} [C{cid}]"
                if i < len(path) - 1:
                    edge_data = self.call_graph.get_edge_data(sid, path[i + 1]) or {}
                    conf = edge_data.get("confidence", "EXACT")
                    ln = edge_data.get("line", "?")
                    hop_str += f" --(L{ln}, {conf})--> "
                hops.append(hop_str)
            lines.append(f"  Path {idx}: " + "".join(hops))

        if helper_roles:
            lines.append("\nAttached Side-Call Helpers / Guards Along Path:")
            for h_sid, desc in helper_roles.items():
                lines.append(f"  + {h_sid} ({desc})")

        lines.append("\n--- EXACT LINE-NUMBERED SOURCE CODE ALONG PATH ---")
        for sid in ordered_symbols:
            sym = self.symbols[sid]
            role_tag = (
                f" | {helper_roles[sid]}"
                if sid in helper_roles
                else " | PRIMARY PATH NODE"
            )
            lines.append(
                f"\n>>> [{sym['kind'].upper()}] {sid} (Cluster {sym['cluster_id']} | "
                f"{sym['file_path']}:{sym['start_line']}-{sym['end_line']}{role_tag})"
            )
            if sym["guards"]:
                lines.append(
                    "    Extracted Guards: "
                    + ", ".join(f"L{g['line']} {g['preview']}" for g in sym["guards"])
                )
            lines.append(sym["source_code"])

        return "\n".join(lines)

    def _find_upstream_chains(
        self, target_symbol: str, max_depth: int
    ) -> List[List[str]]:
        chains: List[List[str]] = []

        def dfs(current_path: List[str], depth: int):
            head = current_path[0]
            callers = [
                pred
                for pred in self.call_graph.predecessors(head)
                if pred not in current_path and not pred.endswith(".__init__")
            ]
            if not callers or depth >= max_depth:
                chains.append(current_path)
                return
            for caller in callers:
                dfs([caller] + current_path, depth + 1)

        dfs([target_symbol], 0)
        return chains
