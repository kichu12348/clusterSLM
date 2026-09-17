import networkx as nx
from pathlib import Path


def get_module_name(file_path, repo_path):
    """
    Convert:
        Test/auth/authenticator.py
    into:
        Test.auth.authenticator
    """
    relative = file_path.relative_to(repo_path)
    parts = list(relative.parts)

    parts[-1] = parts[-1].removesuffix(".py")

    if parts[-1] == "__init__":
        parts.pop()

    return ".".join(parts)


def build_module_map(files, repo_path):
    module_map = {}
    for file in files:
        module_name = get_module_name(file.path, repo_path.parent)
        module_map[module_name] = file.path
    return module_map


def resolve_import(import_info, module_map, source_module):
    module = import_info.module
    level = import_info.level

    if level > 0:
        # Relative import: walk up `level` packages from the importing module
        parts = source_module.split(".")
        base = parts[:-level] if level <= len(parts) else []
        target = ".".join(base + [module]) if module else ".".join(base)
    else:
        target = module

    if target in module_map:
        return module_map[target]

    return None


def build_dependency_graph(files, repo_path):
    graph = nx.DiGraph()
    module_map = build_module_map(files, repo_path)

    for file in files:
        source_module = get_module_name(file.path, repo_path.parent)
        graph.add_node(source_module, path=str(file.path))

    for file in files:
        source_module = get_module_name(file.path, repo_path.parent)

        for import_info in file.imports:
            target_path = resolve_import(import_info, module_map, source_module)

            if target_path is None:
                continue

            target_module = get_module_name(target_path, repo_path.parent)
            graph.add_edge(source_module, target_module)

    return graph


def build_symbol_graph(edges):
    """
    Builds the Level-3 Function/Call Dependency Graph using NetworkX.
    """
    G = nx.DiGraph()
    
    # We filter out highly common built-ins so they don't skew the partitioning algorithm
    # (e.g., we don't want two unrelated functions clustered together just because they both call len())
    ignore_builtins = {'len', 'str', 'int', 'bool', 'isinstance', 'open', 'print', 'set', 'dict', 'join', 'lower', 'get', 'decode', 'encode'}
    
    for caller, callee in edges:
        if callee not in ignore_builtins:
            G.add_edge(caller, callee)
            
    return G


def print_graph(graph):
    print("\nDEPENDENCY GRAPH")
    print("=" * 60)
    print(f"Nodes: {graph.number_of_nodes()}")
    print(f"Edges: {graph.number_of_edges()}")
    print("\nDependencies:")

    for source, target in graph.edges():
        print(f"  {source} -> {target}")


import matplotlib.pyplot as plt


def plot_graph(graph):
    if graph.number_of_nodes() == 0:
        print("Nothing to plot — graph is empty.")
        return

    plt.figure(figsize=(12, 8))

    pos = nx.spring_layout(graph, k=0.6, seed=42)  # consistent layout

    nx.draw_networkx_nodes(graph, pos, node_size=1500, node_color="#8ecae6")
    nx.draw_networkx_edges(
        graph, pos, arrowstyle="-|>", arrowsize=15, edge_color="#555555"
    )
    nx.draw_networkx_labels(graph, pos, font_size=8)

    plt.title("Module Dependency Graph")
    plt.axis("off")
    plt.tight_layout()
    plt.show()

