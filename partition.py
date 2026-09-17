import networkx as nx
from networkx.algorithms.community import greedy_modularity_communities

def partition_graph(graph):
    """
    Process 3.0: Graph-Guided Repository Partitioning.
    Uses modularity-based community detection to find natural clusters.
    """
    # Community detection algorithms generally require an undirected graph
    undirected_graph = graph.to_undirected()

    # Discover communities based purely on edge density
    communities = greedy_modularity_communities(undirected_graph)

    partitions = []
    for i, comm in enumerate(communities):
        # Extract the directed subgraph for this partition
        subgraph = graph.subgraph(comm).copy()
        partitions.append({
            "partition_id": i + 1,
            "nodes": list(comm),
            "subgraph": subgraph
        })

    return partitions

def print_partitions(partitions):
    print("\n" + "=" * 50)
    print("PROCESS 3.0: GRAPH-GUIDED PARTITIONS")
    print("=" * 50)
    
    for p in partitions:
        print(f"\nPartition {p['partition_id']} ({len(p['nodes'])} nodes):")
        # Print sorted nodes so it's easy to read
        for node in sorted(p['nodes']):
            print(f"  - {node}")