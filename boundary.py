from collections import defaultdict

def find_boundaries(graph, partitions):
    """
    Identifies edges that cross partition boundaries.
    Returns a list of dictionaries containing the source/target nodes and their partition IDs.
    """
    # 1. Create a fast lookup mapping each node to its partition ID
    node_to_partition = {}
    for p in partitions:
        for node in p['nodes']:
            node_to_partition[node] = p['partition_id']

    boundaries = []

    # 2. Find edges where the source and target are in different partitions
    for u, v in graph.edges():
        part_u = node_to_partition.get(u)
        part_v = node_to_partition.get(v)

        # Skip if a node wasn't partitioned (a failsafe, shouldn't happen)
        if not part_u or not part_v:
            continue

        if part_u != part_v:
            boundaries.append({
                "source_node": u,
                "source_partition": part_u,
                "target_node": v,
                "target_partition": part_v
            })

    return boundaries

def print_boundaries(boundaries):
    print("\n" + "=" * 50)
    print("PROCESS 3.0/5.0: BOUNDARY IDENTIFICATION")
    print("=" * 50)
    
    print(f"\nDiscovered {len(boundaries)} cross-partition boundary edges.\n")

    # Group the edges by their partition pairs for readable output
    grouped = defaultdict(list)
    for b in boundaries:
        pair = (b['source_partition'], b['target_partition'])
        grouped[pair].append((b['source_node'], b['target_node']))

    for (p_src, p_tgt), edges in sorted(grouped.items()):
        print(f"Boundary: Partition {p_src} -> Partition {p_tgt}")
        for u, v in sorted(edges):
            print(f"  {u}\n    -> {v}")
        print()