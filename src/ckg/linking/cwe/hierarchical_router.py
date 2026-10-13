from ckg.graph.ports import GraphRepository


def canonical_neighbors(repository: GraphRepository, cwe_id: str) -> tuple[str, ...]:
    allowed = {"CHILD_OF", "PARENT_OF", "PEER_OF", "CAN_ALSO_BE"}
    found = set()
    for edge in repository.edges():
        if edge.edge_type not in allowed:
            continue
        if edge.subject_id == cwe_id:
            found.add(edge.object_id)
        elif edge.object_id == cwe_id:
            found.add(edge.subject_id)
    return tuple(sorted(found))
