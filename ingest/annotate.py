from db.sink import GraphSink


def mark_web_testable(sink: GraphSink) -> dict[str, int]:
    """Flag each Weakness by whether OWASP maps it to a WSTG test.

    A ``TESTED_BY`` edge means WSTG has a methodology for the weakness, i.e. it
    is web-testable. The many Top 25 entries without one (memory-safety,
    deserialization, ...) are marked ``webTestable=false`` so the graph states
    the absence of coverage rather than staying silent about it.

    Written against the sink primitives, so it holds identically on both the
    in-memory and Neo4j backends.
    """
    counts = {"web": 0, "non_web": 0}
    for node in sink.nodes("Weakness"):
        weakness_id = node["weaknessId"]
        tested = sink.match_rels(
            "TESTED_BY", from_label="Weakness", from_value=weakness_id
        )
        flag = bool(tested)
        sink.merge_node(
            "Weakness",
            "weaknessId",
            {"weaknessId": weakness_id, "webTestable": flag},
        )
        counts["web" if flag else "non_web"] += 1
    return counts
