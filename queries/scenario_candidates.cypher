MATCH (scenario:GraphEntity:Scenario)-[:CKG_REL {kind:'TARGETS'}]->(target:GraphEntity {nodeId: $cve_id})
RETURN scenario
ORDER BY scenario.nodeId
LIMIT $limit
