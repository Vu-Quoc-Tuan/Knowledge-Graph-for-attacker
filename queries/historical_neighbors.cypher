// Source-specific candidate lists must be ranked before fusion by application code.
MATCH (cve:GraphEntity {nodeId: $cve_id})-[:CKG_REL {kind:'HAS_WEAKNESS_ASSERTION'}]->(:GraphEntity)-[:CKG_REL {kind:'MAPS_TO'}]->(cwe:GraphEntity)
MATCH (other:GraphEntity)-[:CKG_REL {kind:'HAS_WEAKNESS_ASSERTION'}]->(:GraphEntity)-[:CKG_REL {kind:'MAPS_TO'}]->(cwe)
WHERE other.nodeId <> cve.nodeId
RETURN DISTINCT other.nodeId AS vulnerability_id
ORDER BY vulnerability_id
LIMIT $top_k
