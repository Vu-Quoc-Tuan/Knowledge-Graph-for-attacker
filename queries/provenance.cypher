MATCH (subject:GraphEntity {nodeId: $subject_id})-[rel:CKG_REL]->(claim:GraphEntity)
WHERE rel.kind IN ['HAS_WEAKNESS_ASSERTION','HAS_TECHNIQUE_ASSERTION','HAS_CONTEXT_ASSERTION','SUPPORTED_BY']
OPTIONAL MATCH (claim)-[:CKG_REL {kind:'SUPPORTED_BY'}]->(evidence:GraphEntity)
RETURN subject, rel, claim, collect(evidence) AS evidence
