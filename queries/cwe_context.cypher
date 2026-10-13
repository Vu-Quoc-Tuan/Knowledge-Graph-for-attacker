MATCH (cwe:GraphEntity {nodeId: $cwe_id})<-[map:CKG_REL {kind:'MAPS_TO'}]-(assertion:GraphEntity)<-[has:CKG_REL]-(vulnerability:GraphEntity)
WHERE has.kind IN ['HAS_WEAKNESS_ASSERTION','HAS_TECHNIQUE_ASSERTION','HAS_CONTEXT_ASSERTION']
RETURN vulnerability, assertion, map
LIMIT $limit
