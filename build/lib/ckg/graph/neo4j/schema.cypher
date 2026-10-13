CREATE CONSTRAINT ckg_v2_node_id IF NOT EXISTS
FOR (n:GraphEntity) REQUIRE n.nodeId IS UNIQUE;

CREATE INDEX ckg_v2_node_kind IF NOT EXISTS
FOR (n:GraphEntity) ON (n.kind);
