CREATE FULLTEXT INDEX ckg_v2_cwe_text IF NOT EXISTS
FOR (n:CWE) ON EACH [n.name, n.description];

CREATE FULLTEXT INDEX ckg_v2_vulnerability_text IF NOT EXISTS
FOR (n:CVE) ON EACH [n.title, n.description];
