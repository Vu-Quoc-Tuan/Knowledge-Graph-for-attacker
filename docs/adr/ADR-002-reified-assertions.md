# ADR-002: Reify vulnerability claims

CVE-to-CWE and CVE-to-technique mappings are represented by assertion nodes.
Direct edges cannot retain separate source, scope, evidence and confidence for
many-to-many mappings. Assertions also let conflicting source claims coexist.
