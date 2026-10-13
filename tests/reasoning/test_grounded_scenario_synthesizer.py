from __future__ import annotations

from ckg.domain.enums.scenario_type import ScenarioType
from ckg.graph.memory import InMemoryGraphRepository
from ckg.graph.models import GraphEdge, GraphNode
from ckg.ingestion.wstg.catalog import (
    CANONICAL_CONSTRAINTS,
    CANONICAL_WSTG_STRATEGIES,
    build_canonical_wstg_nodes_and_edges,
    import_canonical_wstg_catalog,
)
from ckg.reasoning.subgraph.builder import build_local_subgraph
from ckg.scenario.discoverer import discover_scenarios
from ckg.scenario.synthesizer import synthesized_scenarios


def _node(label: str, node_id: str, **props: object) -> GraphNode:
    return GraphNode(label=label, node_id=node_id, props=dict(props))


def _edge(edge_id: str, edge_type: str, subject_id: str, object_id: str, **props: object) -> GraphEdge:
    return GraphEdge(edge_id=edge_id, edge_type=edge_type, subject_id=subject_id, object_id=object_id, props=dict(props))


def test_missing_target_evidence_cannot_borrow_neighbors_weakness_as_novel() -> None:
    repo = InMemoryGraphRepository()
    repo.atomic_write(nodes=[
        _node("CVE", "CVE-2026-10001", title="Target path traversal"),
        _node("WeaknessAssertion", "WAS-TARGET", evidence_spans=[{"evidence_id": "EVID-MISSING"}], all_source_snapshots_available=False),
        _node("CWE", "CWE-22"),
        _node("CVE", "CVE-2026-10002", title="SQL injection /login.php"),
        _node("WeaknessAssertion", "WAS-NEIGHBOR"),
        _node("CWE", "CWE-89"),
    ], edges=[
        _edge("a", "HAS_WEAKNESS_ASSERTION", "CVE-2026-10001", "WAS-TARGET"),
        _edge("b", "MAPS_TO", "WAS-TARGET", "CWE-22"),
        _edge("c", "HAS_WEAKNESS_ASSERTION", "CVE-2026-10002", "WAS-NEIGHBOR"),
        _edge("d", "MAPS_TO", "WAS-NEIGHBOR", "CWE-89"),
        _edge("e", "SIMILAR_TO", "CVE-2026-10001", "CVE-2026-10002"),
    ])
    import_canonical_wstg_catalog(repo)

    candidates = discover_scenarios(repo, "CVE-2026-10001")
    assert not [candidate for candidate in candidates if candidate.scenario.scenario_type == ScenarioType.NOVEL]
    assert all("CWE-89" not in candidate.scenario.weakness_ids for candidate in candidates)


def test_synthesized_candidate_reports_only_present_target_evidence() -> None:
    repo = InMemoryGraphRepository()
    repo.atomic_write(nodes=[
        _node("CVE", "CVE-2026-10001", title="SQL injection in /login.php via id parameter"),
        _node("WeaknessAssertion", "WAS-1", evidence_spans=[{"evidence_id": "EVID-1"}]),
        _node("Evidence", "EVID-1", content_digest="sha256:" + "a" * 64),
        _node("CWE", "CWE-89"),
    ], edges=[
        _edge("a", "HAS_WEAKNESS_ASSERTION", "CVE-2026-10001", "WAS-1"),
        _edge("b", "MAPS_TO", "WAS-1", "CWE-89"),
        _edge("c", "SUPPORTED_BY", "WAS-1", "EVID-1"),
    ])
    import_canonical_wstg_catalog(repo)

    candidates = discover_scenarios(repo, "CVE-2026-10001")
    assert candidates
    assert all(candidate.evidence_ids == ("EVID-1",) for candidate in candidates)
    assert all(candidate.scenario.confidence.evidence_coverage > 0 for candidate in candidates)


def test_canonical_wstg_catalog_generation_and_import() -> None:
    repo = InMemoryGraphRepository()
    count = import_canonical_wstg_catalog(repo)
    assert count == len(CANONICAL_WSTG_STRATEGIES)
    assert len(repo.nodes("TestStrategy")) == len(CANONICAL_WSTG_STRATEGIES)
    assert len(repo.nodes("ApplicabilityConstraint")) == len(CANONICAL_CONSTRAINTS)
    assert len(repo.nodes("Technique")) >= 4
    assert len(repo.nodes("Oracle")) >= 2
    assert len(repo.nodes("InputSurface")) >= 3


def test_subgraph_builder_includes_test_strategies_and_constraints() -> None:
    repo = InMemoryGraphRepository()
    # Populate CWE-89 first so WSTG import links to it
    repo.atomic_write(
        nodes=[
            _node("CWE", "CWE-89"),
            _node("CVE", "CVE-2026-9000", title="Test SQLi", description="SQL injection vulnerability in /search.php via q parameter."),
            _node("WeaknessAssertion", "WAS-9000"),
        ],
        edges=[
            _edge("e1", "HAS_WEAKNESS_ASSERTION", "CVE-2026-9000", "WAS-9000"),
            _edge("e2", "MAPS_TO", "WAS-9000", "CWE-89"),
        ],
    )
    import_canonical_wstg_catalog(repo)

    subgraph = build_local_subgraph(repo, "CVE-2026-9000")
    node_ids = {n.node_id for n in subgraph.nodes}
    assert "CVE-2026-9000" in node_ids
    assert "CWE-89" in node_ids
    assert "TSTRAT-WSTG-INPV-05" in node_ids
    assert "TECH-ERROR_BASED" in node_ids
    assert "CHANNEL-HTTP" in node_ids
    assert "CONSTRAINT-SQL-BACKEND" in node_ids


def test_grounded_scenario_synthesizer_extracts_cve_artifacts() -> None:
    repo = InMemoryGraphRepository()
    desc = (
        "Affected by this issue is the function article::getDataOfJson of the file "
        "/index.php?m=content&f=article&v=getDataOfJson. The manipulation of the argument "
        "title/master_table leads to sql injection. Remote exploitation is possible."
    )
    repo.atomic_write(
        nodes=[
            _node("CWE", "CWE-89"),
            _node("CVE", "CVE-2026-9184", title="WuzhiCMS SQLi", description=desc),
            _node("WeaknessAssertion", "WAS-9184"),
        ],
        edges=[
            _edge("e1", "HAS_WEAKNESS_ASSERTION", "CVE-2026-9184", "WAS-9184"),
            _edge("e2", "MAPS_TO", "WAS-9184", "CWE-89"),
        ],
    )
    import_canonical_wstg_catalog(repo)

    candidates = synthesized_scenarios(repo, "CVE-2026-9184")
    assert len(candidates) >= 2

    # Check that concrete parameters and endpoints are present in missing bindings
    first = candidates[0]
    assert "endpoint=/index.php?m=content&f=article&v=getDataOfJson" in first.missing_bindings
    assert "parameter:title" in first.missing_bindings
    assert "parameter:master_table" in first.missing_bindings
    assert "function:article::getDataOfJson" in first.missing_bindings

    # Check that constraints are attached
    assert "CONSTRAINT-REMOTE-NETWORK-REACHABLE" in first.scenario.constraint_ids
    assert "CONSTRAINT-HTTP-SERVICE-REACHABLE" in first.scenario.constraint_ids
    assert "CONSTRAINT-SQL-BACKEND" in first.scenario.constraint_ids


def test_discover_scenarios_produces_both_transferred_and_synthesized() -> None:
    repo = InMemoryGraphRepository()
    desc = "A hard-coded credentials flaw allows access to ftpd service as root where FTP is reachable."
    repo.atomic_write(
        nodes=[
            _node("CWE", "CWE-798"),
            _node("CVE", "CVE-2026-68950", title="Hardcoded FTP", description=desc),
            _node("WeaknessAssertion", "WAS-68950"),
        ],
        edges=[
            _edge("e1", "HAS_WEAKNESS_ASSERTION", "CVE-2026-68950", "WAS-68950"),
            _edge("e2", "MAPS_TO", "WAS-68950", "CWE-798"),
        ],
    )
    import_canonical_wstg_catalog(repo)

    results = discover_scenarios(repo, "CVE-2026-68950")
    assert len(results) >= 2

    # One transferred WSTG-ATHN-06 strategy
    transferred = [c for c in results if "TSTRAT-WSTG-ATHN-06" in c.scenario.derivation_ids and not c.scenario.constraint_ids]
    assert len(transferred) >= 1

    # One synthesized scenario with FTP service constraints and bindings
    synthesized = [c for c in results if "CONSTRAINT-FTP-SERVICE-REACHABLE" in c.scenario.constraint_ids]
    assert len(synthesized) >= 1
    assert "service:ftpd" in synthesized[0].missing_bindings


def test_synthesizer_login_form_semantics_and_post_error_based_poc() -> None:
    repo = InMemoryGraphRepository()
    desc = (
        "SQL Injection vulnerability in doctorlogin.php via doc_mail and doc_pswd parameters "
        "allows remote unauthenticated attackers to bypass authentication or extract sensitive database information."
    )
    repo.atomic_write(
        nodes=[
            _node("CWE", "CWE-89"),
            _node("CVE", "CVE-2026-90805", title="Doctor Login SQLi", description=desc),
            _node("WeaknessAssertion", "WAS-90805"),
        ],
        edges=[
            _edge("e1", "HAS_WEAKNESS_ASSERTION", "CVE-2026-90805", "WAS-90805"),
            _edge("e2", "MAPS_TO", "WAS-90805", "CWE-89"),
        ],
    )
    import_canonical_wstg_catalog(repo)

    candidates = synthesized_scenarios(repo, "CVE-2026-90805")
    assert len(candidates) >= 3  # Error-based, Time-based, Auth-bypass

    # Check endpoint extraction properly extracted doctorlogin.php
    first = candidates[0]
    assert "endpoint=/doctorlogin.php" in first.missing_bindings
    assert "parameter:doc_mail" in first.missing_bindings
    assert "parameter:doc_pswd" in first.missing_bindings

    # Find the Error-based candidate and verify POST + ExtractValue PoC
    error_c = next(c for c in candidates if "TECH-ERROR_BASED" in c.scenario.technique_ids)
    assert "-X POST" in error_c.scenario.poc_command
    assert "doctorlogin.php" in error_c.scenario.poc_command
    assert "extractvalue" in error_c.scenario.poc_command
    assert "-d \"doc_mail=" in error_c.scenario.poc_command

    # Find the Auth-bypass candidate
    auth_c = next(c for c in candidates if "TECH-BOOLEAN_BASED" in c.scenario.technique_ids)
    assert "Form Đăng Nhập" in auth_c.scenario.title or "Vượt Qua Xác Thực" in auth_c.scenario.title
    assert "-X POST" in auth_c.scenario.poc_command
    assert "1%3D1" in auth_c.scenario.poc_command


def test_synthesizer_mssql_unauthenticated_fixed_param_cve_2024_58385() -> None:
    repo = InMemoryGraphRepository()
    desc = (
        "Yonyou U8 CRM contains an unauthenticated SQL injection vulnerability in the "
        "fillbacksettingedit.php configuration endpoint where the DontCheckLogin=1 parameter "
        "bypasses authentication and the id parameter is incorporated into SQL queries without sanitization. "
        "Attackers can exploit this flaw to execute arbitrary SQL commands and, on Microsoft SQL Server deployments "
        "with xp_cmdshell enabled, write backdoor files and execute arbitrary operating system commands. "
        "Exploitation evidence was first observed by the Shadowserver Foundation on 2025-02-13."
    )
    repo.atomic_write(
        nodes=[
            _node("CWE", "CWE-89"),
            _node("CVE", "CVE-2024-58385", title="Yonyou U8 CRM SQLi", description=desc),
            _node("WeaknessAssertion", "WAS-58385"),
        ],
        edges=[
            _edge("e1", "HAS_WEAKNESS_ASSERTION", "CVE-2024-58385", "WAS-58385"),
            _edge("e2", "MAPS_TO", "WAS-58385", "CWE-89"),
        ],
    )
    import_canonical_wstg_catalog(repo)

    candidates = synthesized_scenarios(repo, "CVE-2024-58385")
    # Only Error-based and Time-based, no Auth-bypass since this is not a login form
    assert len(candidates) == 2

    # Check extracted bindings
    first = candidates[0]
    assert "endpoint=/fillbacksettingedit.php" in first.missing_bindings
    assert "parameter:id" in first.missing_bindings
    assert "fixed_parameter:DontCheckLogin=1" in first.missing_bindings
    assert "parameter:bypasses" not in first.missing_bindings

    # Error-based candidate: MSSQL CONVERT, target param id, fixed param DontCheckLogin=1
    error_c = next(c for c in candidates if "TECH-ERROR_BASED" in c.scenario.technique_ids)
    assert "DontCheckLogin=1" in error_c.scenario.poc_command
    assert "id=1%27%20AND%201%3DCONVERT(int%2C%20(SELECT%20%40%40version))--" in error_c.scenario.poc_command
    assert "extractvalue" not in error_c.scenario.poc_command
    assert "bypasses" not in error_c.scenario.poc_command

    # Time-based candidate: MSSQL WAITFOR DELAY, stacked query syntax
    time_c = next(c for c in candidates if "TECH-TIME_BASED" in c.scenario.technique_ids)
    assert "DontCheckLogin=1" in time_c.scenario.poc_command
    assert "id=1%27%3B%20WAITFOR%20DELAY%20%270%3A0%3A5%27--" in time_c.scenario.poc_command
    assert "SLEEP" not in time_c.scenario.poc_command
    assert "bypasses" not in time_c.scenario.poc_command


def test_synthesizer_unbound_parameter_and_endpoint_consistency() -> None:
    repo = InMemoryGraphRepository()
    desc = (
        "GitLab has remediated an issue in GitLab CE/EE affecting all versions from 15.3 before 19.1.8, "
        "19.2 before 19.2.6, and 19.3 before 19.3.2 that, under certain conditions, an authenticated user "
        "could have induced a targeted user to perform unintended state-changing HTTP requests due to "
        "improper sanitization of user-controlled data in the Markdown JSON table renderer."
    )
    repo.atomic_write(
        nodes=[
            _node("CWE", "CWE-79"),
            _node("CVE", "CVE-2026-78252", title="GitLab Markdown Table XSS", description=desc),
            _node("WeaknessAssertion", "WAS-78252"),
        ],
        edges=[
            _edge("e1", "HAS_WEAKNESS_ASSERTION", "CVE-2026-78252", "WAS-78252"),
            _edge("e2", "MAPS_TO", "WAS-78252", "CWE-79"),
        ],
    )
    import_canonical_wstg_catalog(repo)

    candidates = synthesized_scenarios(repo, "CVE-2026-78252")
    assert len(candidates) >= 1
    cand = candidates[0]

    # Verify missing bindings accurately identify unbound input and endpoint
    assert "input_binding" in cand.missing_bindings
    assert "target_endpoint" in cand.missing_bindings

    # Steps and PoC must be internally consistent: NO hallucinated 'id', 'q', or '/index.php'
    steps_text = " ".join(cand.scenario.steps)
    poc = cand.scenario.poc_command

    assert "tham số 'id'" not in steps_text
    assert "<INPUT_PARAM>" in steps_text
    assert "/<TARGET_ENDPOINT>" in steps_text

    assert "q=" not in poc
    assert "/index.php" not in poc
    assert "<INPUT_PARAM>" in poc
    assert "/<TARGET_ENDPOINT>" in poc
    assert "LƯU Ý" in poc


def test_synthesizer_container_breakout_and_access_control() -> None:
    repo = InMemoryGraphRepository()
    repo.atomic_write(
        nodes=[
            _node("CWE", "CWE-403"),
            _node("CWE", "CWE-639"),
            _node("CWE", "CWE-352"),
            _node(
                "CVE",
                "CVE-2024-21626",
                title="Container Breakout via Leaked File Descriptor in runc",
                description="runc 1.0.0-rc93 through 1.1.11 leaks an internal file descriptor into the container execution context, allowing attackers to access host filesystem.",
            ),
            _node(
                "CVE",
                "CVE-2026-63901",
                title="IDOR in user profile endpoint",
                description="Insecure direct object reference in /api/users via user_id parameter allows reading records of other users.",
            ),
            _node(
                "CVE",
                "CVE-2026-35201",
                title="CSRF in password reset",
                description="Cross-site request forgery in /account/reset allows state-changing requests via victim session.",
            ),
            _node("WeaknessAssertion", "WAS-403"),
            _node("WeaknessAssertion", "WAS-639"),
            _node("WeaknessAssertion", "WAS-352"),
        ],
        edges=[
            _edge("e1", "HAS_WEAKNESS_ASSERTION", "CVE-2024-21626", "WAS-403"),
            _edge("e2", "MAPS_TO", "WAS-403", "CWE-403"),
            _edge("e3", "HAS_WEAKNESS_ASSERTION", "CVE-2026-63901", "WAS-639"),
            _edge("e4", "MAPS_TO", "WAS-639", "CWE-639"),
            _edge("e5", "HAS_WEAKNESS_ASSERTION", "CVE-2026-35201", "WAS-352"),
            _edge("e6", "MAPS_TO", "WAS-352", "CWE-352"),
        ],
    )
    import_canonical_wstg_catalog(repo)

    # 1. Container breakout
    runc_candidates = synthesized_scenarios(repo, "CVE-2024-21626")
    assert len(runc_candidates) >= 1
    runc_s = runc_candidates[0].scenario
    assert "Container Breakout" in runc_s.title
    assert "CONSTRAINT-CONTAINER-ENVIRONMENT" in runc_s.constraint_ids
    assert "CONSTRAINT-LOCAL-PROCESS-EXECUTION" in runc_s.constraint_ids
    assert "/proc/self/fd/" in runc_s.poc_command

    # 2. IDOR / Access Control
    idor_candidates = synthesized_scenarios(repo, "CVE-2026-63901")
    assert len(idor_candidates) >= 1
    idor_s = idor_candidates[0].scenario
    assert "IDOR" in idor_s.title
    assert "user_id" in idor_s.title
    assert "CONSTRAINT-AUTHENTICATED-SESSION" in idor_s.constraint_ids
    assert "Authorization: Bearer" in idor_s.poc_command

    # 3. CSRF
    csrf_candidates = synthesized_scenarios(repo, "CVE-2026-35201")
    assert len(csrf_candidates) >= 1
    csrf_s = csrf_candidates[0].scenario
    assert "CSRF" in csrf_s.title
    assert "CONSTRAINT-AUTHENTICATED-SESSION" in csrf_s.constraint_ids
    assert "<form id=\"csrfForm\"" in csrf_s.poc_command


def test_ranker_prioritizes_rich_scenarios_over_empty_skeletons() -> None:
    from ckg.domain.entities.scenario import Scenario
    from ckg.domain.enums.applicability import Applicability
    from ckg.domain.enums.fact_status import FactStatus
    from ckg.domain.value_objects.confidence import Confidence
    from ckg.scenario.contract import ScenarioCandidate
    from ckg.scenario.ranker import rank

    empty_skeleton = ScenarioCandidate(
        scenario=Scenario(
            scenario_id="SCN-0001-empty",
            scenario_type=ScenarioType.INHERITED,
            status=FactStatus.INFERRED,
            target_vulnerability_id="CVE-2026-1000",
            weakness_ids=("CWE-89",),
            applicability=Applicability.UNKNOWN,
            confidence=Confidence(relevance=0.7, evidence_coverage=0.45, final=0.45),
            derivation_ids=("SRC-1",),
            steps=(),
        ),
        premises=("shared weakness",),
    )
    rich_scenario = ScenarioCandidate(
        scenario=Scenario(
            scenario_id="SCN-9999-rich",
            scenario_type=ScenarioType.NOVEL,
            status=FactStatus.INFERRED,
            target_vulnerability_id="CVE-2026-1000",
            weakness_ids=("CWE-89",),
            applicability=Applicability.UNKNOWN,
            confidence=Confidence(relevance=0.7, evidence_coverage=0.45, final=0.45),
            derivation_ids=("SRC-2",),
            title="Rich Scenario with Steps",
            steps=("Step 1", "Step 2"),
            poc_command="curl ...",
        ),
        premises=("grounded synthesis",),
    )

    ranked = rank((empty_skeleton, rich_scenario))
    assert ranked[0].scenario.scenario_id == "SCN-9999-rich"
    assert len(ranked[0].scenario.steps) > 0


def test_order_by_sqli_synthesis_and_endpoint_subsumption() -> None:
    repo = InMemoryGraphRepository()
    desc = (
        "A vulnerability was identified in zyx0814 FilePress up to 3.0.1. "
        "This vulnerability affects unknown code of the file dzz/publish/search.php of the component Publish Module. "
        "Such manipulation of the argument orderby/order leads to sql injection. The attack can be launched remotely."
    )
    repo.atomic_write(
        nodes=[
            _node("CWE", "CWE-89"),
            _node("CVE", "CVE-2026-90879", title="zyx0814 FilePress Publish search.php sql injection", description=desc),
            _node("WeaknessAssertion", "WAS-90879"),
        ],
        edges=[
            _edge("e1", "HAS_WEAKNESS_ASSERTION", "CVE-2026-90879", "WAS-90879"),
            _edge("e2", "MAPS_TO", "WAS-90879", "CWE-89"),
        ],
    )
    import_canonical_wstg_catalog(repo)

    candidates = synthesized_scenarios(repo, "CVE-2026-90879")
    assert len(candidates) >= 2

    # Check endpoint subsumption: /dzz/publish/search.php kept, /search.php pruned
    first = candidates[0]
    assert "endpoint=/dzz/publish/search.php" in first.missing_bindings
    assert "endpoint=/search.php" not in first.missing_bindings

    # Check both parameters extracted
    assert "parameter:orderby" in first.missing_bindings
    assert "parameter:order" in first.missing_bindings

    # Check that ORDER BY title and direct expression (no single quote or WHERE logic) are generated
    assert any("ORDER BY SQL Injection" in c.scenario.title for c in candidates)
    for c in candidates:
        poc = c.scenario.poc_command or ""
        assert "extractvalue(1%2Cconcat" in poc or "(SELECT%201%20FROM%20(SELECT(SLEEP(5)))a)" in poc
        assert "test%27" not in poc
        # Both parameters covered in PoC
        assert "orderby=" in poc
        assert "order=" in poc


def test_grounded_scenario_synthesizer_api_auth_put_command_injection() -> None:
    repo = InMemoryGraphRepository()
    desc = (
        "A high-privileged remote attacker can exploit a command injection vulnerability "
        "in the /api/iodd/config endpoint by sending a crafted PUT request with admin credentials "
        "allowing execution of commands with root privileges on the device."
    )
    repo.atomic_write(
        nodes=[
            _node("CWE", "CWE-78"),
            _node("CVE", "CVE-2026-27562", title="Command Injection via PUT in /api/iodd/config", description=desc),
            _node("WeaknessAssertion", "WAS-27562"),
        ],
        edges=[
            _edge("e1", "HAS_WEAKNESS_ASSERTION", "CVE-2026-27562", "WAS-27562"),
            _edge("e2", "MAPS_TO", "WAS-27562", "CWE-78"),
        ],
    )
    import_canonical_wstg_catalog(repo)

    candidates = synthesized_scenarios(repo, "CVE-2026-27562")
    assert len(candidates) >= 1

    first = candidates[0]
    # Endpoint /api/iodd/config must be bound
    assert "endpoint=/api/iodd/config" in first.missing_bindings
    assert "target_endpoint" not in first.missing_bindings

    # Constraint must have CONSTRAINT-AUTHENTICATED-SESSION and NOT CONSTRAINT-UNAUTHENTICATED-ACCESS
    assert "CONSTRAINT-AUTHENTICATED-SESSION" in first.scenario.constraint_ids
    assert "CONSTRAINT-UNAUTHENTICATED-ACCESS" not in first.scenario.constraint_ids

    # Techniques must be BLIND and TIME_BASED (not ERROR_BASED or OUT_OF_BAND)
    assert "TECH-BLIND" in first.scenario.technique_ids
    assert "TECH-TIME_BASED" in first.scenario.technique_ids
    assert "TECH-ERROR_BASED" not in first.scenario.technique_ids

    # PoC check: method PUT, endpoint /api/iodd/config, JSON body, Bearer token
    poc = first.scenario.poc_command
    assert "-X PUT" in poc
    assert "/api/iodd/config" in poc
    assert "Content-Type: application/json" in poc
    assert "Authorization: Bearer <ADMIN_TOKEN>" in poc
    assert '-d \'{"<INPUT_PARAM>": "test; id; whoami"}\'' in poc


def test_grounded_scenario_synthesizer_generic_sqli_multi_db_and_post_alt() -> None:
    repo = InMemoryGraphRepository()
    desc = (
        "kaiten from 57.192.20 to before 57.214.26 is vulnerable to SQL Injection. "
        "Dynamic SQL statements are generated without the required data validation "
        "and without using parameterized statements or stored procedures."
    )
    repo.atomic_write(
        nodes=[
            _node("CWE", "CWE-89"),
            _node("CVE", "CVE-2026-79303", title="Kaiten SQL Injection", description=desc),
            _node("WeaknessAssertion", "WAS-79303"),
            _node("CVE", "CVE-2024-58385", title="Yonyou SQLi", description="Vulnerability in fillbacksettingedit.php via id parameter"),
            _node("WeaknessAssertion", "WAS-58385"),
        ],
        edges=[
            _edge("e1", "HAS_WEAKNESS_ASSERTION", "CVE-2026-79303", "WAS-79303"),
            _edge("e2", "MAPS_TO", "WAS-79303", "CWE-89"),
            _edge("e3", "HAS_WEAKNESS_ASSERTION", "CVE-2024-58385", "WAS-58385"),
            _edge("e4", "MAPS_TO", "WAS-58385", "CWE-89"),
        ],
    )
    import_canonical_wstg_catalog(repo)

    candidates = synthesized_scenarios(repo, "CVE-2026-79303")
    assert len(candidates) >= 2

    error_cand = next(c for c in candidates if "TECH-ERROR_BASED" in c.scenario.technique_ids)
    time_cand = next(c for c in candidates if "TECH-TIME_BASED" in c.scenario.technique_ids)

    # Check unbound endpoint & input acknowledged
    assert "input_binding" in error_cand.missing_bindings
    assert "target_endpoint" in error_cand.missing_bindings

    # Check recon & fuzzing hints dynamically pulled from graph neighbor
    error_poc = error_cand.scenario.poc_command
    assert "GỢI Ý TỪ LÁNG GIỀNG ĐỒ THỊ (HISTORICAL NEIGHBORS)" in error_poc
    assert "'id' (từ CVE-2024-58385)" in error_poc
    assert "'/fillbacksettingedit.php' (từ CVE-2024-58385)" in error_poc
    assert "LƯU Ý XÁC THỰC" in error_poc

    # Check multi-database alternatives provided
    assert "PostgreSQL" in error_poc
    assert "SQL Server" in error_poc
    assert "POST JSON Body" in error_poc

    # Check time-based PoC alternatives
    time_poc = time_cand.scenario.poc_command
    assert "PostgreSQL" in time_poc
    assert "SQL Server" in time_poc
    assert "POST JSON Body" in time_poc
    assert "pg_sleep" in time_poc
    assert "WAITFOR" in time_poc
