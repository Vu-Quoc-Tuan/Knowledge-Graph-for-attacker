"""Grounded scenario synthesizer combining WSTG strategies, CWE semantics, historical neighbors, and extracted CVE artifacts."""

from __future__ import annotations

from datetime import datetime
import re
from typing import Any

from ckg.domain.enums.scenario_type import ScenarioType
from ckg.graph.ports import GraphRepository
from ckg.linking.historical.hybrid_retriever import HistoricalNeighbor
from ckg.reasoning._graph import constraint_ids, mapped_values, targets
from ckg.scenario.catalog import ScenarioCatalog
from ckg.scenario.composer import compose
from ckg.scenario.contract import ScenarioCandidate


def _is_valid_endpoint(ep: str) -> bool:
    clean = ep.lstrip("/")
    if not clean or len(clean) < 2:
        return False
    # Exclude common system/binary targets that are not web endpoints
    system_paths = ("etc/passwd", "etc/shadow", "etc/hosts", "bin/sh", "bin/bash", "proc/self", "dev/null")
    if any(clean.lower().startswith(sp) for sp in system_paths):
        return False
    # Must have web extension, slashes, or query string
    web_exts = (".php", ".jsp", ".asp", ".aspx", ".html", ".do", ".action", ".cgi", ".json", ".xml", ".js")
    if any(clean.lower().endswith(ext) for ext in web_exts):
        return True
    if "/" in clean or "?" in clean or "=" in clean:
        return True
    return False


def _extract_cve_artifacts(text: str) -> dict[str, Any]:
    """Extract concrete endpoints, parameters, functions, and services from vulnerability text."""
    raw_endpoints = re.findall(r"\b(?:file|endpoint|uri|path)\s+([/\w\.\-\?\&=]+)", text, re.IGNORECASE)
    postfix_endpoints = re.findall(r"([/\w\.\-~]+)\s+(?:endpoint|uri|path|route|service|api)\b", text, re.IGNORECASE)
    prep_endpoints = re.findall(r"\b(?:in|at|on|to)\s+(?:the\s+)?([/][a-zA-Z0-9_\-\.]+(?:/[a-zA-Z0-9_\-\.]+)*)", text, re.IGNORECASE)
    url_paths = re.findall(r"(?:\b|\s)(/(?:api|v[0-9]+|rest|iodd|config|auth|admin|oauth|user|service|sys|data)/[a-zA-Z0-9_\-\./]+)", text, re.IGNORECASE)
    web_files = re.findall(r"\b([/\w\.\-]+\.(?:php|jsp|asp|aspx|html|do|action|cgi))\b", text, re.IGNORECASE)
    all_raw = raw_endpoints + postfix_endpoints + prep_endpoints + url_paths + web_files
    endpoints: list[str] = []
    for raw in all_raw:
        ep = raw.rstrip(".,;:)")
        if not ep:
            continue
        if not ep.startswith("/"):
            ep = f"/{ep}"
        if _is_valid_endpoint(ep) and ep not in endpoints and not ep.endswith("/."):
            endpoints.append(ep)

    # Prune subsumed / redundant suffix endpoints (e.g. keep /dzz/publish/search.php, prune /search.php)
    pruned_endpoints: list[str] = []
    for ep in endpoints:
        is_subsumed = any(
            other != ep and len(other) > len(ep) and (
                other.endswith(ep) or other.split("?")[0] == ep
            )
            for other in endpoints
        )
        if not is_subsumed:
            pruned_endpoints.append(ep)
    endpoints = pruned_endpoints

    funcs = re.findall(r"\b([\w\.:]+)\(\)", text)
    funcs += re.findall(r"\b(?:function|method|handler)\s+([\w:]+)", text, re.IGNORECASE)
    funcs = [f.rstrip(".,;:)") for f in funcs if f.lower() not in {"validates", "allows", "enables", "results", "causes"}]

    params: list[str] = []
    fixed_params: dict[str, str] = {}

    def _add_param(p: str) -> None:
        p = p.strip().rstrip(".,;:)")
        if "=" in p:
            parts = p.split("=", 1)
            name = parts[0].strip()
            val = parts[1].strip()
            if name and val:
                fixed_params[name] = val
                return
        stop_words = {
            "the", "a", "an", "this", "that", "via", "in", "of", "and", "or", "to", "for", "with",
            "allows", "allow", "leading", "leads", "lead", "enables", "enable", "causes", "cause",
            "results", "result", "which", "is", "are", "by", "from", "on", "at", "as", "such", "using",
            "bypasses", "bypass", "incorporated", "incorporates", "sanitization", "unauthenticated",
            "authenticated", "exploited", "observed", "contains", "where", "without", "arbitrary",
            "value", "values", "name", "names", "used", "was", "were", "been", "has", "have", "had",
        }
        if p and len(p) >= 1 and p.lower() not in stop_words and p not in params:
            params.append(p)

    # Prefix parameter keywords: e.g. "parameter doc_mail" or "argument title/master_table"
    for m in re.finditer(r"\b(?:argument|parameter|param|field)s?\s+([\w\-_/=]+)", text, re.IGNORECASE):
        raw = m.group(1).rstrip(".,;:)")
        for p in raw.split("/"):
            _add_param(p)

    # Postfix parameter keywords: e.g. "the id parameter", "doc_mail and doc_pswd parameters"
    for m in re.finditer(
        r"\b(?:the\s+)?([`'\"a-zA-Z0-9_\-=]+)(?:\s+(?:and|,)\s+([`'\"a-zA-Z0-9_\-=]+))?\s+(?:arguments|parameters|params|fields|argument|parameter|param|field)\b",
        text,
        re.IGNORECASE,
    ):
        if m.group(1):
            _add_param(m.group(1).strip("`'\""))
        if m.group(2):
            _add_param(m.group(2).strip("`'\""))

    # Member / array / element keywords: e.g. "key_ops JWK member", "key_ops array"
    for m in re.finditer(r"\b([\w\-]+)\s+(?:JWK\s+)?(?:member|property|attribute|array|element)\b", text, re.IGNORECASE):
        _add_param(m.group(1).strip("`'\""))

    # Parameters with explicit assignment: e.g. "DontCheckLogin=1 parameter"
    for m in re.finditer(r"\b([a-zA-Z0-9_\-]+)=([^\s&,;]+)\s+(?:parameter|argument|field)s?\b", text, re.IGNORECASE):
        fixed_params[m.group(1)] = m.group(2)

    # "via [the] <param> parameter" or "via <param>"
    for m in re.finditer(r"\bvia\s+(?:the\s+)?([`'\"a-zA-Z0-9_\-]+)\s+(?:parameter|argument|field)\b", text, re.IGNORECASE):
        _add_param(m.group(1).strip("`'\""))

    services = [
        s.rstrip(".,;:")
        for s in re.findall(r"\b([a-zA-Z0-9_\-]+)\s+service\b", text, re.IGNORECASE)
    ]
    is_remote = bool(re.search(r"\bremote\b", text, re.IGNORECASE))
    is_ftp = bool(re.search(r"\bftp[d]?\b", text, re.IGNORECASE))
    is_http = bool(re.search(r"\bhttps?|\bweb\b|\burl\b|\.php\b|\bjson\b|\bapi\b|\bjwk\b|\boidc\b|\bacme\b|\bkey-import\b", text, re.IGNORECASE))
    has_auth_clause = bool(
        re.search(
            r"\bauthenticated attackers?\b"
            r"|\bwith\s+[\w\-]+(?:-level)?\s+(?:access|credentials|privileges|permissions)\b"
            r"|\brequires?\s+(?:authentication|admin|valid\s+credentials|login)\b"
            r"|\bauthenticated users?\b"
            r"|\b(?:high|low|medium)[\-\s]+privileged\b"
            r"|\badmin(?:istrator)?\s+(?:credentials|access|privileges|account)\b",
            text,
            re.IGNORECASE,
        )
    )
    role_m = re.search(
        r"\bwith\s+([a-zA-Z0-9_\-]+)[-\s]+level\s+access\b"
        r"|\bwith\s+([a-zA-Z0-9_\-]+)\s+(?:credentials|privileges|permissions|access)\b"
        r"|\b(admin(?:istrator)?|root|user|subscriber|editor|author)\s+(?:credentials|privileges|access|role)\b"
        r"|\b([a-zA-Z0-9_\-]+)[\-\s]+privileged\b",
        text,
        re.IGNORECASE,
    )
    auth_role = None
    if role_m:
        raw_role = (role_m.group(1) or role_m.group(2) or role_m.group(3) or role_m.group(4)).lower()
        if raw_role in ("high", "admin", "administrator", "root"):
            auth_role = "admin"
        else:
            auth_role = raw_role

    if has_auth_clause:
        is_authenticated = True
        is_unauthenticated = False
    else:
        is_authenticated = False
        is_unauthenticated = bool(
            re.search(r"\bunauthenticated\b|\bpre-auth\b|\bwithout authentication\b", text, re.IGNORECASE)
        )
    is_root = bool(re.search(r"\broot\b|\badministrator\b|\badmin\b", text, re.IGNORECASE))

    # Query declarative detector for order_by clause
    order_by_cfg = ScenarioCatalog.get_default().surface_detectors.get("order_by", {})
    order_by_terms = set(order_by_cfg.get("param_keywords", [
        "orderby", "order_by", "order", "sort", "sort_by", "sort_dir",
        "dir", "sort_order", "sortorder", "ordering", "sortfield",
        "sort_column", "sortcol", "sortkey", "direction",
    ]))
    order_by_patterns = order_by_cfg.get("text_patterns", [r"\border\s+by\b", r"\bsort\s+by\b", r"\bsorting\s+parameter\b"])
    is_order_by = bool(
        any(p.lower() in order_by_terms for p in params)
        or any(re.search(pat, text, re.IGNORECASE) for pat in order_by_patterns)
    )

    return {
        "endpoints": endpoints,
        "functions": funcs,
        "parameters": params,
        "fixed_parameters": fixed_params,
        "services": services,
        "is_remote": is_remote,
        "is_ftp": is_ftp,
        "is_http": is_http,
        "is_unauthenticated": is_unauthenticated,
        "is_authenticated": is_authenticated,
        "auth_role": auth_role,
        "is_root": is_root,
        "is_order_by": is_order_by,
    }


# Backwards-compatible aliases delegating to ScenarioCatalog
def _classify_weaknesses(weakness_ids: set[str]) -> str | None:
    return ScenarioCatalog.get_default().classify_weaknesses(weakness_ids)


def _infer_component_semantics(artifacts: dict[str, Any], text: str) -> dict[str, Any]:
    return ScenarioCatalog.get_default().infer_component_semantics(artifacts, text)


def _infer_tech_stack(artifacts: dict[str, Any], text: str) -> dict[str, str]:
    return ScenarioCatalog.get_default().infer_tech_stack(artifacts, text)


def _generate_title(category: str | None, var: dict[str, Any], artifacts: dict[str, Any], component: dict[str, Any] | None = None, tech: dict[str, str] | None = None) -> str:
    return ScenarioCatalog.get_default().render_title(category, var, artifacts, component, tech)


def _generate_description(category: str | None, var: dict[str, Any], artifacts: dict[str, Any], component: dict[str, Any] | None = None, tech: dict[str, str] | None = None) -> str:
    return ScenarioCatalog.get_default().render_description(category, var, artifacts, component, tech)


def _generate_steps(category: str | None, var: dict[str, Any], artifacts: dict[str, Any], component: dict[str, Any] | None = None, tech: dict[str, str] | None = None) -> tuple[str, ...]:
    return ScenarioCatalog.get_default().render_steps(category, var, artifacts, component, tech)


def _generate_poc(category: str | None, var: dict[str, Any], artifacts: dict[str, Any], vulnerability_id: str, component: dict[str, Any] | None = None, tech: dict[str, str] | None = None) -> str:
    return ScenarioCatalog.get_default().render_poc(category, var, artifacts, vulnerability_id, component, tech)


# Module-level dictionary interface for backward compatibility
class _WeaknessVariantsProxy(dict):
    def __getitem__(self, key: str) -> list[dict[str, Any]]:
        cat = ScenarioCatalog.get_default()
        variants = cat.categories.get(key, {}).get("variants", [])
        return [dict(v) for v in variants]

    def get(self, key: str, default: Any = None) -> Any:
        cat = ScenarioCatalog.get_default()
        if key in cat.categories:
            return [dict(v) for v in cat.categories[key].get("variants", [])]
        return default


_WEAKNESS_VARIANTS = _WeaknessVariantsProxy()


def synthesized_scenarios(
    repository: GraphRepository,
    vulnerability_id: str,
    neighbors: tuple[HistoricalNeighbor, ...] = (),
    *,
    as_of: datetime | None = None,
    _weakness_ids: set[str] | None = None,
) -> tuple[ScenarioCandidate, ...]:
    """Synthesize evidence-grounded attack scenario candidates using WSTG knowledge, CWE semantics, historical neighbor similarity, and extracted CVE parameters."""
    target_node = next((n for n in repository.find_nodes("CVE", {}) if n.node_id == vulnerability_id), None)
    if target_node is None:
        target_node = next((n for n in repository.find_nodes("GHSA", {}) if n.node_id == vulnerability_id), None)
    if target_node is None:
        return ()

    catalog = ScenarioCatalog.get_default()
    text = f"{target_node.props.get('title', '')} {target_node.props.get('description', '')}".strip()
    artifacts = _extract_cve_artifacts(text)
    component = catalog.infer_component_semantics(artifacts, text)
    tech = catalog.infer_tech_stack(artifacts, text)

    # Resolve weakness assertions mapped to target
    weakness_ids = _weakness_ids or mapped_values(repository, vulnerability_id, "HAS_WEAKNESS_ASSERTION")
    if not weakness_ids:
        return ()

    # Independent CWE families need independent candidates.  Passing the
    # complete set to one category previously attached unrelated weaknesses to
    # (for example) an SQLi scenario and dropped XSS coverage.
    if _weakness_ids is None:
        grouped = catalog.group_weaknesses(weakness_ids)
        if len(grouped) > 1:
            return tuple(
                candidate
                for group in grouped.values()
                for candidate in synthesized_scenarios(
                    repository,
                    vulnerability_id,
                    neighbors,
                    as_of=as_of,
                    _weakness_ids=set(group),
                )
            )

    category = catalog.classify_weaknesses(weakness_ids)
    variants = catalog.get_variants(category, component.get("kind"))

    if not variants:
        dyn_techniques: set[str] = set()
        dyn_channels: set[str] = set()
        dyn_oracles: set[str] = set()
        dyn_strategies: set[str] = set()
        for strategy in repository.find_nodes("TestStrategy", {}):
            strat_cwes = targets(repository, strategy.node_id, "TARGETS_WEAKNESS")
            if strat_cwes & weakness_ids:
                dyn_strategies.add(strategy.node_id)
                dyn_techniques.update(targets(repository, strategy.node_id, "USES_TECHNIQUE"))
                dyn_channels.update(targets(repository, strategy.node_id, "USES_CHANNEL"))
                dyn_oracles.update(targets(repository, strategy.node_id, "USES_ORACLE"))
        if dyn_techniques:
            variants = [
                {
                    "id_suffix": "knowledge_guided",
                    "name": "Kịch Bản Kiểm Thử Tự Động Định Hướng Tri Thức (Knowledge-Guided)",
                    "techniques": tuple(sorted(dyn_techniques)),
                    "channels": tuple(sorted(dyn_channels)),
                    "oracles": tuple(sorted(dyn_oracles)),
                    "constraints": (
                        "CONSTRAINT-REMOTE-NETWORK-REACHABLE",
                        "CONSTRAINT-HTTP-SERVICE-REACHABLE",
                    ),
                    "probe_kind": "generic_knowledge_probe",
                }
            ]

    if not variants:
        return ()

    # Limit to top 5 highest quality neighbors to eliminate context noise
    relevant_neighbors = [
        n for n in neighbors
        if (mapped_values(repository, n.vulnerability_id, "HAS_WEAKNESS_ASSERTION") & weakness_ids)
        or n.score > 0.3
    ][:5]
    if not relevant_neighbors:
        try:
            from ckg.linking.historical.hybrid_retriever import retrieve_historical_neighbors
            auto_neighbors = retrieve_historical_neighbors(repository, vulnerability_id, top_k=8, as_of=as_of)
            relevant_neighbors = [
                n for n in auto_neighbors
                if (mapped_values(repository, n.vulnerability_id, "HAS_WEAKNESS_ASSERTION") & weakness_ids)
                or n.score > 0.3
            ][:5]
        except Exception:
            relevant_neighbors = []
    top_neighbor = relevant_neighbors[0] if relevant_neighbors else None

    strategy_nodes = [
        s.node_id for s in repository.find_nodes("TestStrategy", {})
        if targets(repository, s.node_id, "TARGETS_WEAKNESS") & weakness_ids
    ]

    # Mine concrete parameters & endpoints from historical neighbors in the graph
    neighbor_artifacts: dict[str, Any] = {
        "endpoints": [],
        "parameters": [],
        "endpoint_origins": {},
        "param_origins": {},
    }
    candidate_vuln_ids: list[str] = [n.vulnerability_id for n in relevant_neighbors]
    if not candidate_vuln_ids:
        # Fallback: inspect repository nodes for CVE/GHSA sharing weakness
        for cve_node in repository.find_nodes("CVE", {}):
            if cve_node.node_id != vulnerability_id and (mapped_values(repository, cve_node.node_id, "HAS_WEAKNESS_ASSERTION") & weakness_ids):
                candidate_vuln_ids.append(cve_node.node_id)
        for ghsa_node in repository.find_nodes("GHSA", {}):
            if ghsa_node.node_id != vulnerability_id and (mapped_values(repository, ghsa_node.node_id, "HAS_WEAKNESS_ASSERTION") & weakness_ids):
                candidate_vuln_ids.append(ghsa_node.node_id)

    for vuln_cand_id in candidate_vuln_ids[:8]:
        n_node = next((node for node in repository.find_nodes("CVE", {}) if node.node_id == vuln_cand_id), None)
        if n_node is None:
            n_node = next((node for node in repository.find_nodes("GHSA", {}) if node.node_id == vuln_cand_id), None)
        if n_node:
            n_text = f"{n_node.props.get('title', '')} {n_node.props.get('description', '')}".strip()
            n_art = _extract_cve_artifacts(n_text)
            for ep in n_art.get("endpoints", []):
                if ep not in neighbor_artifacts["endpoints"]:
                    neighbor_artifacts["endpoints"].append(ep)
                    neighbor_artifacts["endpoint_origins"][ep] = vuln_cand_id
            for p in n_art.get("parameters", []):
                if p not in neighbor_artifacts["parameters"]:
                    neighbor_artifacts["parameters"].append(p)
                    neighbor_artifacts["param_origins"][p] = vuln_cand_id

    artifacts["neighbor_artifacts"] = neighbor_artifacts

    base_derivations = list(strategy_nodes) if strategy_nodes else [f"SYNTH-{category or 'GENERIC'}"]
    if relevant_neighbors:
        base_derivations.extend(n.vulnerability_id for n in relevant_neighbors[:3])

    missing: list[str] = []
    if artifacts["endpoints"]:
        for ep in artifacts["endpoints"][:2]:
            missing.append(f"endpoint={ep}")
    else:
        missing.append("target_endpoint")

    if artifacts["parameters"]:
        for param in artifacts["parameters"][:3]:
            missing.append(f"parameter:{param}")
    else:
        missing.append("input_binding")

    if artifacts.get("fixed_parameters"):
        for k, v in artifacts["fixed_parameters"].items():
            missing.append(f"fixed_parameter:{k}={v}")

    if artifacts["functions"]:
        for fn in artifacts["functions"][:1]:
            missing.append(f"function:{fn}")

    if artifacts["services"]:
        for svc in artifacts["services"][:2]:
            missing.append(f"service:{svc}")

    missing.extend(["environment_snapshot", "probe_payload"])

    declared_constraints = list(constraint_ids(repository, vulnerability_id))

    candidates: list[ScenarioCandidate] = []
    for var in variants:
        variant_constraints = list(var["constraints"])
        if artifacts["is_ftp"] and "CONSTRAINT-FTP-SERVICE-REACHABLE" not in variant_constraints:
            variant_constraints.append("CONSTRAINT-FTP-SERVICE-REACHABLE")
        if artifacts["is_unauthenticated"] and "CONSTRAINT-UNAUTHENTICATED-ACCESS" not in variant_constraints:
            variant_constraints.append("CONSTRAINT-UNAUTHENTICATED-ACCESS")
        if artifacts["is_authenticated"]:
            if "CONSTRAINT-AUTHENTICATED-SESSION" not in variant_constraints:
                variant_constraints.append("CONSTRAINT-AUTHENTICATED-SESSION")
            if "CONSTRAINT-UNAUTHENTICATED-ACCESS" in variant_constraints:
                variant_constraints.remove("CONSTRAINT-UNAUTHENTICATED-ACCESS")
            declared_constraints = [c for c in declared_constraints if c != "CONSTRAINT-UNAUTHENTICATED-ACCESS"]

        all_constraints = tuple(sorted(set(declared_constraints + variant_constraints)))

        title = catalog.render_title(category, var, artifacts, component, tech)
        description = catalog.render_description(category, var, artifacts, component, tech)
        steps = catalog.render_steps(category, var, artifacts, component, tech)
        poc = catalog.render_poc(category, var, artifacts, vulnerability_id, component, tech)

        neighbor_clause = (
            f"bổ trợ bởi {len(relevant_neighbors)} láng giềng lịch sử (tiêu biểu: {top_neighbor.vulnerability_id} độ tương đồng {top_neighbor.score:.2f})"
            if top_neighbor
            else "xây dựng dựa trên ontology điểm yếu chuẩn và tiêu chuẩn kiểm thử OWASP WSTG"
        )
        premise = f"{title} cho điểm yếu {','.join(sorted(weakness_ids))}; {neighbor_clause}"

        relevance = 0.70
        if relevant_neighbors:
            relevance = min(0.95, 0.78 + 0.04 * len(relevant_neighbors[:5]))
        coverage = 0.60 if (artifacts["endpoints"] or artifacts["parameters"]) else 0.45
        support = sum(n.score for n in relevant_neighbors) / len(relevant_neighbors) if relevant_neighbors else None

        candidate = compose(
            target_vulnerability_id=vulnerability_id,
            scenario_type=ScenarioType.NOVEL,
            weakness_ids=tuple(sorted(weakness_ids)),
            technique_ids=tuple(var["techniques"]),
            channel_ids=tuple(var["channels"]),
            oracle_ids=tuple(var["oracles"]),
            constraint_ids=all_constraints,
            relevance=relevance,
            evidence_coverage=coverage,
            historical_support=support,
            derivation_ids=tuple(base_derivations),
            premises=(premise,),
            missing_bindings=tuple(missing + [var["probe_kind"]]),
            title=title,
            description=description,
            steps=steps,
            poc_command=poc,
        )
        candidates.append(candidate)

    return tuple(candidates)
