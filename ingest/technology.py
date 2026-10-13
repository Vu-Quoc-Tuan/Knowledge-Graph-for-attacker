import re
from pathlib import PurePath


# Two families of "technology" a scenario can be split by: the DBMS of a SQL
# injection, and the language/runtime of a template or deserialization payload.
# Both are just a Technology node name; a slice decides via
# `technology_from_filename` whether to read one out of a filename at all, so a
# flat vuln's topic filenames are never run through this.
TECH_ALIASES = {
    # DBMS (SQL injection)
    "postgresql": "PostgreSQL",
    "postgres": "PostgreSQL",
    "mysql": "MySQL",
    "sql server": "MSSQL",
    "sql_server": "MSSQL",
    "mssql": "MSSQL",
    "oracle": "Oracle",
    "oraclesql": "Oracle",
    "oracle sql": "Oracle",
    "ms access": "MS Access",
    "ms_access": "MS Access",
    "sqlite": "SQLite",
    # Language / runtime (template and deserialization injection)
    "python": "Python",
    "php": "PHP",
    "java": "Java",
    "javascript": "JavaScript",
    "ruby": "Ruby",
    "asp": "ASP",
    "elixir": "Elixir",
    "perl": "Perl",
    "dotnet": ".NET",
    "net": ".NET",
    "node": "Node.js",
    "nodejs": "Node.js",
}


def _clean(value: str) -> str:
    value = PurePath(value).stem
    value = re.sub(r"^\d+(?:\.\d+)?-", "", value)
    for prefix in ("Testing_for_", "Testing_", "SQL_Injection_", "SQL Injection "):
        if value.lower().startswith(prefix.lower()):
            value = value[len(prefix) :]
            break
    value = re.sub(r"\bInjection\b", "", value, flags=re.IGNORECASE)
    return re.sub(r"[\s_-]+", " ", value).strip().lower()


def normalize_technology(value: str) -> str | None:
    cleaned = _clean(value)
    for alias, canonical in TECH_ALIASES.items():
        if cleaned == alias or cleaned.startswith(alias + " "):
            return canonical
    return None


def normalize_wstg_technology(slug: str) -> str | None:
    return normalize_technology(slug)


def normalize_patt_technology(filename: str) -> str | None:
    return normalize_technology(filename)
