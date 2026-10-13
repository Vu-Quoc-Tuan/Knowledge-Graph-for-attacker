"""Official CWE catalog download contract.

MITRE's current download page links XML ZIP and a matching XSD for each release.
The client pins a requested release and refuses a document whose root Version
does not match that request; a `latest` URL therefore cannot silently change a
reproducible build.
"""

from __future__ import annotations

import io
import zipfile
from xml.etree import ElementTree


CWE_CATALOG_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_v{release}.xml.zip"
CWE_SCHEMA_URL = "https://cwe.mitre.org/data/xsd/cwe_schema_v{schema_version}.xsd"


def extract_single_xml(archive_bytes: bytes) -> bytes:
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        members = sorted(
            member for member in archive.namelist() if member.lower().endswith(".xml") and not member.endswith("/")
        )
        if len(members) != 1:
            raise ValueError(f"CWE archive must contain exactly one XML catalog, found {members}")
        return archive.read(members[0])


def catalog_zip_url(release: str) -> str:
    return CWE_CATALOG_ZIP_URL.format(release=release)


def schema_url(schema_version: str) -> str:
    return CWE_SCHEMA_URL.format(schema_version=schema_version)


def assert_release(*, actual: str, expected: str, catalog: str) -> None:
    if actual != expected:
        raise ValueError(f"{catalog} catalog release mismatch: expected {expected}, got {actual}")


def root_version(xml_bytes: bytes) -> str:
    release = ElementTree.fromstring(xml_bytes).attrib.get("Version")
    if not release:
        raise ValueError("CWE catalog has no Version")
    return release
