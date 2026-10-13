"""Official CAPEC catalog download contract with explicit expected release."""

from xml.etree import ElementTree


CAPEC_CATALOG_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"
CAPEC_SCHEMA_URL = "https://capec.mitre.org/data/xsd/ap_schema_latest.xsd"


def assert_release(*, actual: str, expected: str) -> None:
    if actual != expected:
        raise ValueError(f"CAPEC catalog release mismatch: expected {expected}, got {actual}")


def root_version(xml_bytes: bytes) -> str:
    release = ElementTree.fromstring(xml_bytes).attrib.get("Version")
    if not release:
        raise ValueError("CAPEC catalog has no Version")
    return release
