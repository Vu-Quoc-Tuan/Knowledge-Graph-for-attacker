# Ingestion

Raw source bytes are snapshot before parsing. CWE/CAPEC use pinned catalog
digests. NVD, CVE Services and GHSA records become source-record revisions plus
`REPORTED` assertions. Rejected or withdrawn records stay historical but do not
emit active assertions.

NVD CPE configurations are also normalized into source-backed `Product` and
`VersionRange` nodes. The v2 API can query this projection with
`GET /cves?technology=<name>&from_year=<year>&to_year=<year>`; without explicit
years it uses the five most recent calendar years. `POST /ingest/cves/search`
is the explicit network operation for refreshing from NVD. A `technology`
query is first resolved against the NVD CPE catalog, then each matching
product family is used as a CVE applicability filter (`virtualMatchString`);
callers may instead pass an exact CPE 2.3 name as `cpe_name` (`cpeName`). The
client splits publication dates into NVD-compatible 120-day windows, bounds
candidate families and CVE records, deduplicates results, snapshots the
aggregate response, and then uses the normal structured importer. The response
reports searched CPEs and any truncation. A complete lookup with no usable CPE
returns `NO_CPE_MATCH` without writing a snapshot or ingestion job; a capped,
unresolved lookup reports `CPE_RESOLUTION_INCOMPLETE`. The local `GET /cves`
search remains graph-only and never triggers a network request. NVD API calls
are paced per process; if the upstream still returns `429`, the API forwards a
retry hint where available and writes no partial snapshot or job. The runtime
has one v2 repository and graph schema; legacy registry/event data can enter it
only through an explicit, provenance-preserving migration adapter.
