# Evolving Vulnerability CKG

## V2 research path

`src/ckg` is the provenance-first implementation of the evolving CKG design.
It keeps MITRE CWE canonical, reifies CVE↔CWE mappings, retains every source
record/evidence span, and discovers semantic — not executable — scenarios.
The v2 modules below are the only runtime and graph source of truth. Legacy
registry/event adapters remain available only for explicit one-way migration;
they are not an alternate server or build implementation.

The offline foundation can be checked without downloading anything:

```bash
.venv/bin/python -m scripts.verify_canonical_catalogs
.venv/bin/python -m scripts.verify_legacy_v2_migration
```

Both verifiers emit a structured diagnostic summary. A pinned source-release
reference or missing legacy snapshot is never promoted silently: the normal
report uses `PASS_WITH_DIAGNOSTICS` with `promotion_allowed: false`, while CI
can fail closed with `--strict`.

The offline historical CVE-to-CWE evaluation is a real replay pipeline over the
hash-pinned local snapshots. It writes JSON/JSONL/CSV artifacts and labels
held-out source mappings as future-observed rather than human gold:

```bash
.venv/bin/python -m scripts.run_historical_evaluation
```

The corresponding regression suite is:

```bash
.venv/bin/python -m pytest tests/unit tests/graph tests/integration tests/reasoning tests/regression tests/evaluation -q
```

To build a wheel in an offline/restricted environment, keep the build backend
installed in the local Python toolchain and disable isolated dependency
resolution explicitly:

```bash
python3 -m pip wheel --no-build-isolation --no-deps --wheel-dir dist .
```

This command fails clearly when the local `setuptools`/`wheel` toolchain is
missing; it never attempts a network download. `make wheel-offline` is the
equivalent checked command.

### Module-1 Unified CLI (`ckg`)

The installed package exposes the `ckg` entrypoint for v2 operations:

```bash
ckg build       # Build canonical CWE/CAPEC graph from verified snapshots
ckg serve       # Serve Module-1 HTTP API backed by Neo4j or in-memory
ckg analyze     # Analyze a CVE and output the Section 55 semantic analysis contract
ckg ingest      # Ingest CVE/CWE sources or an explicit local PATT reference manifest
ckg feedback    # Record execution feedback and update Bayesian Beta posteriors
ckg rebuild     # Rebuild learned CWE context profiles and co-occurrence graphs
ckg-evaluate-history  # Replay pinned CVE/CWE history and write evaluation artifacts
```

### Bootstrap Scripts (`scripts/`)

- `scripts/bootstrap_cwe.py`: Snapshot pinned official CWE catalog & schema
- `scripts/bootstrap_capec.py`: Snapshot pinned official CAPEC catalog & schema
- `scripts/bootstrap_wstg.py`: Snapshot & import OWASP WSTG testing methodology cases
- `scripts/bootstrap_patt.py`: Generate a revision-pinned local PATT reference manifest
- `scripts/bootstrap_cves.py`: Snapshot & import CVE records from CVE Services or NVD API 2.0

V2 key contracts:

- canonical CWE/CAPEC snapshots are pinned by release and SHA-256;
- direct `CVE → CWE` is forbidden in v2; mappings are `WeaknessAssertion`
  with a source/evidence span;
- unknown environment/configuration stays `UNKNOWN`, not false;
- Module 1 scenarios have no endpoint, parameter, payload or callback binding;
- feedback updates only a scoped Beta belief bucket and does not mutate
  canonical CWE.

The dependency-light v2 inspection API exposes `/cves/{id}`, local subgraphs,
weaknesses, historical neighbors, semantic scenarios, CWE profiles, ingestion
and execution feedback. Its case-file UI is served at `/ui/v2` by the v2 API
handler. Technology-to-CVE search is available at
`GET /cves?technology=Grafana&from_year=2023&to_year=2026&limit=50&offset=0`;
omitted years default to the five most recent calendar years. The response
includes `total`, `returned`, `limit`, `offset` and `truncated` metadata. For
technology searches, `total` is `null` when the bounded candidate window is
exhausted; treat `truncated: true` as a lower-bound result and refine the
technology/year query before making completeness claims. The search is
source-backed: it only returns vulnerabilities linked to an affected
Product/Package, keeps version ranges and source records, folds CVE/GHSA
aliases, and excludes records whose available source evidence is entirely
rejected or withdrawn.
Use `POST /ingest/cves/search` with `{ "technology": "Grafana" }` to
resolve the name against NVD's CPE catalog and fetch CVEs using the matching
product-family applicability criteria. To avoid ambiguous name resolution,
provide an exact CPE 2.3 name instead, for example
`{ "cpe_name": "cpe:2.3:a:grafana:grafana:10.0.0:*:*:*:*:*:*:*" }`.
The response reports the CPE families queried and whether candidate or CVE
limits truncated the results. A complete lookup with no usable CPE returns
`NO_CPE_MATCH`; if the candidate lookup itself was capped before finding a
usable CPE, it returns `CPE_RESOLUTION_INCOMPLETE`. Neither case creates an
empty snapshot or ingestion job. This explicit network fetch is separate from
`GET /cves?technology=...`, which
only searches data already present in the graph and never contacts NVD.
NVD requests are paced; if the upstream still rate-limits a request, the API
returns HTTP `429` (and `Retry-After` when NVD provides it) without writing a
partial snapshot or job.
See [the architecture index](docs/architecture/00-overview.md) and
[the runtime-hardening plan](docs/superpowers/plans/2026-09-22-v2-runtime-hardening.md).

DAST consumers can fetch one bounded context bundle with
`GET /cwes/CWE-89/context`. The compact response contains the selected CWE
description and source revision, plus explicitly linked WSTG methods with a
curated summary, techniques, input surfaces, observable signals and source
evidence. `availability` and `missing_components` identify absent context.
DAST combines this with its own target profile and supplies the target-specific
bindings. Raw PATT payloads stay on `GET /cwes/CWE-89/payloads`; they are
reference-only, and `validation_status=untested` does not mean a payload works.

### PATT reference payloads (explicit import)

PATT raw strings are a separate, source-backed reference plane. They are never
fetched by `ckg build`, API reads, or the UI; they never create an executable
scenario or a direct `CVE/GHSA → Payload` edge. Imported values are always
`origin=patt`, `curation_status=upstream_curated`, and
`validation_status=untested`.

The canonical active graph keeps this plane compact: `CWE -> PayloadFamily`,
with optional `PayloadFamily -> Technology` links when the pinned source gives
a technology-specific extraction. The bounded current-time reasoning
subgraph can traverse the family and any available technology nodes as
test-design context; an `as_of` query excludes undated PATT nodes until their
source-availability time is recorded. A focused rebuild that skips remote
refresh reconstructs this semantic plane from the local payload index and
fails closed if the seven native PATT CWE slices are not present.

`PATTDocument`/PATT evidence metadata and their source relationships are
retained losslessly in the snapshot-backed `compact_details.sqlite3` sidecar;
family nodes also retain the source revisions and snapshot digests. Exact
payload strings and section locators remain in `patt_payloads.sqlite3` and are
returned by the API in pages. This preserves byte-exact review data without
creating thousands of graph nodes or edges; payload rows remain reference-only,
untested, and are never sent to a target.

First generate one local manifest from a checked PATT source. For a remote
source, `--url` must contain a real immutable 40+ character Git commit; for a
local file, record the upstream commit that produced it:

```bash
.venv/bin/python scripts/bootstrap_patt.py \
  --patt-cwe CWE-79 --kind wordlist \
  --file path/to/Intruders/xss.txt \
  --commit <immutable-patt-commit> \
  --output patt-xss-wordlist.json

ckg ingest --patt-cwe CWE-79 --file patt-xss-wordlist.json
```

The same command supports `--kind markdown`; add an optional `--technology`
when importing a technology-split source. The target CWE must already exist in
the v2 graph. After import, inspect reference material through
`GET /cwes/CWE-79/payloads?limit=50&offset=0` or
`GET /cves/<CVE-ID>/payloads?limit=50&offset=0`; the v2 UI shows the same
strings only under “Tham Khảo Payload Đã Curate” and loads further pages on
demand.

### Which source planes participate in reasoning

| Source | Current role |
|---|---|
| CWE | Canonical weakness identities and hierarchy used to scope retrieval and scenarios. |
| CVE/NVD and CVE Services | Reified `CVE -> WeaknessAssertion -> CWE` links, affected-product/version context, provenance, and historical neighbors. |
| CAPEC | CAPEC-to-CWE links contribute attack-pattern context; detailed attack steps and prerequisites are preserved in the compact sidecar, not expanded into every runtime subgraph. |
| OWASP WSTG | Explicit CWE-mapped test strategies and their technique/channel/oracle references can contribute scenario candidates. |
| PayloadsAllTheThings | Family/technology summaries are traversable current-time context; exact strings are fetched from the paginated sidecar API and are not execution instructions. |
| OpenCRE | Not ingested or used by the current runtime. |

## Canonical runtime and migration

`ckg build` and `ckg serve` are the only runtime/build implementation. They use
the v2 `GraphRepository` contract and the packaged UI under `src/ckg/ui/v2/`.
The root `build.py` and `ui/server.py` files are compatibility delegators only;
they cannot select the legacy sink or static UI.

Legacy registry and proposal-event files are accepted only by the explicit
one-way migration adapters in `src/ckg/migration/`. They preserve source
evidence and do not silently merge the old graph schema into a v2 read path.

Kho này xây property graph tập trung cho CWE, CAPEC, CVE, OWASP WSTG,
PayloadsAllTheThings và weakness nội bộ. OpenCRE hiện chưa được ingest vào graph;
không có OpenCRE importer hoặc dữ liệu OpenCRE runtime trong bản này. Mục tiêu là
bảo toàn nguồn gốc và ranh giới tin cậy: một liên kết tương đồng có thể gợi ý
cách thiết kế test, nhưng không tự động biến payload hoặc scenario của weakness
khác thành tri thức của weakness mới.

CKG có API đọc tri thức và scenario để DAST tích hợp; MCP server và runtime gửi
payload vào mục tiêu **không nằm trong phiên bản này**. Kho cung cấp ngữ cảnh
và hỗ trợ duyệt test; DAST chịu trách nhiệm binding và thực thi trên mục tiêu.

## Mô hình tin cậy

| Bậc | Ý nghĩa | Có tạo scenario local? |
|---|---|---|
| Definition | Weakness local có định nghĩa và provenance | Không |
| Relationship | `CHILD_OF` hoặc `SIMILAR_TO` đã duyệt | Không; chỉ tạo reference |
| Payload | Payload byte-exact, riêng weakness, đã test và duyệt | Chưa |
| Oracle | Oracle đặc tả observable/success criteria, đã duyệt | Có, nếu payload cũng đạt |
| Validated material | Validation record có target/execution/evidence digest | Khẳng định material đã test |

`SIMILAR_TO` bắt buộc có `dimension`. Dimension cho biết phần nào được phỏng
theo: `mechanism`, `input_vector`, `precondition`, `impact`, hoặc
`detection_strategy`. Card trả riêng:

- `assertedRelations`: quan hệ đã duyệt và provenance của nó;
- `referenceMethodologies` và `referenceScenarios`: gợi ý có
  `applicability: unknown`, kèm relation/dimension đã phơi ra reference;
- `scenarios`: chỉ scenario thực sự `TARGETS` weakness được hỏi.

Rút relation bằng event `retract` giữ nguyên audit history, nhưng domain edge và
mọi reference do edge đó phơi ra biến mất ở lần **reset rebuild** kế tiếp. Build
MERGE-only sẽ phát hiện edge cũ còn tồn tại và yêu cầu `--reset`, thay vì để
reference stale tồn tại âm thầm.

Mười slice CWE authoritative là bất đối xứng có chủ đích: scenario của chúng
vẫn có `testReady: true` với detection signal `strategy_hint`. Chỉ scenario của
weakness local mới bắt buộc oracle spec `accepted` riêng cho
weakness/family/technology.

## Cài đặt

Yêu cầu Python 3.12+, Docker Compose và Git. Tạo cấu hình:

```bash
cp .env.example .env
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

Không commit `.env`. Các API key, cache embedding, manifest local và dữ liệu
Neo4j đều bị ignore.

## Build có provenance

Live build luôn phải ghi manifest; response body được lưu content-addressed ở
`SOURCE_SNAPSHOT_ROOT/objects/<sha256>`:

```bash
.venv/bin/ckg build --dry-run
```

Replay cấm network và fail nếu URL không có trong manifest, object thiếu, hash
sai hoặc byte length sai. Sau build, replay còn phải khớp stage summaries,
graph counts và SHA-256 canonical của toàn bộ node/relationship; manifest cũ
không khớp semantic graph hiện tại bị từ chối trước mọi reset write:

```bash
.venv/bin/ckg build --dry-run
```

Build Neo4j bình thường là MERGE-only. Reset dùng hai pha: dựng và validate toàn
bộ graph trong RAM, sau đó delete + replay node/relation trong **một Neo4j
transaction**. Nếu bất kỳ write nào fail, Neo4j rollback về graph cũ:

```bash
.venv/bin/ckg build --reset
```

Không dùng `--reset` trên graph quan trọng nếu chưa chủ động cho phép thay thế
materialized view. Việc build schema/constraint xảy ra ngoài data-replacement
transaction; chúng là idempotent và không xóa dữ liệu.

## Workflow weakness mới

### 1. Definition

Thêm entry vào `registry/weaknesses.yaml`. Nếu entry được ingest từ URL, CLI lưu
raw bytes vào `registry/source_snapshots/objects/` và ghi `source_snapshot`,
`source_hash`, `source_excerpt`; commit snapshot và registry trước khi build:

```bash
.venv/bin/python -m ai_producers.cli ingest-url \
  --url https://example.org/advisory --write
```

### 2. Relation scaffold

AI chỉ tạo pending proposal:

```bash
.venv/bin/python -m ai_producers.cli relations \
  --weakness LAB-101 --top-k 5 --write
.venv/bin/python -m proposals.cli list --status pending
.venv/bin/python -m proposals.cli approve REL-PROP-... \
  --actor reviewer --comment 'mechanism evidence checked'
```

Human có thể request changes/revise/reject/retract. AI proposal bắt buộc giữ
retrieval score type, candidate rank/set size, embedding model và canonical text
hashes. Approval không copy scenario/payload/oracle từ CWE liên quan.

### 3. Payload riêng và validation

Nguồn payload phải là file UTF-8 tracked, committed trong `HEAD`, không symlink
và không dirty. Manual và AI dùng cùng validator:

```bash
.venv/bin/python -m ai_producers.cli payloads \
  --weakness LAB-101 \
  --family-key prompt.context_break \
  --family-name 'Prompt context break' \
  --technology OpenAI \
  --source-ref evidence/lab-101-payloads.md --write
```

Sau khi test trong lab, record validation cần target, execution và evidence ref
kèm SHA-256 cho từng artifact:

```bash
.venv/bin/python -m proposals.payload_cli record-validation PAY-PROP-... \
  --revision 1 --result passed --environment isolated-lab \
  --target-ref evidence/target.json --target-hash sha256:... \
  --execution-ref evidence/execution.json --execution-hash sha256:... \
  --observed-outcome 'controlled marker was emitted' \
  --evidence-ref evidence/result.json --evidence-hash sha256:... \
  --actor reviewer
.venv/bin/python -m proposals.payload_cli approve PAY-PROP-... \
  --actor reviewer --comment 'byte-exact payload and evidence checked'
```

Local committed artifact phải đúng hash. Remote validation artifact được phép
chỉ khi là URL tuyệt đối và có digest explicit; URL trần không đủ provenance.
Payload giữ riêng ba trục: `origin` (`patt`, `local_manual`, `ai_extracted`,
`rule_extracted`), `curationStatus` và `validationStatus`. Vì thế PATT mặc định
là `upstream_curated` nhưng `untested`; payload local chỉ thành
`human_reviewed`/`tested` sau đúng workflow validation + approval.

### 4. Oracle riêng

Thêm oracle vào `registry/oracle_specs.yaml`. Các field cốt lõi gồm
`observable_kind`, `observation`, `success_criteria`, `source_ref`,
`source_hash`, `reviewed_by`, `reviewed_at`, weakness/family và technology phù
hợp. `status` phải là `accepted`. Oracle source cũng phải là blob sạch đã
commit ở `HEAD` và đúng hash.

Build chỉ compose scenario local khi cùng weakness/family/technology có:

1. payload proposal `accepted` sau validation `passed`; và
2. oracle spec `accepted`.

Nếu thiếu một gate, definition, relation và reference vẫn query được nhưng
`scenarios` local rỗng. Đây là fail-closed có chủ đích.

## Kiểm thử

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m py_compile $(rg --files -g '*.py')
```

Test Neo4j transaction dùng service riêng ở cổng 7688:

```bash
docker compose --profile test up -d --wait neo4j-test
NEO4J_TEST_URI=bolt://localhost:7688 \
NEO4J_TEST_USER=neo4j \
NEO4J_TEST_PASSWORD=test-password \
  .venv/bin/python -m pytest tests/test_neo4j_replace.py -q
```

The v2 repository parity suite is separate and opt-in. It exercises the
canonical `GraphEntity` schema and technology-to-CVE query on the test service;
the in-memory suite is not a substitute for this live check:

```bash
NEO4J_V2_TEST_URI=bolt://localhost:7688 \
NEO4J_V2_TEST_USER=neo4j \
NEO4J_V2_TEST_PASSWORD=test-password \
  .venv/bin/python -m pytest tests/graph/test_v2_neo4j.py -q
```

Các warning `scenarios_missing_methodology`,
`scenarios_missing_detection_signal`, `unclassified_table_spans` và `over_cap`
là coverage gaps được in công khai, không phải bằng chứng stage đã đầy đủ.
