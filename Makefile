.PHONY: help start stop up down restart dev serve serve-memory build build-memory verify evaluate-history wheel-offline test test-fast status clean

ifneq (,$(wildcard .env))
    include .env
    export
endif

COMPOSE ?= docker compose
PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
CKG ?= $(if $(wildcard .venv/bin/ckg),.venv/bin/ckg,$(PYTHON) -m ckg)
PORT ?= 8088

# Mặc định khi chỉ gõ `make`
help:
	@echo "=========================================================================="
	@echo "                     EVOLVING-VULN-CKG (MODULE 1)                         "
	@echo "=========================================================================="
	@echo "Lệnh khởi động & dừng nhanh:"
	@echo "  make dev             Khởi động UI/API ngay lập tức (In-Memory, siêu nhanh 1s)"
	@echo "  make start           Khởi động toàn bộ (bật Neo4j + build đồ thị + chạy UI)"
	@echo "  make stop            Tắt toàn bộ (dừng Neo4j và server)"
	@echo "  make restart         Khởi động lại toàn bộ hệ thống"
	@echo ""
	@echo "Lệnh chạy từng phần:"
	@echo "  make up              Chỉ bật container Neo4j (port 7687, 7474)"
	@echo "  make down            Chỉ tắt container Neo4j"
	@echo "  make build           Nạp đồ thị chuẩn CWE/CAPEC vào graph v2"
	@echo "  make serve           Chạy server UI/API kết nối Neo4j (http://localhost:$(PORT)/ui/v2)"
	@echo ""
	@echo "Kiểm tra & Test:"
	@echo "  make status          Kiểm tra trạng thái Docker, Neo4j và Web UI"
	@echo "  make verify          Xác minh catalog và migration v2 offline"
	@echo "  make evaluate-history Chạy replay đánh giá CVE-CWE offline và sinh artifact"
	@echo "  make wheel-offline   Build wheel không resolve network (cần setuptools/wheel local)"
	@echo "  make test            Chạy toàn bộ pytest (kèm test container Neo4j nếu có)"
	@echo "  make test-fast       Chạy test offline nhanh (không cần Docker)"
	@echo "  make clean           Xóa cache và dừng mọi container"
	@echo "=========================================================================="

# Chạy siêu tốc không cần Docker/Neo4j (In-Memory Sandbox)
dev:
	@echo "==> Khởi động CKG Web UI (In-Memory mode) tại http://localhost:$(PORT)/ui/v2"
	@$(CKG) serve --memory --port $(PORT)

# Khởi động đầy đủ với Neo4j
start: .env up
	@$(PYTHON) -c "from ckg.config.env import load_env; load_env(); from ckg.config.settings import Settings; import os; from neo4j import GraphDatabase; d = GraphDatabase.driver(os.environ.get('NEO4J_URI', Settings.neo4j_uri), auth=(os.environ.get('NEO4J_USER', Settings.neo4j_user), os.environ.get('NEO4J_PASSWORD', Settings.neo4j_password))); s = d.session(); cnt = s.run('MATCH (n:GraphEntity) RETURN count(n) AS c').single()['c']; d.close(); exit(0 if cnt > 0 else 1)" 2>/dev/null || $(MAKE) build
	@$(CKG) serve --port $(PORT)

# Bật container Neo4j
up: .env
	@echo "==> Đang bật Neo4j container..."
	@$(COMPOSE) up -d --wait neo4j
	@echo "==> Neo4j sẵn sàng theo cấu hình NEO4J_URI"

# Tắt sạch toàn bộ
stop: down
	@echo "==> Đang dừng Web UI server nếu có..."
	@-pkill -f "ckg serve" 2>/dev/null || true
	@echo "==> Đã tắt toàn bộ dịch vụ."

down:
	@echo "==> Đang dừng các container..."
	@$(COMPOSE) --profile test down

restart: stop start

# Build đồ thị vào Neo4j
build: .env
	@echo "==> Đang nạp đồ thị Canonical CWE & CAPEC vào graph v2..."
	@$(CKG) build

build-memory:
	@echo "==> Đang nạp đồ thị Canonical CWE & CAPEC vào RAM..."
	@$(CKG) build --memory

# Chạy server
serve:
	@echo "==> Đang chạy CKG Server tại http://localhost:$(PORT)/ui/v2"
	@$(CKG) serve --port $(PORT)

serve-memory: dev

# Kiểm tra trạng thái
status:
	@echo "==> Trạng thái Docker containers:"
	@$(COMPOSE) ps
	@echo ""
	@echo "==> Kiểm tra kết nối ports:"
	@nc -z 127.0.0.1 7687 2>/dev/null && echo "  [+] Neo4j Bolt (7687): ONLINE" || echo "  [-] Neo4j Bolt (7687): OFFLINE"
	@nc -z 127.0.0.1 $(PORT) 2>/dev/null && echo "  [+] CKG Web UI ($(PORT)): ONLINE (http://localhost:$(PORT)/ui/v2)" || echo "  [-] CKG Web UI ($(PORT)): OFFLINE"

# Xác minh offline
verify:
	@echo "==> Xác minh Catalog chính thống (CWE 4.20 & CAPEC 3.9)..."
	@$(PYTHON) -m scripts.verify_canonical_catalogs
	@echo "==> Xác minh Migration v2..."
	@$(PYTHON) -m scripts.verify_legacy_v2_migration

# Replay evaluation trên các snapshot CVE đã pin trong manifest
evaluate-history:
	@$(PYTHON) -m scripts.run_historical_evaluation

# Build release artifact từ toolchain local; --no-build-isolation là chủ ý để offline
wheel-offline:
	@python3 -c "import setuptools, wheel; print('setuptools', setuptools.__version__, 'wheel', wheel.__version__)"
	@mkdir -p dist
	@python3 -m pip wheel --no-build-isolation --no-deps --wheel-dir dist .

# Chạy test đầy đủ
test:
	@echo "==> Bật Neo4j test container trên port 7688..."
	@$(COMPOSE) --profile test up -d --wait neo4j-test
	@echo "==> Chạy toàn bộ test suite..."
	@bash -c 'trap "$(COMPOSE) --profile test stop neo4j-test" EXIT; NEO4J_V2_TEST_URI=bolt://localhost:7688 NEO4J_V2_TEST_PASSWORD=test-password $(PYTHON) -m pytest -q'


# Chạy test offline
test-fast:
	@echo "==> Chạy test offline (không cần Docker)..."
	@$(PYTHON) -m pytest -q

# Dọn dẹp
clean: down
	@echo "==> Dọn dẹp cache Python..."
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@rm -rf .pytest_cache .cache build dist *.egg-info src/*.egg-info

.env:
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "==> Đã tạo file .env từ .env.example"; \
	fi
