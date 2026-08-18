# AEGIS v2 — developer entrypoints (R2).
.PHONY: up down test bench bench-surfaces bench-audit bench-all seed redteam \
        lint console modelscan loadtest backup verify-models

# Bring up the full stack (gateway + redis + postgres + dashboard), offline.
up:
	docker compose up --build

down:
	docker compose down -v

# Run the test suite. Uses pytest if available, else stdlib unittest (offline).
test:
	cd gateway && (python -m pytest -q || python -m unittest discover -s tests -p "test_*.py")

# Lint. compileall is the stdlib floor and always runs; ruff runs when present.
# A missing ruff is reported, never silently skipped.
lint:
	python -m compileall -q gateway/app benchmark redteam loadtest scripts
	@if command -v ruff >/dev/null 2>&1; then \
		ruff check gateway/app benchmark redteam loadtest scripts; \
	else \
		echo "NOTE: ruff not installed — ran compileall only (pip install ruff)"; \
	fi

# Benchmark + red-team + report (writes benchmark/out/). Offline, real numbers.
bench:
	python -m benchmark.run_benchmark

# Surface benchmark: indirect prompt injection across all seven surfaces,
# measured against the v2.0 prompt firewall on the same artifacts flattened.
bench-surfaces:
	python -m benchmark.run_surface_benchmark

# Audit benchmark: before/after for the v2.1 hardening (whole-conversation
# coverage + structural injection). See docs/HARDENING.md.
bench-audit:
	python -m benchmark.run_audit_benchmark

bench-all: bench bench-surfaces bench-audit redteam

# Materialize the labeled datasets (cached JSONL copies).
seed:
	python -m benchmark.datasets

# Red-team evasion sweep only.
redteam:
	python -m redteam.run_redteam

# CI model-supply-chain scan: fail on any non-safetensors checkpoint (S3).
# Scans the whole repo root, matching .github/workflows/ci.yml, so a stray
# checkpoint outside models/ is caught too. No `|| true` — this gate must fail.
modelscan:
	cd gateway && python -m app.security.modelscan ..

# Quick local inspection console (no server needed).
console:
	cd gateway && python -m app.cli

# Load test (in-process, single worker) — real throughput + latency numbers.
loadtest:
	python -m loadtest.run_load --requests 5000 --concurrency 50

# Postgres backup / restore (audit is the system of record).
backup:
	./scripts/backup.sh

# Verify pinned model integrity offline (S3).
verify-models:
	python scripts/fetch_models.py --verify
