# Benchmark + red-team runner. Runs fully offline (stdlib detectors); matplotlib
# is optional and only used to render charts.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONUTF8=1
WORKDIR /work

# Charts are optional; the report degrades to tables if matplotlib is absent.
RUN pip install --no-cache-dir matplotlib==3.9.0 || true

COPY gateway/app /work/gateway/app
COPY gateway/rules /work/gateway/rules
COPY gateway/policies /work/gateway/policies
COPY benchmark /work/benchmark
COPY redteam /work/redteam

CMD ["python", "-m", "benchmark.run_benchmark"]
