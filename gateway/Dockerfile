# AEGIS v2 gateway — light, offline-capable image (heuristic detector profile).
# Enable real ML models by adding the `ml` extra (see comment below).
FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUTF8=1

WORKDIR /app

# Install core deps only (fast build, no heavy ML downloads).
COPY pyproject.toml ./
RUN pip install --upgrade pip && pip install .

# To enable real fine-tuned models instead of heuristics, rebuild with:
#   RUN pip install ".[ml]"

COPY app ./app
COPY rules ./rules
COPY policies ./policies

# Run as non-root (secure by default).
RUN useradd --create-home --uid 10001 aegis && chown -R aegis /app
USER aegis

EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8080/healthz').status==200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
