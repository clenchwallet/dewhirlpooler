FROM python:3.12-slim-bookworm AS builder

WORKDIR /build

COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m pip wheel --no-cache-dir --wheel-dir /wheels .


FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEWHIRLPOOLER_CACHE_PATH=/data/reports.sqlite3

WORKDIR /app

COPY --from=builder /wheels /wheels

RUN python -m pip install --no-cache-dir --no-index --find-links=/wheels \
        /wheels/dewhirlpooler-*.whl \
    && groupadd --gid 10001 dewhirlpooler \
    && useradd --uid 10001 --gid 10001 --home-dir /nonexistent \
        --no-create-home --shell /usr/sbin/nologin dewhirlpooler \
    && mkdir -p /data \
    && chown 10001:10001 /app /data \
    && rm -rf /wheels

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).read()"]

CMD ["uvicorn", "dewhirlpooler.web:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
