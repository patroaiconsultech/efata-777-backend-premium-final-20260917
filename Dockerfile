FROM python:3.12-slim@sha256:876416ecde9aca2bcc90e1fb0c7a9500bbf749f5788b70f82d4c5a5c2357f8b4
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    PLATFORM_STT_MODEL_CACHE_DIR=/opt/orkio/models/faster-whisper
COPY pyproject.toml uv.lock requirements.lock.txt alembic.ini ./
COPY migrations ./migrations
COPY scripts ./scripts
COPY src ./src
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock.txt \
    && DATABASE_URL='sqlite+pysqlite:///:memory:' \
       PLATFORM_ENVIRONMENT=test \
       PLATFORM_AUTH_MODE=test \
       python -c "import faster_whisper; import orkio_v2.main; print('STT_DEPENDENCY_PRESENT')"
ARG ORKIO_STT_PREWARM_MODEL=""
RUN mkdir -p "${PLATFORM_STT_MODEL_CACHE_DIR}" \
    && if [ -n "${ORKIO_STT_PREWARM_MODEL}" ]; then \
         PLATFORM_STT_PROVIDER=faster_whisper \
         PLATFORM_STT_MODEL="${ORKIO_STT_PREWARM_MODEL}" \
         PLATFORM_STT_LOCAL_FILES_ONLY=false \
         python scripts/prewarm_stt.py; \
       else \
         echo "STT model prewarm skipped; set ORKIO_STT_PREWARM_MODEL at build time to bake a model cache."; \
       fi
RUN groupadd --system --gid 10001 orkio \
    && useradd --system --uid 10001 --gid 10001 --create-home --home-dir /home/orkio orkio \
    && mkdir -p /opt/orkio/models/faster-whisper /app/data/artifacts /app/data/tts-cache \
    && chown -R orkio:orkio /app /opt/orkio /home/orkio
ENV HOME=/home/orkio
USER orkio
EXPOSE 8080
CMD ["uvicorn","orkio_v2.main:app","--host","0.0.0.0","--port","8080"]
