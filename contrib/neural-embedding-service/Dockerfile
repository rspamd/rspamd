# Rspamd Neural Embedding Service
#
# CPU-optimized embedding service using FastEmbed + ONNX Runtime
#
# Build:
#   docker build -t rspamd-embedding-service .
#
# Run:
#   docker run -p 8080:8080 rspamd-embedding-service
#
# With custom model:
#   docker run -p 8080:8080 -e EMBEDDING_MODEL="BAAI/bge-base-en-v1.5" rspamd-embedding-service

FROM python:3.11-slim

# Build arguments
ARG EMBEDDING_MODEL="BAAI/bge-small-en-v1.5"

# Environment
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    EMBEDDING_MODEL=${EMBEDDING_MODEL} \
    EMBEDDING_PORT=8080 \
    EMBEDDING_HOST=0.0.0.0

# Install system dependencies for ONNX Runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-download model during build (optional, makes container larger but faster startup)
# Uncomment to include model in image:
# RUN python -c "from fastembed import TextEmbedding; TextEmbedding('${EMBEDDING_MODEL}')"

# Copy application
COPY embedding_service.py .

# Non-root user
RUN useradd -m -u 1000 embedding && chown -R embedding:embedding /app
USER embedding

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

# Run with uvicorn
CMD ["python", "embedding_service.py"]
