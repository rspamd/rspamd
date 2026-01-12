# Rspamd Neural Embedding Service

A lightweight, CPU-optimized embedding service for Rspamd's neural plugin.

## Overview

This service provides text embeddings for Rspamd's neural LLM provider. It uses FastEmbed with ONNX Runtime for efficient CPU inference, making it suitable for servers without GPU hardware.

## Features

- **CPU-optimized**: Uses ONNX Runtime with INT8 quantization support
- **Lightweight**: ~100MB memory for bge-small-en-v1.5
- **Compatible**: Supports both Ollama and OpenAI API formats
- **Fast**: 2,500-5,000 sentences/second on modern CPUs

## Quick Start

### Option 1: Direct Python

```bash
# Install dependencies
pip install -r requirements.txt

# Run service
python embedding_service.py
```

### Option 2: Docker

```bash
# Build
docker build -t rspamd-embedding-service .

# Run
docker run -p 8080:8080 rspamd-embedding-service

# With custom model
docker run -p 8080:8080 -e EMBEDDING_MODEL="BAAI/bge-base-en-v1.5" rspamd-embedding-service
```

### Option 3: Docker Compose

See the main guide: `doc/neural-llm-embeddings-guide.md`

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `EMBEDDING_MODEL` | `BAAI/bge-small-en-v1.5` | FastEmbed model name |
| `EMBEDDING_PORT` | `8080` | Port to listen on |
| `EMBEDDING_HOST` | `0.0.0.0` | Host to bind to |

### Command Line Arguments

```bash
python embedding_service.py --help

Options:
  --model, -m     Model name (default: BAAI/bge-small-en-v1.5)
  --port, -p      Port number (default: 8080)
  --host, -H      Host to bind (default: 0.0.0.0)
  --workers, -w   Number of workers (default: 1)
  --log-level, -l Log level (default: info)
```

## API Endpoints

### Ollama Format (Recommended for Rspamd)

```bash
curl http://localhost:8080/api/embeddings -d '{
  "model": "BAAI/bge-small-en-v1.5",
  "prompt": "Test message about cheap medications"
}'
```

Response:
```json
{
  "embedding": [0.123, -0.456, ...]
}
```

### OpenAI Format

```bash
curl http://localhost:8080/v1/embeddings -d '{
  "model": "BAAI/bge-small-en-v1.5",
  "input": "Test message"
}'
```

Response:
```json
{
  "object": "list",
  "data": [{"embedding": [...], "index": 0}],
  "model": "BAAI/bge-small-en-v1.5",
  "usage": {"prompt_tokens": 2, "total_tokens": 2}
}
```

### Health Check

```bash
curl http://localhost:8080/health
```

## Rspamd Configuration

Configure Rspamd to use this service:

```hcl
# /etc/rspamd/local.d/neural.conf
rules {
  default {
    providers = [
      {
        type = "llm";
        llm_type = "ollama";  # or "openai"
        model = "BAAI/bge-small-en-v1.5";
        url = "http://localhost:8080/api/embeddings";  # or /v1/embeddings
        timeout = 2.0;
        cache_ttl = 86400;
      }
    ];
    # ...
  }
}
```

## Supported Models

| Model | Size | Dims | Quality | Speed |
|-------|------|------|---------|-------|
| `BAAI/bge-small-en-v1.5` | 33MB | 384 | Good | Excellent |
| `BAAI/bge-base-en-v1.5` | 440MB | 768 | Better | Good |
| `sentence-transformers/all-MiniLM-L6-v2` | 90MB | 384 | Fair | Excellent |
| `intfloat/e5-small-v2` | 200MB | 384 | Good | Excellent |

For the full list, see: https://qdrant.github.io/fastembed/examples/Supported_Models/

## Production Deployment

### With Gunicorn

```bash
pip install gunicorn
gunicorn -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8080 embedding_service:app
```

### Resource Recommendations

| Model | Memory | CPU Cores |
|-------|--------|-----------|
| bge-small-en-v1.5 | 256MB | 1 |
| bge-base-en-v1.5 | 1GB | 2 |

## Troubleshooting

### Model download issues

```bash
# Pre-download model
python -c "from fastembed import TextEmbedding; TextEmbedding('BAAI/bge-small-en-v1.5')"
```

### Memory issues

Use a smaller model:
```bash
EMBEDDING_MODEL="BAAI/bge-small-en-v1.5" python embedding_service.py
```

### Slow inference

- Ensure ONNX Runtime is using optimized providers
- Consider increasing workers for parallel processing
- Use batching for bulk operations

## License

Apache License 2.0

See the main Rspamd repository for license details.
