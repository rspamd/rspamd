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
| `EMBEDDING_HOST` | `0.0.0.0` | Host to bind |

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

## GPU Deployment

For higher throughput, you can run this service on a GPU. GPU inference is 10-50x faster than CPU.

### Local GPU (Docker)

```bash
# Build GPU image
docker build -f Dockerfile.gpu -t rspamd-embedding-service:gpu .

# Run with GPU access
docker run --gpus all -p 8080:8080 rspamd-embedding-service:gpu

# With larger model (GPU has more memory)
docker run --gpus all -p 8080:8080 \
  -e EMBEDDING_MODEL="BAAI/bge-large-en-v1.5" \
  rspamd-embedding-service:gpu
```

### Vast.ai Cloud GPU

[Vast.ai](https://vast.ai) provides affordable GPU rentals ($0.10-0.50/hr). This is useful for:
- Testing GPU performance before buying hardware
- Burst capacity during high-volume periods
- Running larger models that need more VRAM

#### Quick Start

```bash
# Install vast.ai CLI
pip install vastai

# Set your API key (get from https://vast.ai/console/account/)
vastai set api-key YOUR_API_KEY

# Search for available GPUs
./vastai-launch.sh --search-only

# Launch an instance
./vastai-launch.sh --model "BAAI/bge-small-en-v1.5" --gpu RTX_3090
```

#### Launch Script Options

```bash
./vastai-launch.sh [options]

Options:
  --model MODEL    Embedding model (default: BAAI/bge-small-en-v1.5)
  --gpu GPU_TYPE   GPU type filter (default: RTX_3090)
  --max-price MAX  Maximum $/hr (default: 0.30)
  --disk DISK_GB   Disk space in GB (default: 20)
  --search-only    Only search for instances, don't launch
  --show-url ID    Show service URL for a running instance
```

#### Getting the Service URL

After launching, get your service URL:

```bash
# Option 1: Use the helper
./vastai-launch.sh --show-url <INSTANCE_ID>

# Option 2: Manual lookup
vastai show instance <INSTANCE_ID>
# Look for: 8080/tcp -> 0.0.0.0:XXXXX
# Your URL is: http://<PUBLIC_IP>:XXXXX
```

**Important:** The SSH port (22) is NOT your service port. Look for port 8080's mapping.

#### Manual Vast.ai Setup

1. Go to [vast.ai/console/create](https://vast.ai/console/create/)
2. Select a GPU instance (RTX 3090 or better recommended)
3. Choose `pytorch/pytorch:2.1.0-cuda12.1-cudnn8-runtime` as the image
4. In the on-start script, add:

```bash
pip install uv
uv pip install --system "numpy<2" "transformers==4.40.0" "sentence-transformers==2.7.0" fastapi uvicorn pydantic
# Copy embedding_service.py to /root/
EMBEDDING_MODEL="intfloat/multilingual-e5-large" python /root/embedding_service.py
```

5. After the instance starts, find your service URL:
   ```bash
   # List your instances
   vastai show instances

   # Get instance details (replace ID with your instance ID)
   vastai show instance <ID>

   # Look for port mapping like: 8080/tcp -> 0.0.0.0:41234
   # Your service URL is: http://<PUBLIC_IP>:41234
   ```

6. Configure Rspamd to use `http://<PUBLIC_IP>:<MAPPED_PORT>/api/embeddings`

**Note:** Vast.ai maps container ports to random high ports. The SSH port (usually 22) is different from your service port (8080 mapped to something like 41234).

#### Recommended GPU Instances

| GPU | VRAM | Price | Use Case |
|-----|------|-------|----------|
| RTX 3090 | 24GB | $0.15-0.30/hr | Best value, handles all models |
| RTX 4090 | 24GB | $0.40-0.60/hr | Faster inference |
| A100 | 40-80GB | $1.00-2.00/hr | Very large models, batch processing |

#### Cost Estimation

| Volume | GPU Cost | Notes |
|--------|----------|-------|
| 10K emails/day | ~$3-7/month | RTX 3090, shared instance |
| 100K emails/day | ~$20-50/month | Dedicated RTX 3090 |
| 1M emails/day | ~$150-300/month | Multiple GPUs or A100 |

### GPU Requirements

| Model | VRAM | Dims | Notes |
|-------|------|------|-------|
| `intfloat/multilingual-e5-large` | 2GB | 1024 | **Recommended** - 100+ languages, excellent Russian |
| `sentence-transformers/paraphrase-multilingual-mpnet-base-v2` | 1GB | 768 | Good multilingual, smaller |
| `BAAI/bge-base-en-v1.5` | 1GB | 768 | English only, fast |
| `BAAI/bge-large-en-v1.5` | 2GB | 1024 | English only, high quality |

### Multilingual Models (Recommended for GPU)

For multilingual support including Russian, use `intfloat/multilingual-e5-large`:
- 1024-dim embeddings
- Supports 100+ languages with excellent Russian performance
- State-of-the-art on multilingual benchmarks

```bash
# Use multilingual-e5-large (default for vast.ai script)
./vastai-launch.sh --model "intfloat/multilingual-e5-large"
```

## License

Apache License 2.0

See the main Rspamd repository for license details.
