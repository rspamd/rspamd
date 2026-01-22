#!/bin/bash
# Rspamd Neural Embedding Service - Vast.ai Launch Script
#
# This script helps launch the embedding service on vast.ai GPU instances.
#
# Prerequisites:
#   1. Install vastai CLI: pip install vastai
#   2. Set API key: vastai set api-key YOUR_API_KEY
#
# Usage:
#   ./vastai-launch.sh [options]
#
# Options:
#   --model MODEL    Embedding model (default: BAAI/bge-small-en-v1.5)
#   --gpu GPU_TYPE   GPU type filter (default: RTX_3090)
#   --max-price MAX  Maximum $/hr (default: 0.30)
#   --disk DISK_GB   Disk space in GB (default: 20)
#   --search-only    Only search for instances, don't launch
#   --show-url ID    Show service URL for a running instance
#   --help           Show this help message

set -e

# Defaults - use multilingual-e5-large for GPU (supports Russian and 100+ languages)
MODEL="${EMBEDDING_MODEL:-intfloat/multilingual-e5-large}"
GPU_TYPE="RTX_3090"
MAX_PRICE="0.30"
DISK_GB="20"
SEARCH_ONLY=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --model)
            MODEL="$2"
            shift 2
            ;;
        --gpu)
            GPU_TYPE="$2"
            shift 2
            ;;
        --max-price)
            MAX_PRICE="$2"
            shift 2
            ;;
        --disk)
            DISK_GB="$2"
            shift 2
            ;;
        --search-only)
            SEARCH_ONLY=true
            shift
            ;;
        --show-url)
            # Show service URL for a running instance
            if [ -z "$2" ]; then
                echo "Usage: $0 --show-url <INSTANCE_ID>"
                exit 1
            fi
            echo "Getting connection info for instance $2..."
            INFO=$(vastai show instance "$2" --raw 2>/dev/null)
            if [ $? -ne 0 ]; then
                echo "Error: Could not get instance info"
                exit 1
            fi

            SSH_HOST=$(echo "$INFO" | grep -oE '"ssh_host": "[^"]+"' | cut -d'"' -f4)
            SSH_PORT=$(echo "$INFO" | grep -oE '"ssh_port": [0-9]+' | grep -oE '[0-9]+')
            PUBLIC_IP=$(echo "$INFO" | grep -oE '"public_ipaddr": "[^"]+"' | cut -d'"' -f4)
            STATUS=$(echo "$INFO" | grep -oE '"actual_status": "[^"]+"' | cut -d'"' -f4)

            echo ""
            echo "Instance Status: $STATUS"
            echo "Public IP: $PUBLIC_IP"
            echo "SSH: ssh -p $SSH_PORT root@$SSH_HOST"
            echo ""
            echo "=== Access Methods ==="
            echo ""
            echo "Option 1: SSH Tunnel (recommended for testing)"
            echo "  Run this in a separate terminal:"
            echo "    ssh -L 8080:localhost:8080 -p $SSH_PORT root@$SSH_HOST"
            echo "  Then access: http://localhost:8080/health"
            echo ""
            echo "Option 2: Direct access via public IP"
            echo "  First, SSH in and check if the service is running:"
            echo "    ssh -p $SSH_PORT root@$SSH_HOST"
            echo "    curl localhost:8080/health"
            echo ""
            echo "  If running, access via: http://$PUBLIC_IP:8080"
            echo "  (Note: May require firewall/port config on vast.ai)"
            echo ""
            exit 0
            ;;
        --help)
            head -25 "$0" | tail -20
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check vastai CLI
if ! command -v vastai &> /dev/null; then
    echo "Error: vastai CLI not found. Install with: pip install vastai"
    exit 1
fi

# Startup script that runs inside the vast.ai instance
ONSTART_SCRIPT=$(cat << 'SCRIPT'
#!/bin/bash
set -e

# Install dependencies using uv (10-100x faster than pip)
pip install uv
# Use sentence-transformers with PyTorch CUDA (pinned versions for compatibility)
uv pip install --system "numpy<2" "transformers==4.40.0" "sentence-transformers==2.7.0" fastapi uvicorn[standard] pydantic

# Create embedding service
cat > /root/embedding_service.py << 'EOF'
import os
import logging
from typing import List, Union, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

# Use sentence-transformers with PyTorch CUDA
from sentence_transformers import SentenceTransformer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Rspamd Embedding Service (GPU)")

# Configuration
MODEL_NAME = os.environ.get("EMBEDDING_MODEL", "intfloat/multilingual-e5-large")

# Initialize model on CUDA
logger.info(f"Loading model {MODEL_NAME} on CUDA...")
model = SentenceTransformer(MODEL_NAME, device="cuda")
logger.info(f"Loaded {MODEL_NAME} on {model.device}")

class OllamaRequest(BaseModel):
    model: str
    prompt: str

class OllamaResponse(BaseModel):
    embedding: List[float]

class OpenAIRequest(BaseModel):
    model: str
    input: Union[str, List[str]]

class EmbeddingData(BaseModel):
    embedding: List[float]
    index: int
    object: str = "embedding"

class OpenAIResponse(BaseModel):
    object: str = "list"
    data: List[EmbeddingData]
    model: str
    usage: dict

def get_embeddings(texts: List[str]) -> List[List[float]]:
    embs = model.encode(texts, convert_to_numpy=True)
    return [emb.tolist() for emb in embs]

@app.get("/health")
async def health():
    return {"status": "ok", "model": MODEL_NAME, "device": str(model.device)}

@app.post("/api/embeddings", response_model=OllamaResponse)
async def ollama_embeddings(request: OllamaRequest):
    try:
        embeddings = get_embeddings([request.prompt])
        return OllamaResponse(embedding=embeddings[0])
    except Exception as e:
        logger.error(f"Embedding error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/v1/embeddings", response_model=OpenAIResponse)
async def openai_embeddings(request: OpenAIRequest):
    try:
        texts = [request.input] if isinstance(request.input, str) else request.input
        embeddings = get_embeddings(texts)
        data = [EmbeddingData(embedding=emb, index=i) for i, emb in enumerate(embeddings)]
        return OpenAIResponse(
            data=data,
            model=request.model,
            usage={"prompt_tokens": len(texts), "total_tokens": len(texts)}
        )
    except Exception as e:
        logger.error(f"Embedding error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    port = int(os.environ.get("EMBEDDING_PORT", "8080"))
    host = os.environ.get("EMBEDDING_HOST", "0.0.0.0")
    uvicorn.run(app, host=host, port=port)
EOF

# Start service
cd /root
EMBEDDING_MODEL="${EMBEDDING_MODEL}" python embedding_service.py &

echo "Embedding service started on port 8080"
SCRIPT
)

echo "=== Rspamd Embedding Service - Vast.ai Launcher ==="
echo "Model: $MODEL"
echo "GPU: $GPU_TYPE"
echo "Max price: \$$MAX_PRICE/hr"
echo ""

# Search for available instances
echo "Searching for available instances..."
QUERY="gpu_name=$GPU_TYPE rentable=true dph<$MAX_PRICE disk_space>=$DISK_GB cuda_vers>=12.0"

vastai search offers "$QUERY" --order 'dph' | head -20

if [ "$SEARCH_ONLY" = true ]; then
    echo ""
    echo "Search only mode. To launch, run without --search-only"
    exit 0
fi

echo ""
read -p "Enter instance ID to rent (or 'q' to quit): " INSTANCE_ID

if [ "$INSTANCE_ID" = "q" ]; then
    echo "Aborted."
    exit 0
fi

# Create the instance
echo "Creating instance $INSTANCE_ID..."
vastai create instance "$INSTANCE_ID" \
    --image pytorch/pytorch:2.1.0-cuda12.1-cudnn8-runtime \
    --disk "$DISK_GB" \
    --env "EMBEDDING_MODEL=$MODEL" \
    --onstart-cmd "$ONSTART_SCRIPT"

echo ""
echo "Instance created! Monitor with: vastai show instances"
echo ""
echo "=== Finding your service URL ==="
echo ""
echo "1. Wait for instance to be 'running': vastai show instances"
echo ""
echo "2. Get the public URL (port 8080 is mapped to a random port):"
echo "   vastai show instance <INSTANCE_ID>"
echo ""
echo "   Look for 'ports' section, e.g.:"
echo "     8080/tcp -> 0.0.0.0:41234"
echo "   This means your service is at: http://<PUBLIC_IP>:41234"
echo ""
echo "3. Or use SSH tunnel for testing:"
echo "   vastai ssh-url <INSTANCE_ID>"
echo "   ssh -L 8080:localhost:8080 <SSH_COMMAND>"
echo "   Then use: http://localhost:8080"
echo ""
echo "4. Configure Rspamd with the public URL:"
echo ""
echo "  neural {"
echo "    rules {"
echo "      default {"
echo "        providers = ["
echo "          {"
echo "            type = \"llm\";"
echo "            llm_type = \"ollama\";"
echo "            model = \"$MODEL\";"
echo "            url = \"http://<PUBLIC_IP>:<MAPPED_PORT>/api/embeddings\";"
echo "          }"
echo "        ];"
echo "      }"
echo "    }"
echo "  }"
echo ""
echo "5. Test the endpoint:"
echo "   curl http://<PUBLIC_IP>:<MAPPED_PORT>/health"
