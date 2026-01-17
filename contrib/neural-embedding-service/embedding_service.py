#!/usr/bin/env python3
"""
Lightweight embedding service for Rspamd neural plugin.

Uses FastEmbed with ONNX for CPU-optimized inference.
Provides both Ollama-compatible and OpenAI-compatible endpoints.

Installation:
    pip install fastapi uvicorn fastembed pydantic

Usage:
    python embedding_service.py [--model MODEL] [--port PORT] [--host HOST]

    # Default: bge-small-en-v1.5 on port 8080
    python embedding_service.py

    # Custom model
    python embedding_service.py --model "BAAI/bge-base-en-v1.5"

    # Production with gunicorn
    gunicorn -w 4 -k uvicorn.workers.UvicornWorker embedding_service:app

Environment variables:
    EMBEDDING_MODEL: Model name (default: BAAI/bge-small-en-v1.5)
    EMBEDDING_PORT: Port number (default: 8080)
    EMBEDDING_HOST: Host to bind (default: 0.0.0.0)
"""
import argparse
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import List, Optional, Union

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# FastEmbed - CPU-optimized ONNX inference
from fastembed import TextEmbedding

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration from environment
DEFAULT_MODEL = os.getenv('EMBEDDING_MODEL', 'BAAI/bge-small-en-v1.5')
DEFAULT_PORT = int(os.getenv('EMBEDDING_PORT', '8080'))
DEFAULT_HOST = os.getenv('EMBEDDING_HOST', '0.0.0.0')

# Global model instance
model: Optional[TextEmbedding] = None
model_name: str = DEFAULT_MODEL
model_dim: int = 0

# Request/Response models
class OllamaEmbeddingRequest(BaseModel):
    """Ollama-compatible embedding request."""
    model: str = DEFAULT_MODEL
    prompt: str


class OllamaEmbeddingResponse(BaseModel):
    """Ollama-compatible embedding response."""
    embedding: List[float]


class OpenAIEmbeddingRequest(BaseModel):
    """OpenAI-compatible embedding request."""
    model: str = DEFAULT_MODEL
    input: Union[str, List[str]]
    encoding_format: str = "float"


class OpenAIEmbeddingData(BaseModel):
    """OpenAI embedding data object."""
    object: str = "embedding"
    embedding: List[float]
    index: int


class OpenAIUsage(BaseModel):
    """OpenAI usage object."""
    prompt_tokens: int
    total_tokens: int


class OpenAIEmbeddingResponse(BaseModel):
    """OpenAI-compatible embedding response."""
    object: str = "list"
    data: List[OpenAIEmbeddingData]
    model: str
    usage: OpenAIUsage


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    model: str
    dimensions: int
    uptime_seconds: float

# Startup time for uptime calculation
startup_time: float = 0.0


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load model on startup."""
    global model, model_name, model_dim, startup_time

    logger.info(f"Loading embedding model: {model_name}")
    start = time.time()

    model = TextEmbedding(model_name)
    test_embed = list(model.embed(["test"]))[0]
    model_dim = len(test_embed)
    elapsed = time.time() - start
    logger.info(f"Model loaded in {elapsed:.2f}s, dimensions: {model_dim}")
    startup_time = time.time()

    yield

    logger.info("Shutting down embedding service")


app = FastAPI(
    title="Rspamd Embedding Service",
    description="CPU-optimized embedding service for Rspamd neural plugin",
    version="1.0.0",
    lifespan=lifespan,
)


def get_embedding(text: str) -> List[float]:
    """Generate embedding for a single text."""
    if model is None:
        raise HTTPException(500, "Model not loaded")

    embeddings = list(model.embed([text]))
    return embeddings[0].tolist()


def get_embeddings_batch(texts: List[str]) -> List[List[float]]:
    """Generate embeddings for multiple texts."""
    if model is None:
        raise HTTPException(500, "Model not loaded")

    embeddings = list(model.embed(texts))
    return [e.tolist() for e in embeddings]


def count_tokens(text: str) -> int:
    """Approximate token count (words * 1.3)."""
    return int(len(text.split()) * 1.3)


@app.post("/api/embeddings", response_model=OllamaEmbeddingResponse)
async def ollama_embeddings(request: OllamaEmbeddingRequest) -> OllamaEmbeddingResponse:
    """
    Ollama-compatible embedding endpoint.

    Used by Rspamd neural LLM provider with llm_type = "ollama".
    """
    if not request.prompt:
        raise HTTPException(400, "Missing prompt")

    logger.debug(f"Ollama request: {len(request.prompt)} chars")
    embedding = get_embedding(request.prompt)

    return OllamaEmbeddingResponse(embedding=embedding)


@app.post("/v1/embeddings", response_model=OpenAIEmbeddingResponse)
async def openai_embeddings(request: OpenAIEmbeddingRequest) -> OpenAIEmbeddingResponse:
    """
    OpenAI-compatible embedding endpoint.

    Used by Rspamd neural LLM provider with llm_type = "openai".
    """
    if not request.input:
        raise HTTPException(400, "Missing input")

    # Handle single string or list of strings
    if isinstance(request.input, str):
        texts = [request.input]
    else:
        texts = request.input

    logger.debug(f"OpenAI request: {len(texts)} texts")
    embeddings = get_embeddings_batch(texts)

    # Build response
    data = [
        OpenAIEmbeddingData(embedding=emb, index=i)
        for i, emb in enumerate(embeddings)
    ]

    total_tokens = sum(count_tokens(t) for t in texts)

    return OpenAIEmbeddingResponse(
        data=data,
        model=request.model,
        usage=OpenAIUsage(prompt_tokens=total_tokens, total_tokens=total_tokens)
    )


@app.get("/health", response_model=HealthResponse)
@app.get("/", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Health check endpoint."""
    return HealthResponse(
        status="ok" if model is not None else "loading",
        model=model_name,
        dimensions=model_dim,
        uptime_seconds=time.time() - startup_time if startup_time > 0 else 0
    )


@app.get("/v1/models")
async def list_models():
    """List available models (OpenAI-compatible)."""
    return {
        "object": "list",
        "data": [
            {
                "id": model_name,
                "object": "model",
                "created": int(startup_time),
                "owned_by": "fastembed",
                "permission": [],
                "root": model_name,
            }
        ]
    }


def main():
    """Run the embedding service."""
    global model_name

    parser = argparse.ArgumentParser(
        description="Rspamd embedding service",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--model", "-m",
        default=DEFAULT_MODEL,
        help="FastEmbed model name"
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=DEFAULT_PORT,
        help="Port to listen on"
    )
    parser.add_argument(
        "--host", "-H",
        default=DEFAULT_HOST,
        help="Host to bind to"
    )
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=1,
        help="Number of worker processes"
    )
    parser.add_argument(
        "--log-level", "-l",
        default="info",
        choices=["debug", "info", "warning", "error"],
        help="Log level"
    )

    args = parser.parse_args()
    model_name = args.model

    import uvicorn
    uvicorn.run(
        "embedding_service:app",
        host=args.host,
        port=args.port,
        workers=args.workers,
        log_level=args.log_level,
    )


if __name__ == "__main__":
    main()
