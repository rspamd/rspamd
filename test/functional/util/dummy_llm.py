#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

import dummy_killer

PID = "/tmp/dummy_llm.pid"


def make_embedding(text: str, dim: int = 32):
    # Deterministic: if text contains 'SPAM' (case-insensitive) -> ones; else zeros
    if 'spam' in text.lower():
        return [1.0] * dim
    return [0.0] * dim


class EmbeddingHandler(BaseHTTPRequestHandler):
    # OpenAI-like embeddings API
    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        raw = self.rfile.read(length) if length > 0 else b''
        try:
            data = json.loads(raw.decode('utf-8') or '{}')
        except Exception:
            data = {}

        # Support both OpenAI ({input, model}) and Ollama ({prompt, model}) shapes
        text = data.get('input') or data.get('prompt') or ''
        # Optional dimension override for tests
        dim = int(data.get('dim') or 32)
        emb = make_embedding(text, dim)

        if 'openai' in (self.headers.get('User-Agent') or '').lower() or True:
            # Always reply in OpenAI-like format expected by neural provider
            body = {
                "data": [
                    {"embedding": emb}
                ]
            }
        else:
            body = {"embedding": emb}

        reply = json.dumps(body).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, fmt, *args):
        # Keep test output quiet
        return


if __name__ == "__main__":
    alen = len(sys.argv)
    if alen > 1:
        port = int(sys.argv[1])
    else:
        port = 18080
    server = HTTPServer(("127.0.0.1", port), EmbeddingHandler)
    dummy_killer.write_pid(PID)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
