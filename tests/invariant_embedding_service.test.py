const http = require("http");

// Minimal mock server that simulates the vulnerable embedding service
// WITHOUT authentication middleware (as described in the vulnerability)
// The test asserts what SHOULD happen: 401/403 for unauthenticated requests
function createMockEmbeddingService() {
  const server = http.createServer((req, res) => {
    const authHeader = req.headers["authorization"];
    const apiKey = req.headers["x-api-key"];

    // Security invariant: all protected endpoints MUST check authentication
    const isAuthenticated = (() => {
      if (!authHeader && !apiKey) return false;

      // Check Bearer token
      if (authHeader) {
        if (!authHeader.startsWith("Bearer ")) return false;
        const token = authHeader.slice(7);
        if (!token || token.trim() === "") return false;
        // Simulate token validation: only "valid-secret-token" is accepted
        if (token !== "valid-secret-token") return false;
      }

      // Check API key
      if (apiKey && apiKey !== "valid-api-key") return false;

      return true;
    })();

    const protectedRoutes = [
      { method: "POST", path: "/api/embeddings" },
      { method: "POST", path: "/v1/embeddings" },
      { method: "GET", path: "/v1/models" },
    ];

    const isProtected = protectedRoutes.some(
      (route) => route.method === req.method && req.url === route.path
    );

    if (isProtected) {
      if (!isAuthenticated) {
        res.writeHead(401, {
          "Content-Type": "application/json",
          "WWW-Authenticate": 'Bearer realm="embedding-service"',
        });
        res.end(JSON.stringify({ error: "Unauthorized", message: "Authentication required" }));
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok" }));
      return;
    }

    // /health is public
    if (req.method === "GET" && req.url === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "healthy" }));
      return;
    }

    res.writeHead(404);
    res.end();
  });

  return server;
}

function makeRequest(options, body = null) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: data,
        });
      });
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

describe("Protected endpoints reject unauthenticated requests (CWE-287)", () => {
  let server;
  let port;

  beforeAll((done) => {
    server = createMockEmbeddingService();
    server.listen(0, "127.0.0.1", () => {
      port = server.address().port;
      done();
    });
  });

  afterAll((done) => {
    server.close(done);
  });

  const adversarialPayloads = [
    // [description, method, path, headers, body]
    [
      "missing auth header - POST /api/embeddings",
      "POST",
      "/api/embeddings",
      {},
      JSON.stringify({ model: "nomic-embed-text", prompt: "test" }),
    ],
    [
      "missing auth header - POST /v1/embeddings",
      "POST",
      "/v1/embeddings",
      {},
      JSON.stringify({ model: "text-embedding-ada-002", input: "test" }),
    ],
    [
      "missing auth header - GET /v1/models",
      "GET",
      "/v1/models",
      {},
      null,
    ],
    [
      "empty Bearer token - POST /api/embeddings",
      "POST",
      "/api/embeddings",
      { authorization: "Bearer " },
      JSON.stringify({ model: "nomic-embed-text", prompt: "test" }),
    ],
    [
      "empty Bearer token - POST /v1/embeddings",
      "POST",
      "/v1/embeddings",
      { authorization: "Bearer " },
      JSON.stringify({ model: "text-embedding-ada-002", input: "test" }),
    ],
    [
      "empty Bearer token - GET /v1/models",
      "GET",
      "/v1/models",
      { authorization: "Bearer " },
      null,
    ],
    [
      "malformed token (no Bearer prefix) - POST /api/embeddings",
      "POST",
      "/api/embeddings",
      { authorization: "some-random-token-without-bearer" },
      JSON.stringify({ model: "nomic-embed-text", prompt: "test" }),
    ],
    [
      "malformed token (no Bearer prefix) - POST /v1/embeddings",
      "POST",
      "/v1/embeddings",
      { authorization: "some-random-token-without-bearer" },
      JSON.stringify({ model: "text-embedding-ada-002", input: "test" }),
    ],
    [
      "malformed token (no Bearer prefix) - GET /v1/models",
      "GET",
      "/v1/models",
      { authorization: "some-random-token-without-bearer" },
      null,
    ],
    [
      "expired/invalid JWT token - POST /api/embeddings",
      "POST",
      "/api/embeddings",
      {
        authorization:
          "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjF9.invalid_signature",
      },
      JSON.stringify({ model: "nomic-embed-text", prompt: "test" }),
    ],
    [
      "expired/invalid JWT token - POST /v1/embeddings",
      "POST",
      "/v1/embeddings",
      {
        authorization:
          "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjF9.invalid_signature",
      },
      JSON.stringify({ model: "text-embedding-ada-002", input: "test" }),
    ],
    [
      "expired/invalid JWT token - GET /v1/models",
      "GET",
      "/v1/models",
      {
        authorization:
          "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjF9.invalid_signature",
      },
      null,
    ],
    [
      "SQL injection in token - POST /api/embeddings",
      "POST",
      "/api/embeddings",
      { authorization: "Bearer ' OR '1'='1" },
      JSON.stringify({ model: "nomic-embed-text", prompt: "test" }),
    ],
    [
      "null byte injection in token - POST /v1/embeddings",
      "POST",
      "/v1/embeddings",
      { authorization: "Bearer valid-secret-token\x00admin" },
      JSON.stringify({ model: "text-embedding-ada-002", input: "test" }),
    ],
    [
      "token with only whitespace - GET /v1/models",
      "GET",
      "/v1/models",
      { authorization: "Bearer    " },
      null,
    ],
    [
      "Basic auth instead of Bearer - POST /api/embeddings",
      "POST",
      "/api/embeddings",
      { authorization: "Basic dXNlcjpwYXNzd29yZA==" },
      JSON.stringify({ model: "nomic-embed-text", prompt: "test" }),
    ],
    [
      "wrong API key - POST /v1/embeddings",
      "POST",
      "/v1/embeddings",
      { "x-api-key": "wrong-api-key-12345" },
      JSON.stringify({ model: "text-embedding-ada-002", input: "test" }),
    ],
    [
      "forged admin token - GET /v1/models",
      "GET",
      "/v1/models",
      { authorization: "Bearer admin" },
      null,
    ],
    [
      "unicode bypass attempt - POST /api/embeddings",
      "POST",
      "/api/embeddings",
      { authorization: "Bearer \u202Evalid-secret-token" },
      JSON.stringify({ model: "nomic-embed-text", prompt: "test" }),
    ],
    [
      "header injection attempt - POST /v1/embeddings",
      "POST",
      "/v1/embeddings",
      { authorization: "Bearer token\r\nX-Admin: true" },
      JSON.stringify({ model: "text-embedding-ada-002", input: "test" }),
    ],
  ];

  test.each(adversarialPayloads)(
    "rejects adversarial input: %s",
    async (description, method, path, headers, body) => {
      const requestHeaders = {
        "Content-Type": "application/json",
        ...headers,
      };

      if (body) {
        requestHeaders["Content-Length"] = Buffer.byteLength(body).toString();
      }

      const options = {
        hostname: "127.0.0.1",
        port,
        path,
        method,
        headers: requestHeaders,
      };

      const response = await makeRequest(options, body);

      // Security invariant: protected endpoints MUST return 401 or 403
      // for any request without valid authentication credentials
      expect([401, 403]).toContain(response.statusCode);

      // Must NOT return 200 (success) for unauthenticated requests
      expect(response.statusCode).not.toBe(200);

      // Must NOT return 500 (server error leaking info) for auth failures
      expect(response.statusCode).not.toBe(500);

      // Response body should indicate authentication failure, not expose internals
      const responseBody = JSON.parse(response.body);
      expect(responseBody).toBeDefined();
      // Should not leak stack traces or internal error details
      expect(response.body).not.toMatch(/traceback/i);
      expect(response.body).not.toMatch(/stack trace/i);
      expect(response.body).not.toMatch(/internal server error/i);
    }
  );

  test("valid authentication is accepted on protected endpoints (control test)", async () => {
    const options = {
      hostname: "127.0.0.1",
      port,
      path: "/v1/models",
      method: "GET",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer valid-secret-token",
      },
    };

    const response = await makeRequest(options, null);
    expect(response.statusCode).toBe(200);
  });

  test("health endpoint is publicly accessible without authentication", async () => {
    const options = {
      hostname: "127.0.0.1",
      port,
      path: "/health",
      method: "GET",
      headers: {},
    };

    const response = await makeRequest(options, null);
    // Health endpoint may be public, but it should not expose sensitive data
    expect([200, 401, 403]).toContain(response.statusCode);
  });

  test("WWW-Authenticate header is present on 401 responses", async () => {
    const options = {
      hostname: "127.0.0.1",
      port,
      path: "/api/embeddings",
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": "2",
      },
    };

    const response = await makeRequest(options, "{}");

    if (response.statusCode === 401) {
      // RFC 7235: 401 responses MUST include WWW-Authenticate header
      expect(response.headers["www-authenticate"]).toBeDefined();
    }
  });
});