#!/usr/bin/env python3
"""
A deliberately "buggy" HTTP server that sends early responses before
reading the full client request. This is used to test rspamd's HTTP
client handling of edge cases that are allowed by HTTP/1.1 spec.

Scenarios implemented:
1. /early-reply - Send response immediately after reading headers, before body
2. /early-error-413 - Send 413 error and close after reading just the request line
3. /early-error-close - Send error and immediately close connection (no keep-alive)
4. /keepalive-early - Send response early but keep connection alive
5. /slow-read-fast-reply - Read request very slowly but reply quickly
"""

import asyncio
import argparse
import sys
import os

# Add parent directory to path for dummy_killer
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dummy_killer


class EarlyResponseServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.server = None

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a single client connection."""
        addr = writer.get_extra_info('peername')
        print(f"Connection from {addr}", file=sys.stderr)

        try:
            # Read just the request line first
            request_line = await asyncio.wait_for(reader.readline(), timeout=10.0)
            if not request_line:
                return

            request_line = request_line.decode('utf-8', errors='replace').strip()
            print(f"Request line: {request_line}", file=sys.stderr)

            parts = request_line.split(' ')
            if len(parts) < 2:
                return

            method = parts[0]
            path = parts[1]

            # For /instant-reply, send response BEFORE even reading headers
            # This is the most aggressive early response - client is still sending headers+body
            if path == '/instant-reply':
                print(f"instant-reply: sending 413 BEFORE reading headers!", file=sys.stderr)
                await self._send_response(writer, 413, "Request Entity Too Large",
                                          {"Content-Type": "text/plain", "Connection": "close"},
                                          b"Instant 413 - rejected at request line")
                await writer.drain()
                print(f"instant-reply: response sent, closing", file=sys.stderr)
                return  # Close without reading anything else

            # Read headers (but we might not read body depending on path)
            headers = {}
            content_length = 0
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=10.0)
                if not line or line == b'\r\n' or line == b'\n':
                    break
                line = line.decode('utf-8', errors='replace').strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
                    if key.strip().lower() == 'content-length':
                        content_length = int(value.strip())

            print(f"Headers received, Content-Length: {content_length}", file=sys.stderr)

            # Handle different test scenarios based on path
            if path == '/early-reply':
                # Send response immediately WITHOUT reading body
                # This tests client handling when server replies before body is fully sent
                await self._send_response(writer, 200, "OK",
                                          {"Content-Type": "text/plain", "Connection": "close"},
                                          b"early reply - body not read")
                # Now try to drain remaining data
                if content_length > 0:
                    try:
                        remaining = await asyncio.wait_for(reader.read(content_length), timeout=1.0)
                        print(f"Drained {len(remaining)} bytes of body", file=sys.stderr)
                    except asyncio.TimeoutError:
                        print("Timeout draining body", file=sys.stderr)

            elif path == '/early-error-413':
                # Send 413 immediately and close - simulates "request too large"
                # Don't even try to read the body
                await self._send_response(writer, 413, "Request Entity Too Large",
                                          {"Content-Type": "text/plain", "Connection": "close"},
                                          b"Request body too large")
                # Close immediately without reading body

            elif path == '/early-error-close':
                # Send error and close connection abruptly
                await self._send_response(writer, 500, "Internal Server Error",
                                          {"Content-Type": "text/plain", "Connection": "close"},
                                          b"Server error - closing")

            elif path == '/keepalive-early':
                # Send response early but indicate keep-alive
                # This tests if client can handle early response + continue with keepalive
                await self._send_response(writer, 200, "OK",
                                          {"Content-Type": "text/plain",
                                           "Connection": "keep-alive",
                                           "Keep-Alive": "timeout=30"},
                                          b"early keepalive response")
                # Read the body to properly maintain connection state
                if content_length > 0:
                    body = await asyncio.wait_for(reader.read(content_length), timeout=5.0)
                    print(f"Read body: {len(body)} bytes", file=sys.stderr)

                # Wait for potential next request on keep-alive connection
                try:
                    next_line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                    if next_line:
                        print(f"Keep-alive follow-up: {next_line}", file=sys.stderr)
                        # Handle second request simply
                        while True:
                            line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                            if not line or line == b'\r\n':
                                break
                        await self._send_response(writer, 200, "OK",
                                                  {"Content-Type": "text/plain", "Connection": "close"},
                                                  b"second response on keepalive")
                except asyncio.TimeoutError:
                    print("No follow-up request on keepalive", file=sys.stderr)

            elif path == '/slow-read-fast-reply':
                # Start reading body very slowly, but send reply quickly
                # This creates a race condition
                await self._send_response(writer, 200, "OK",
                                          {"Content-Type": "text/plain", "Connection": "close"},
                                          b"fast reply while slowly reading")
                # Now slowly read
                if content_length > 0:
                    read_so_far = 0
                    while read_so_far < content_length:
                        chunk = await reader.read(min(100, content_length - read_so_far))
                        if not chunk:
                            break
                        read_so_far += len(chunk)
                        await asyncio.sleep(0.1)  # Slow down

            elif path == '/partial-read-then-reply':
                # Read only part of the body, then send response
                if content_length > 0:
                    # Read only first 100 bytes
                    partial = await reader.read(min(100, content_length))
                    print(f"Read partial body: {len(partial)} bytes", file=sys.stderr)

                await self._send_response(writer, 200, "OK",
                                          {"Content-Type": "text/plain", "Connection": "close"},
                                          b"response after partial body read")

            elif path == '/immediate-close-413':
                # Send 413 and close socket IMMEDIATELY without reading anything else
                # This is the most aggressive case - RST may be sent if client is still writing
                await self._send_response(writer, 413, "Request Entity Too Large",
                                          {"Content-Type": "text/plain", "Connection": "close"},
                                          b"Too large - closing immediately")
                # Force close without draining - this should cause client write to fail
                writer.transport.abort()  # Forceful close
                return  # Skip normal close

            elif path == '/block-and-reply':
                # TRUE early response test:
                # Send response IMMEDIATELY after headers, before body starts.
                # The client should receive this while still preparing/sending body.
                print(f"block-and-reply: sending 413 IMMEDIATELY (content-length={content_length})", file=sys.stderr)
                # Send response right away - no waiting
                await self._send_response(writer, 413, "Request Entity Too Large",
                                          {"Content-Type": "text/plain", "Connection": "close"},
                                          b"Early 413 - body was never read")
                # Flush immediately
                await writer.drain()
                print(f"block-and-reply: response sent, closing without reading body", file=sys.stderr)
                # Don't read body, just close

            elif path == '/block-and-reply-slow':
                # Even more aggressive: wait longer to let more data queue up
                print(f"block-and-reply-slow: waiting for client to fill buffers", file=sys.stderr)
                await asyncio.sleep(1.0)  # Wait for client to really fill up buffers
                await self._send_response(writer, 503, "Service Unavailable",
                                          {"Content-Type": "text/plain", "Connection": "close"},
                                          b"Server busy - your data was ignored")
                await asyncio.sleep(0.1)

            elif path == '/slow-response-no-drain':
                # Wait a bit (let client send more data), then respond without reading
                await asyncio.sleep(0.5)  # Let client start/continue sending
                await self._send_response(writer, 200, "OK",
                                          {"Content-Type": "text/plain", "Connection": "close"},
                                          b"slow response - body not read")
                # Don't drain - close with data potentially still in flight

            elif path == '/request':
                # Normal request handling for comparison
                if content_length > 0:
                    body = await asyncio.wait_for(reader.read(content_length), timeout=10.0)
                    print(f"Read full body: {len(body)} bytes", file=sys.stderr)
                await self._send_response(writer, 200, "OK",
                                          {"Content-Type": "text/plain", "Connection": "close"},
                                          b"normal response")

            elif path == '/keepalive-normal':
                # Normal keep-alive handling for comparison
                if content_length > 0:
                    body = await asyncio.wait_for(reader.read(content_length), timeout=10.0)
                await self._send_response(writer, 200, "OK",
                                          {"Content-Type": "text/plain",
                                           "Connection": "keep-alive",
                                           "Keep-Alive": "timeout=30"},
                                          b"normal keepalive response")

            else:
                await self._send_response(writer, 404, "Not Found",
                                          {"Content-Type": "text/plain", "Connection": "close"},
                                          b"Not found")

        except asyncio.TimeoutError:
            print(f"Timeout handling {addr}", file=sys.stderr)
        except ConnectionResetError:
            print(f"Connection reset by {addr}", file=sys.stderr)
        except Exception as e:
            print(f"Error handling {addr}: {type(e).__name__}: {e}", file=sys.stderr)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            print(f"Connection closed for {addr}", file=sys.stderr)

    async def _send_response(self, writer: asyncio.StreamWriter, status: int, status_text: str,
                             headers: dict, body: bytes):
        """Send an HTTP response."""
        response_lines = [f"HTTP/1.1 {status} {status_text}"]
        headers["Content-Length"] = str(len(body))
        for key, value in headers.items():
            response_lines.append(f"{key}: {value}")
        response_lines.append("")
        response_lines.append("")

        response_header = "\r\n".join(response_lines).encode('utf-8')
        writer.write(response_header)
        writer.write(body)
        await writer.drain()
        print(f"Sent response: {status} {status_text}, {len(body)} bytes body", file=sys.stderr)

    async def start(self):
        """Start the server."""
        self.server = await asyncio.start_server(
            self.handle_client, self.host, self.port
        )
        print(f"Early response server listening on {self.host}:{self.port}", file=sys.stderr)

    async def serve_forever(self):
        """Serve until cancelled."""
        # Python 3.7+ has serve_forever(), but 3.6 doesn't
        if hasattr(self.server, 'serve_forever'):
            async with self.server:
                await self.server.serve_forever()
        else:
            # For Python 3.6 compatibility, use async context manager
            await asyncio.Event().wait()


async def main():
    parser = argparse.ArgumentParser(description="HTTP server for testing early response scenarios")
    parser.add_argument("--bind", "-b", default="127.0.0.1", help="bind address")
    parser.add_argument("--port", "-p", type=int, default=18083, help="bind port")
    parser.add_argument("--pidfile", "-pf", help="path to the PID file")
    args = parser.parse_args()

    print(f"dummy_http_early_response.py: Starting on {args.bind}:{args.port}", file=sys.stderr)

    server = EarlyResponseServer(args.host if hasattr(args, 'host') else args.bind, args.port)
    await server.start()

    if args.pidfile:
        dummy_killer.write_pid(args.pidfile)
        print(f"PID file written to {args.pidfile}", file=sys.stderr)

    await server.serve_forever()


if __name__ == "__main__":
    try:
        if hasattr(asyncio, 'run') and callable(getattr(asyncio, 'run')):
            asyncio.run(main())
        else:
            loop = asyncio.get_event_loop()
            loop.run_until_complete(main())
    except KeyboardInterrupt:
        print("Shutting down...", file=sys.stderr)
    except Exception as e:
        print(f"FATAL ERROR: {type(e).__name__}: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
