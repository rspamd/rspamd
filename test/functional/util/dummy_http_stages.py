#!/usr/bin/env python3

"""
HTTP/1.1 server for the HTTP client stage timeout tests, plain or TLS.

POST /answer?delay=N reads the request and answers after N seconds.
POST /no-read?delay=N reads the headers, leaves the body unread for N seconds,
then reads it and answers.

Answers keep the connection alive unless the query has close=1. Every request
is logged as "tag=<tag> request=<n>", n counting the requests on its
connection, so a test can check that a connection was reused.

With --silent the server accepts connections and never sends a byte, which
stalls a TLS handshake.
"""

import argparse
import asyncio
import socket
import ssl
import sys
import traceback
from urllib.parse import parse_qs, urlsplit

import dummy_killer

# A small receive buffer makes an unread body block the client quickly
SMALL_RCVBUF = 4096
LARGE_RCVBUF = 4 * 1024 * 1024


def log(*args):
    print('dummy_http_stages.py:', *args, file=sys.stderr, flush=True)


async def serve_silent(reader, writer):
    try:
        while await reader.read(65536):
            pass
    except ConnectionError:
        pass
    finally:
        writer.close()


async def serve_http(reader, writer):
    requests = 0
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            _, target, _ = line.decode().split(' ', 2)
            url = urlsplit(target)
            query = parse_qs(url.query)
            delay = float(query.get('delay', ['0'])[0])
            tag = query.get('tag', [''])[0]
            close = query.get('close', ['0'])[0] == '1'
            length = 0
            while True:
                header = await reader.readline()
                if header in (b'\r\n', b'\n', b''):
                    break
                name, _, value = header.decode().partition(':')
                if name.strip().lower() == 'content-length':
                    length = int(value)
            requests += 1
            log(f'tag={tag} request={requests} path={url.path}')
            if url.path == '/no-read':
                await asyncio.sleep(delay)
                writer.get_extra_info('socket').setsockopt(
                    socket.SOL_SOCKET, socket.SO_RCVBUF, LARGE_RCVBUF)
            await reader.readexactly(length)
            if url.path == '/answer':
                await asyncio.sleep(delay)
            body = b'ok'
            connection = b'close' if close else b'keep-alive'
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n'
                         b'Connection: ' + connection + b'\r\nKeep-Alive: timeout=30\r\n'
                         b'Content-Length: %d\r\n\r\n' % len(body) + body)
            await writer.drain()
            if close:
                break
    except (ConnectionError, asyncio.IncompleteReadError, ssl.SSLError) as e:
        log(f'connection dropped after {requests} requests: {e!r}')
    finally:
        writer.close()


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", "-b", default="127.0.0.1", help="bind address")
    parser.add_argument("--port", "-p", type=int, required=True, help="bind port")
    parser.add_argument("--certfile", "-c", help="PEM file with the certificate and the key, enables TLS")
    parser.add_argument("--silent", action="store_true", help="accept connections and never answer")
    parser.add_argument("--pidfile", "-pf", help="path to the PID file")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SMALL_RCVBUF)
    sock.bind((args.bind, args.port))
    sock.listen(64)

    ctx = None
    if args.certfile and not args.silent:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(args.certfile)

    server = await asyncio.start_server(serve_silent if args.silent else serve_http,
                                        sock=sock, ssl=ctx)

    if args.pidfile:
        dummy_killer.write_pid(args.pidfile)

    log(f'listening on {args.bind}:{args.port}, tls={ctx is not None}, silent={args.silent}')

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print(f"dummy_http_stages.py: FATAL ERROR: {type(e).__name__}: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
