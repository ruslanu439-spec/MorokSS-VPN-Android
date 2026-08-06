from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import json
import secrets
import ssl
import time
from collections import deque
from http import HTTPStatus

from .protocol import (
    ProtocolError,
    HTTPChunkStream,
    ReplayCache,
    WebSocketStream,
    load_server_secrets,
    parse_endpoint,
    pack_datagram,
    pack_envelope,
    read_http_head,
    relay_streams,
    secret_for_path,
    unpack_datagram,
    unpack_envelope,
    verify_auth,
    websocket_accept,
)

PROBE_BYTES = 96 * 1024
PROBE_CHUNK = 4 * 1024
CLAMP_MAX_BYTES = 256 * 1024
CLAMP_MAX_CHUNK = 16 * 1024


class AdmissionControl:
    def __init__(
        self, max_active: int, max_per_minute: int, max_peer_records: int = 65536
    ) -> None:
        if max_active <= 0 or max_per_minute <= 0 or max_peer_records <= 0:
            raise ValueError("connection limits must be positive")
        self.max_active = max_active
        self.max_per_minute = max_per_minute
        self.max_peer_records = max_peer_records
        self.active = 0
        self.attempts: dict[str, deque[float]] = {}
        self.lock = asyncio.Lock()

    async def acquire(self, peer: str) -> bool:
        now = time.monotonic()
        async with self.lock:
            if peer not in self.attempts and len(self.attempts) >= self.max_peer_records:
                oldest = next(iter(self.attempts))
                del self.attempts[oldest]
            recent = self.attempts.setdefault(peer, deque())
            while recent and recent[0] < now - 60:
                recent.popleft()
            if self.active >= self.max_active or len(recent) >= self.max_per_minute:
                return False
            recent.append(now)
            self.active += 1
            return True

    async def release(self) -> None:
        async with self.lock:
            self.active = max(0, self.active - 1)


async def run_path_probe(tunnel: WebSocketStream | HTTPChunkStream) -> None:
    """Verify that one connection carries well beyond the observed 16–20 KiB clamp."""
    await tunnel.send_binary(pack_envelope(b""))
    upload_hash = hashlib.sha256()
    received = 0
    while received < PROBE_BYTES:
        data = unpack_envelope(await tunnel.receive_binary())
        if not data or received + len(data) > PROBE_BYTES:
            raise ProtocolError("invalid upload path probe")
        upload_hash.update(data)
        received += len(data)
    await tunnel.send_binary(pack_envelope(b"up:" + upload_hash.digest()))

    download_hash = hashlib.sha256()
    remaining = PROBE_BYTES
    while remaining:
        chunk = secrets.token_bytes(min(PROBE_CHUNK, remaining))
        download_hash.update(chunk)
        await tunnel.send_binary(pack_envelope(chunk))
        remaining -= len(chunk)
    await tunnel.send_binary(pack_envelope(b"down:" + download_hash.digest()))
    await tunnel.close()


async def run_clamp_probe(
    tunnel: WebSocketStream | HTTPChunkStream,
) -> None:
    """Run a sized, correlated probe used to distinguish per-flow clamps."""
    started = time.monotonic()
    request_data = unpack_envelope(
        await asyncio.wait_for(tunnel.receive_binary(), timeout=8.0)
    )
    try:
        request = json.loads(request_data.decode("utf-8"))
        trace_id = request["trace_id"]
        upload_bytes = int(request["upload_bytes"])
        download_bytes = int(request["download_bytes"])
        chunk_bytes = int(request["chunk_bytes"])
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProtocolError("invalid clamp probe request") from error
    if (
        request.get("version") != 1
        or not isinstance(trace_id, str)
        or len(trace_id) != 32
        or any(character not in "0123456789abcdef" for character in trace_id)
        or not 0 <= upload_bytes <= CLAMP_MAX_BYTES
        or not 0 <= download_bytes <= CLAMP_MAX_BYTES
        or not 256 <= chunk_bytes <= CLAMP_MAX_CHUNK
        or upload_bytes + download_bytes == 0
    ):
        raise ProtocolError("clamp probe request is outside allowed bounds")

    print(
        "MOROKSS_DIAGNOSTIC "
        + json.dumps(
            {
                "trace_id": trace_id,
                "upload_bytes": upload_bytes,
                "download_bytes": download_bytes,
                "status": "started",
            },
            separators=(",", ":"),
        ),
        flush=True,
    )

    upload_hash = hashlib.sha256()
    received = 0
    while received < upload_bytes:
        data = unpack_envelope(await tunnel.receive_binary())
        if not data or received + len(data) > upload_bytes:
            raise ProtocolError("invalid clamp upload")
        upload_hash.update(data)
        received += len(data)
    upload_ack = {
        "version": 1,
        "trace_id": trace_id,
        "direction": "upload",
        "bytes": received,
        "sha256": upload_hash.hexdigest(),
    }
    await tunnel.send_binary(
        pack_envelope(json.dumps(upload_ack, separators=(",", ":")).encode("utf-8"))
    )

    download_hash = hashlib.sha256()
    remaining = download_bytes
    while remaining:
        chunk = secrets.token_bytes(min(chunk_bytes, remaining))
        download_hash.update(chunk)
        await tunnel.send_binary(pack_envelope(chunk))
        remaining -= len(chunk)
    download_ack = {
        "version": 1,
        "trace_id": trace_id,
        "direction": "download",
        "bytes": download_bytes,
        "sha256": download_hash.hexdigest(),
        "server_duration_ms": round((time.monotonic() - started) * 1000),
    }
    await tunnel.send_binary(
        pack_envelope(json.dumps(download_ack, separators=(",", ":")).encode("utf-8"))
    )
    print(
        "MOROKSS_DIAGNOSTIC "
        + json.dumps(
            {
                "trace_id": trace_id,
                "upload_bytes": upload_bytes,
                "download_bytes": download_bytes,
                "duration_ms": download_ack["server_duration_ms"],
                "status": "complete",
            },
            separators=(",", ":"),
        ),
        flush=True,
    )
    await tunnel.close()


class UDPBackendProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.received: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=256)

    def datagram_received(self, data: bytes, _address: tuple[str, int]) -> None:
        try:
            self.received.put_nowait(data)
        except asyncio.QueueFull:
            pass

    def error_received(self, _error: Exception) -> None:
        with contextlib.suppress(asyncio.QueueFull):
            self.received.put_nowait(None)

    def connection_lost(self, _error: Exception | None) -> None:
        with contextlib.suppress(asyncio.QueueFull):
            self.received.put_nowait(None)


async def relay_udp_backend(
    tunnel: WebSocketStream | HTTPChunkStream,
    backend: tuple[str, int],
    *,
    send_ready: bool,
) -> None:
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        UDPBackendProtocol,
        remote_addr=backend,
    )
    assert isinstance(protocol, UDPBackendProtocol)
    if send_ready:
        await tunnel.send_binary(pack_envelope(b""))

    async def client_to_backend() -> None:
        while True:
            payload = await tunnel.receive_binary()
            transport.sendto(unpack_datagram(payload))

    async def backend_to_client() -> None:
        while True:
            data = await protocol.received.get()
            if data is None:
                raise EOFError("UDP backend closed")
            await tunnel.send_binary(pack_datagram(data))

    tasks = {
        asyncio.create_task(client_to_backend()),
        asyncio.create_task(backend_to_client()),
    }
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    transport.close()
    await tunnel.close()
    for task in done:
        error = task.exception()
        if error and not isinstance(
            error, (EOFError, ConnectionError, asyncio.IncompleteReadError)
        ):
            raise error


def http_response(status: HTTPStatus, body: bytes) -> bytes:
    reason = status.phrase
    return (
        f"HTTP/1.1 {status.value} {reason}\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii") + body


async def reject(writer: asyncio.StreamWriter) -> None:
    writer.write(http_response(HTTPStatus.NOT_FOUND, b"Not Found\n"))
    with contextlib.suppress(ConnectionError):
        await writer.drain()
    writer.close()
    with contextlib.suppress(ConnectionError, asyncio.TimeoutError):
        await writer.wait_closed()


async def relay_plain_http(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    raw_head: bytes,
    decoy: tuple[str, int] | None,
) -> None:
    if decoy is None:
        await reject(client_writer)
        return
    try:
        decoy_reader, decoy_writer = await asyncio.wait_for(
            asyncio.open_connection(*decoy), timeout=5.0
        )
    except (ConnectionError, OSError, asyncio.TimeoutError):
        await reject(client_writer)
        return
    decoy_writer.write(raw_head)
    await decoy_writer.drain()

    async def pipe(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        while data := await reader.read(16 * 1024):
            writer.write(data)
            await writer.drain()

    tasks = {
        asyncio.create_task(pipe(client_reader, decoy_writer)),
        asyncio.create_task(pipe(decoy_reader, client_writer)),
    }
    _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    decoy_writer.close()
    client_writer.close()
    with contextlib.suppress(ConnectionError, asyncio.TimeoutError):
        await decoy_writer.wait_closed()
    with contextlib.suppress(ConnectionError, asyncio.TimeoutError):
        await client_writer.wait_closed()


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    secret: bytes | tuple[bytes, ...],
    backend: tuple[str, int],
    decoy: tuple[str, int] | None,
    replay_cache: ReplayCache,
) -> None:
    try:
        secrets_to_try = (secret,) if isinstance(secret, bytes) else secret
        request_line, headers, raw_head = await read_http_head(reader)
        parts = request_line.split(" ")
        matched_secret = (
            secret_for_path(parts[1], secrets_to_try) if len(parts) == 3 else None
        )
        valid_path = (
            len(parts) == 3
            and matched_secret is not None
            and parts[2] == "HTTP/1.1"
        )
        websocket_request = (
            valid_path
            and parts[0] == "GET"
            and headers.get("upgrade", "").lower() == "websocket"
            and "upgrade" in headers.get("connection", "").lower()
            and headers.get("sec-websocket-version") == "13"
            and bool(headers.get("sec-websocket-key"))
        )
        http_stream_request = (
            valid_path
            and parts[0] == "POST"
            and "chunked"
            in {
                value.strip().lower()
                for value in headers.get("transfer-encoding", "").split(",")
            }
            and headers.get("content-type", "").lower()
            == "application/octet-stream"
            and headers.get("x-stream-network", "") in {"tcp", "udp", "probe", "clamp"}
        )
        if not websocket_request and not http_stream_request:
            await relay_plain_http(reader, writer, raw_head, decoy)
            return

        if websocket_request:
            requested_protocols = {
                value.strip()
                for value in headers.get("sec-websocket-protocol", "").split(",")
            }
            if "morokss.clamp.v1" in requested_protocols:
                selected_protocol = "morokss.clamp.v1"
                network_mode = "clamp"
            elif "morokss.probe.v1" in requested_protocols:
                selected_protocol = "morokss.probe.v1"
                network_mode = "probe"
            elif "morokss.udp.v1" in requested_protocols:
                selected_protocol = "morokss.udp.v1"
                network_mode = "udp"
            elif "morokss.v1" in requested_protocols:
                selected_protocol = "morokss.v1"
                network_mode = "tcp"
            else:
                selected_protocol = ""
                network_mode = "tcp"
            ready_supported = bool(selected_protocol)
            accept = websocket_accept(headers["sec-websocket-key"])
            response = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n"
            )
            if ready_supported:
                response += f"Sec-WebSocket-Protocol: {selected_protocol}\r\n"
            writer.write((response + "\r\n").encode("ascii"))
            await writer.drain()
            tunnel = WebSocketStream(reader, writer, client_side=False)
        else:
            ready_supported = True
            network_mode = headers["x-stream-network"]
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/octet-stream\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Cache-Control: no-store\r\n"
                b"Connection: keep-alive\r\n\r\n"
            )
            await writer.drain()
            tunnel = HTTPChunkStream(reader, writer)

        auth = await asyncio.wait_for(tunnel.receive_binary(), timeout=8.0)
        assert matched_secret is not None
        if not verify_auth(auth, matched_secret, replay_cache):
            await tunnel.close()
            return

        if network_mode == "udp":
            await relay_udp_backend(tunnel, backend, send_ready=ready_supported)
            return

        if network_mode == "probe":
            await run_path_probe(tunnel)
            return

        if network_mode == "clamp":
            await tunnel.send_binary(pack_envelope(b""))
            await run_clamp_probe(tunnel)
            return

        backend_reader, backend_writer = await asyncio.wait_for(
            asyncio.open_connection(*backend), timeout=8.0
        )
        if ready_supported:
            await tunnel.send_binary(pack_envelope(b""))
        await relay_streams(backend_reader, backend_writer, tunnel)
    except (
        asyncio.IncompleteReadError,
        asyncio.LimitOverrunError,
        asyncio.TimeoutError,
        ConnectionError,
        EOFError,
        OSError,
        ProtocolError,
    ):
        if not writer.is_closing():
            writer.close()
            with contextlib.suppress(ConnectionError, asyncio.TimeoutError):
                await writer.wait_closed()


async def run(args: argparse.Namespace) -> None:
    listen = parse_endpoint(args.listen)
    backend = parse_endpoint(args.backend)
    decoy = parse_endpoint(args.decoy) if args.decoy else None
    secrets = load_server_secrets(args.secrets_file)
    replay_cache = ReplayCache()
    admission = AdmissionControl(args.max_clients, args.max_connections_per_minute)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(args.cert, args.key)
    tls.set_alpn_protocols(["http/1.1"])

    async def limited_client(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer_info = writer.get_extra_info("peername")
        peer = str(peer_info[0]) if isinstance(peer_info, tuple) and peer_info else "unknown"
        if not await admission.acquire(peer):
            await reject(writer)
            return
        try:
            await handle_client(
                reader,
                writer,
                secret=secrets,
                backend=backend,
                decoy=decoy,
                replay_cache=replay_cache,
            )
        finally:
            await admission.release()

    server = await asyncio.start_server(
        limited_client,
        *listen,
        ssl=tls,
        limit=128 * 1024,
    )
    addresses = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    print(
        f"MorokSS server listening on {addresses}; backend={args.backend}; "
        f"accepted_secrets={len(secrets)}"
    )
    async with server:
        await server.serve_forever()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="TLS transport wrapper for Shadowsocks"
    )
    parser.add_argument("--listen", default="0.0.0.0:443")
    parser.add_argument("--backend", default="127.0.0.1:8388")
    parser.add_argument(
        "--decoy",
        help="optional local HTTP site used for non-tunnel requests, e.g. 127.0.0.1:8080",
    )
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument(
        "--secrets-file",
        help="optional JSON array of per-device client secrets",
    )
    parser.add_argument("--max-clients", type=int, default=1024)
    parser.add_argument("--max-connections-per-minute", type=int, default=240)
    return parser


def main() -> None:
    asyncio.run(run(build_parser().parse_args()))


if __name__ == "__main__":
    main()
