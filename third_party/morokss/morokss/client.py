from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import os
import ssl

from .protocol import (
    ProtocolError,
    WebSocketStream,
    daily_path,
    load_secret,
    make_auth,
    parse_endpoint,
    read_http_head,
    relay_streams,
    unpack_envelope,
    websocket_accept,
)


async def open_websocket(
    server: tuple[str, int],
    hostname: str,
    secret: bytes,
    *,
    insecure: bool,
    ca_file: str | None,
    network: str = "tcp",
) -> WebSocketStream:
    if network not in {"tcp", "udp"}:
        raise ValueError(f"unsupported network mode: {network}")
    if insecure:
        tls = ssl._create_unverified_context()
    else:
        tls = ssl.create_default_context(cafile=ca_file)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.set_alpn_protocols(["http/1.1"])
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(*server, ssl=tls, server_hostname=hostname),
        timeout=10.0,
    )
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    path = daily_path(secret)
    protocol_name = "morokss.udp.v1" if network == "udp" else "morokss.v1"
    writer.write(
        (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {hostname}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Protocol: {protocol_name}\r\n"
            "User-Agent: Mozilla/5.0\r\n\r\n"
        ).encode("ascii")
    )
    await writer.drain()
    status_line, headers, _ = await read_http_head(reader)
    if (
        status_line != "HTTP/1.1 101 Switching Protocols"
        or headers.get("upgrade", "").lower() != "websocket"
        or headers.get("sec-websocket-accept") != websocket_accept(key)
    ):
        writer.close()
        with contextlib.suppress(ConnectionError, asyncio.TimeoutError):
            await writer.wait_closed()
        raise ProtocolError(f"WebSocket upgrade rejected: {status_line}")
    websocket = WebSocketStream(reader, writer, client_side=True)
    await websocket.send_binary(make_auth(secret))
    selected_protocol = headers.get("sec-websocket-protocol", "")
    if selected_protocol and selected_protocol != protocol_name:
        await websocket.close()
        raise ProtocolError(f"unsupported MorokSS subprotocol: {selected_protocol}")
    if network == "udp" and selected_protocol != protocol_name:
        await websocket.close()
        raise ProtocolError("server does not support MorokSS UDP")
    if selected_protocol == protocol_name:
        try:
            ready = await asyncio.wait_for(websocket.receive_binary(), timeout=8.0)
            ready_data = unpack_envelope(ready)
        except (asyncio.TimeoutError, EOFError, ProtocolError):
            await websocket.close()
            raise
        if ready_data != b"":
            await websocket.close()
            raise ProtocolError("invalid server readiness response")
    return websocket


async def handle_local(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    server: tuple[str, int],
    hostname: str,
    secret: bytes,
    insecure: bool,
    ca_file: str | None,
) -> None:
    try:
        websocket = await open_websocket(
            server,
            hostname,
            secret,
            insecure=insecure,
            ca_file=ca_file,
        )
        await relay_streams(reader, writer, websocket)
    except (
        asyncio.IncompleteReadError,
        asyncio.TimeoutError,
        ConnectionError,
        EOFError,
        OSError,
        ProtocolError,
    ) as exc:
        print(f"connection failed: {exc}")
        if not writer.is_closing():
            writer.close()
            with contextlib.suppress(ConnectionError, asyncio.TimeoutError):
                await writer.wait_closed()


async def run(args: argparse.Namespace) -> None:
    listen = parse_endpoint(args.listen)
    server_endpoint = parse_endpoint(args.server)
    secret = load_secret()
    listener = await asyncio.start_server(
        lambda reader, writer: handle_local(
            reader,
            writer,
            server=server_endpoint,
            hostname=args.hostname,
            secret=secret,
            insecure=args.insecure,
            ca_file=args.ca_file,
        ),
        *listen,
        limit=128 * 1024,
    )
    addresses = ", ".join(str(sock.getsockname()) for sock in listener.sockets or [])
    print(f"MorokSS client listening on {addresses}; server={args.server}")
    async with listener:
        await listener.serve_forever()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local client for MorokSS")
    parser.add_argument("--listen", default="127.0.0.1:8389")
    parser.add_argument("--server", required=True)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--ca-file")
    parser.add_argument("--insecure", action="store_true", help="development only")
    return parser


def main() -> None:
    asyncio.run(run(build_parser().parse_args()))


if __name__ == "__main__":
    main()
