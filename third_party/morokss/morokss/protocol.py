from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone


GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_HTTP_HEADER = 16 * 1024
MAX_WS_PAYLOAD = 64 * 1024
DATA_CHUNK = 8 * 1024
MAX_DATAGRAM = 65507
PADDING_BUCKETS = (256, 512, 1024, 2048, 4096, 8192, 12288)


class ProtocolError(Exception):
    """Raised when a peer sends an invalid transport message."""


def parse_endpoint(value: str) -> tuple[str, int]:
    host, separator, port_text = value.rpartition(":")
    if not separator or not host:
        raise ValueError(f"expected HOST:PORT, got {value!r}")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError(f"port out of range: {port}")
    return host, port


def load_secret(env_name: str = "MOROKSS_SECRET") -> bytes:
    value = os.environ.get(env_name, "").encode("utf-8")
    if len(value) < 32:
        raise ValueError(f"{env_name} must contain at least 32 UTF-8 bytes")
    return value


def load_secrets() -> tuple[bytes, ...]:
    current = load_secret()
    previous_text = os.environ.get("MOROKSS_PREVIOUS_SECRET", "")
    if not previous_text:
        return (current,)
    previous = previous_text.encode("utf-8")
    if len(previous) < 32:
        raise ValueError(
            "MOROKSS_PREVIOUS_SECRET must contain at least 32 UTF-8 bytes"
        )
    if hmac.compare_digest(current, previous):
        return (current,)
    return current, previous


def utc_day(timestamp: float | None = None) -> str:
    moment = datetime.fromtimestamp(
        time.time() if timestamp is None else timestamp, timezone.utc
    )
    return moment.strftime("%Y-%m-%d")


def daily_path(secret: bytes, timestamp: float | None = None) -> str:
    message = b"morokss:path:v1:" + utc_day(timestamp).encode("ascii")
    token = hmac.new(secret, message, hashlib.sha256).hexdigest()[:32]
    return f"/api/events/{token}"


def accepted_paths(secret: bytes, timestamp: float | None = None) -> set[str]:
    now = time.time() if timestamp is None else timestamp
    return {daily_path(secret, now + offset) for offset in (-86400, 0, 86400)}


def secret_for_path(
    path: str, secrets_to_try: tuple[bytes, ...], timestamp: float | None = None
) -> bytes | None:
    for secret in secrets_to_try:
        if path in accepted_paths(secret, timestamp):
            return secret
    return None


def websocket_accept(key: str) -> str:
    digest = hashlib.sha1((key + GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def make_auth(secret: bytes, timestamp: int | None = None) -> bytes:
    stamp = int(time.time()) if timestamp is None else timestamp
    stamp_bytes = struct.pack("!Q", stamp)
    nonce = secrets.token_bytes(16)
    mac = hmac.new(
        secret, b"morokss:auth:v1:" + stamp_bytes + nonce, hashlib.sha256
    ).digest()
    return stamp_bytes + nonce + mac + secrets.token_bytes(secrets.randbelow(65))


@dataclass
class ReplayCache:
    ttl: int = 120
    _seen: dict[bytes, float] = field(default_factory=dict)

    def accept(self, nonce: bytes, now: float | None = None) -> bool:
        current = time.time() if now is None else now
        cutoff = current - self.ttl
        self._seen = {key: seen_at for key, seen_at in self._seen.items() if seen_at >= cutoff}
        if nonce in self._seen:
            return False
        self._seen[nonce] = current
        return True


def verify_auth(
    payload: bytes,
    secret: bytes,
    replay_cache: ReplayCache,
    *,
    now: int | None = None,
    max_clock_skew: int = 90,
) -> bool:
    if len(payload) < 56:
        return False
    stamp_bytes, nonce, supplied_mac = payload[:8], payload[8:24], payload[24:56]
    stamp = struct.unpack("!Q", stamp_bytes)[0]
    current = int(time.time()) if now is None else now
    if abs(current - stamp) > max_clock_skew:
        return False
    expected_mac = hmac.new(
        secret, b"morokss:auth:v1:" + stamp_bytes + nonce, hashlib.sha256
    ).digest()
    return hmac.compare_digest(supplied_mac, expected_mac) and replay_cache.accept(
        nonce, float(current)
    )


def pack_envelope(data: bytes) -> bytes:
    return pack_payload(data, DATA_CHUNK)


def pack_datagram(data: bytes) -> bytes:
    return pack_payload(data, MAX_DATAGRAM)


def pack_payload(data: bytes, maximum: int) -> bytes:
    if len(data) > maximum:
        raise ValueError(f"payload exceeds {maximum} bytes")
    required = len(data) + 2
    eligible = [bucket for bucket in PADDING_BUCKETS if bucket >= required]
    bucket = eligible[0] if eligible else required
    if len(eligible) > 1 and secrets.randbelow(5) == 0:
        bucket = eligible[1]
    padding_size = bucket - required
    return struct.pack("!H", len(data)) + data + secrets.token_bytes(padding_size)


def unpack_envelope(payload: bytes) -> bytes:
    return unpack_payload(payload, DATA_CHUNK)


def unpack_datagram(payload: bytes) -> bytes:
    return unpack_payload(payload, MAX_DATAGRAM)


def unpack_payload(payload: bytes, maximum: int) -> bytes:
    if len(payload) < 2:
        raise ProtocolError("truncated envelope")
    data_size = struct.unpack("!H", payload[:2])[0]
    if data_size > maximum or data_size > len(payload) - 2:
        raise ProtocolError("invalid envelope length")
    return payload[2 : 2 + data_size]


async def read_http_head(
    reader: asyncio.StreamReader, timeout: float = 10.0
) -> tuple[str, dict[str, str], bytes]:
    raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout)
    if len(raw) > MAX_HTTP_HEADER:
        raise ProtocolError("HTTP header too large")
    try:
        lines = raw.decode("iso-8859-1").split("\r\n")
    except UnicodeDecodeError as exc:
        raise ProtocolError("invalid HTTP header") from exc
    first_line = lines[0]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        name, separator, value = line.partition(":")
        if not separator:
            raise ProtocolError("invalid HTTP header line")
        headers[name.strip().lower()] = value.strip()
    return first_line, headers, raw


def encode_ws_frame(payload: bytes, *, masked: bool, opcode: int = 0x2) -> bytes:
    if len(payload) > MAX_WS_PAYLOAD:
        raise ValueError("WebSocket payload too large")
    first = 0x80 | opcode
    size = len(payload)
    mask_flag = 0x80 if masked else 0
    if size < 126:
        header = bytes((first, mask_flag | size))
    elif size <= 0xFFFF:
        header = bytes((first, mask_flag | 126)) + struct.pack("!H", size)
    else:
        header = bytes((first, mask_flag | 127)) + struct.pack("!Q", size)
    if not masked:
        return header + payload
    mask = secrets.token_bytes(4)
    masked_payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return header + mask + masked_payload


async def read_ws_frame(
    reader: asyncio.StreamReader, *, expect_masked: bool
) -> tuple[int, bytes]:
    first, second = await reader.readexactly(2)
    if first & 0x70:
        raise ProtocolError("WebSocket extensions aren't supported")
    if not first & 0x80:
        raise ProtocolError("fragmented WebSocket messages aren't supported")
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    if masked != expect_masked:
        raise ProtocolError("invalid WebSocket masking direction")
    size = second & 0x7F
    if size == 126:
        size = struct.unpack("!H", await reader.readexactly(2))[0]
    elif size == 127:
        size = struct.unpack("!Q", await reader.readexactly(8))[0]
    if opcode & 0x08 and size > 125:
        raise ProtocolError("WebSocket control frame is too large")
    if size > MAX_WS_PAYLOAD:
        raise ProtocolError("WebSocket payload too large")
    mask = await reader.readexactly(4) if masked else b""
    payload = await reader.readexactly(size)
    if masked:
        payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return opcode, payload


class WebSocketStream:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        client_side: bool,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.client_side = client_side
        self._send_lock = asyncio.Lock()

    async def send_binary(self, payload: bytes) -> None:
        async with self._send_lock:
            self.writer.write(
                encode_ws_frame(payload, masked=self.client_side, opcode=0x2)
            )
            await self.writer.drain()

    async def receive_binary(self) -> bytes:
        while True:
            opcode, payload = await read_ws_frame(
                self.reader, expect_masked=not self.client_side
            )
            if opcode == 0x2:
                return payload
            if opcode == 0x8:
                raise EOFError("peer closed WebSocket")
            if opcode == 0x9:
                async with self._send_lock:
                    self.writer.write(
                        encode_ws_frame(
                            payload, masked=self.client_side, opcode=0xA
                        )
                    )
                    await self.writer.drain()
                continue
            if opcode == 0xA:
                continue
            raise ProtocolError(f"unsupported WebSocket opcode: {opcode}")

    async def close(self) -> None:
        if not self.writer.is_closing():
            try:
                async with self._send_lock:
                    self.writer.write(
                        encode_ws_frame(
                            struct.pack("!H", 1000),
                            masked=self.client_side,
                            opcode=0x8,
                        )
                    )
                    await self.writer.drain()
            except (ConnectionError, asyncio.CancelledError):
                pass
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except (ConnectionError, asyncio.TimeoutError):
                pass


class HTTPChunkStream:
    def __init__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.reader = reader
        self.writer = writer
        self._send_lock = asyncio.Lock()

    async def send_binary(self, payload: bytes) -> None:
        if len(payload) > MAX_WS_PAYLOAD:
            raise ValueError("HTTP stream payload too large")
        async with self._send_lock:
            self.writer.write(f"{len(payload):x}\r\n".encode("ascii"))
            self.writer.write(payload)
            self.writer.write(b"\r\n")
            await self.writer.drain()

    async def receive_binary(self) -> bytes:
        line = await self.reader.readline()
        if len(line) > 128 or not line.endswith(b"\r\n"):
            raise ProtocolError("invalid HTTP chunk header")
        size_text = line[:-2]
        if b";" in size_text:
            raise ProtocolError("HTTP chunk extensions aren't supported")
        try:
            size = int(size_text, 16)
        except ValueError as exc:
            raise ProtocolError("invalid HTTP chunk size") from exc
        if size == 0:
            raise EOFError("peer closed HTTP stream")
        if size > MAX_WS_PAYLOAD:
            raise ProtocolError("HTTP stream payload too large")
        payload = await self.reader.readexactly(size)
        if await self.reader.readexactly(2) != b"\r\n":
            raise ProtocolError("invalid HTTP chunk ending")
        return payload

    async def close(self) -> None:
        if not self.writer.is_closing():
            try:
                async with self._send_lock:
                    self.writer.write(b"0\r\n\r\n")
                    await self.writer.drain()
            except (ConnectionError, asyncio.CancelledError):
                pass
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except (ConnectionError, asyncio.TimeoutError):
                pass


async def relay_streams(
    local_reader: asyncio.StreamReader,
    local_writer: asyncio.StreamWriter,
    websocket: WebSocketStream | HTTPChunkStream,
) -> None:
    async def local_to_websocket() -> None:
        while data := await local_reader.read(DATA_CHUNK):
            await websocket.send_binary(pack_envelope(data))

    async def websocket_to_local() -> None:
        while True:
            payload = await websocket.receive_binary()
            data = unpack_envelope(payload)
            local_writer.write(data)
            await local_writer.drain()

    tasks = {
        asyncio.create_task(local_to_websocket()),
        asyncio.create_task(websocket_to_local()),
    }
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    for task in done:
        error = task.exception()
        if error and not isinstance(
            error, (EOFError, ConnectionError, asyncio.IncompleteReadError)
        ):
            raise error
    local_writer.close()
    try:
        await local_writer.wait_closed()
    except (ConnectionError, asyncio.TimeoutError):
        pass
    await websocket.close()
