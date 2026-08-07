from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import json
import secrets
import ssl
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
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
BURST_MAX_DATA = 8 * 1024
BURST_MAX_PENDING_CHUNKS = 32
BURST_MAX_PENDING_BYTES = 128 * 1024
BURST_MAX_SEQUENCE_GAP = 64
BURST_MAX_SESSIONS = 256
BURST_MAX_SESSIONS_PER_SECRET = 64
BURST_MAX_ACTIVE_UPLOADS = 8
BURST_IDLE_TIMEOUT = 10 * 60.0
BURST_COMPLETED_WINDOW = 128
BURST_DOWNLOAD_WINDOW = 8
BURST_DOWNLOAD_WAIT = 20.0
BURST_CONNECTIONS_PER_MINUTE = 2_400
BURST_ACTIVE_CONNECTIONS_PER_SECRET = 64
BURST_IO_TIMEOUT = 15.0
BURST_HEADER_TIMEOUT = 30.0
BURST_PAYLOAD_TIMEOUT = 60.0


@dataclass
class BurstSession:
    """One backend stream shared by control and short bidirectional flows."""

    backend_reader: asyncio.StreamReader
    backend_writer: asyncio.StreamWriter
    max_pending_chunks: int = BURST_MAX_PENDING_CHUNKS
    max_pending_bytes: int = BURST_MAX_PENDING_BYTES
    max_sequence_gap: int = BURST_MAX_SEQUENCE_GAP
    max_active_uploads: int = BURST_MAX_ACTIVE_UPLOADS
    completed_window: int = BURST_COMPLETED_WINDOW
    next_sequence: int = 0
    pending_bytes: int = 0
    active_uploads: int = 0
    active_downloads: int = 0
    fin_sequence: int | None = None
    fin_written: bool = False
    download_finished: bool = False
    failed: bool = False
    closed: bool = False
    pending: dict[int, tuple[bytes, bool]] = field(default_factory=dict)
    completed: OrderedDict[int, tuple[int, bytes, bool]] = field(
        default_factory=OrderedDict
    )
    download_next_sequence: int = 0
    download_completed: OrderedDict[int, tuple[bytes, bool]] = field(
        default_factory=OrderedDict
    )
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    download_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    upload_finished: asyncio.Event = field(default_factory=asyncio.Event)
    download_finished_event: asyncio.Event = field(default_factory=asyncio.Event)
    last_activity: float = field(default_factory=time.monotonic)

    def touch(self) -> None:
        self.last_activity = time.monotonic()

    def idle_at(self, now: float, timeout: float) -> bool:
        return (
            self.active_uploads == 0
            and self.active_downloads == 0
            and now - self.last_activity >= timeout
        )

    async def begin_upload(self) -> None:
        async with self.lock:
            if self.closed:
                raise ProtocolError("burst session is closed")
            if self.active_uploads >= self.max_active_uploads:
                raise ProtocolError("too many active burst uploads")
            self.active_uploads += 1
            self.touch()

    async def end_upload(self) -> None:
        async with self.lock:
            self.active_uploads = max(0, self.active_uploads - 1)
            self.touch()

    async def begin_download(self) -> None:
        async with self.lock:
            if self.closed:
                raise ProtocolError("burst session is closed")
            self.active_downloads += 1
            self.touch()

    async def end_download(self) -> None:
        async with self.lock:
            self.active_downloads = max(0, self.active_downloads - 1)
            self.touch()

    async def read_download(
        self, sequence: int, max_length: int
    ) -> tuple[str, int, bytes, bool]:
        """Return one retry-safe backend chunk for a client-initiated poll."""
        async with self.download_lock:
            if self.closed:
                raise ProtocolError("burst session is closed")
            if not 1 <= max_length <= BURST_MAX_DATA:
                raise ProtocolError("invalid burst download length")
            if sequence < self.download_next_sequence:
                cached = self.download_completed.get(sequence)
                if cached is None:
                    raise ProtocolError("burst download retry is too old")
                self.touch()
                data, fin = cached
                return "duplicate", self.download_next_sequence, data, fin
            if sequence > self.download_next_sequence:
                raise ProtocolError("burst download sequence is too far ahead")
            if self.download_finished:
                raise ProtocolError("burst download is already finished")

            try:
                data = await asyncio.wait_for(
                    self.backend_reader.read(max_length), BURST_DOWNLOAD_WAIT
                )
            except asyncio.TimeoutError:
                self.touch()
                return "idle", self.download_next_sequence, b"", False
            except (ConnectionError, OSError):
                async with self.lock:
                    self._fail_locked()
                raise

            fin = not data
            self.download_completed[sequence] = (data, fin)
            while len(self.download_completed) > BURST_DOWNLOAD_WINDOW:
                self.download_completed.popitem(last=False)
            self.download_next_sequence += 1
            if fin:
                self.download_finished = True
                self.download_finished_event.set()
            self.touch()
            return "written", self.download_next_sequence, data, fin

    async def submit(
        self, sequence: int, data: bytes, fin: bool
    ) -> tuple[str, int, bool]:
        """Queue a chunk, flush contiguous chunks, and report its disposition."""
        async with self.lock:
            if self.closed:
                raise ProtocolError("burst session is closed")
            if len(data) > BURST_MAX_DATA:
                raise ProtocolError("burst chunk is too large")
            if sequence < self.next_sequence:
                completed = self.completed.get(sequence)
                if completed is not None and completed != (
                    len(data),
                    hashlib.sha256(data).digest(),
                    fin,
                ):
                    raise ProtocolError("conflicting completed burst chunk")
                self.touch()
                return "duplicate", self.next_sequence, self.fin_written
            if sequence - self.next_sequence > self.max_sequence_gap:
                raise ProtocolError("burst sequence is too far ahead")
            if self.fin_sequence is not None:
                if sequence > self.fin_sequence or (fin and sequence != self.fin_sequence):
                    raise ProtocolError("burst chunk is after the final sequence")

            existing = self.pending.get(sequence)
            if existing is not None:
                if existing != (data, fin):
                    raise ProtocolError("conflicting duplicate burst chunk")
                self.touch()
                return "duplicate", self.next_sequence, self.fin_written

            if fin:
                if any(pending_sequence > sequence for pending_sequence in self.pending):
                    raise ProtocolError("burst final sequence precedes pending data")
                self.fin_sequence = sequence

            # The missing next chunk is always allowed because it immediately frees
            # any contiguous pending data. Future chunks consume the bounded buffer.
            if sequence != self.next_sequence and (
                len(self.pending) >= self.max_pending_chunks
                or self.pending_bytes + len(data) > self.max_pending_bytes
            ):
                if fin:
                    self.fin_sequence = None
                raise ProtocolError("burst pending buffer is full")

            self.pending[sequence] = (data, fin)
            self.pending_bytes += len(data)
            while self.next_sequence in self.pending:
                completed_sequence = self.next_sequence
                payload, chunk_fin = self.pending.pop(completed_sequence)
                self.pending_bytes -= len(payload)
                if payload:
                    try:
                        self.backend_writer.write(payload)
                        await asyncio.wait_for(
                            self.backend_writer.drain(), BURST_IO_TIMEOUT
                        )
                    except (ConnectionError, OSError, asyncio.TimeoutError):
                        self._fail_locked()
                        raise
                self.completed[completed_sequence] = (
                    len(payload),
                    hashlib.sha256(payload).digest(),
                    chunk_fin,
                )
                while len(self.completed) > self.completed_window:
                    self.completed.popitem(last=False)
                self.next_sequence += 1
                if chunk_fin:
                    can_write_eof = getattr(self.backend_writer, "can_write_eof", None)
                    if callable(can_write_eof) and can_write_eof():
                        try:
                            self.backend_writer.write_eof()
                            await asyncio.wait_for(
                                self.backend_writer.drain(), BURST_IO_TIMEOUT
                            )
                        except (ConnectionError, OSError, asyncio.TimeoutError):
                            self._fail_locked()
                            raise
                    self.fin_written = True
                    self.upload_finished.set()
                    break

            self.touch()
            status = "written" if sequence < self.next_sequence else "pending"
            return status, self.next_sequence, self.fin_written

    def _fail_locked(self) -> None:
        self.failed = True
        self.closed = True
        self.pending.clear()
        self.pending_bytes = 0
        self.upload_finished.set()
        self.download_finished_event.set()
        self.backend_writer.close()

    async def close(self) -> None:
        async with self.lock:
            self.closed = True
            self.pending.clear()
            self.pending_bytes = 0
            self.download_completed.clear()
            self.upload_finished.set()
            self.download_finished_event.set()
            if not self.backend_writer.is_closing():
                self.backend_writer.close()
        with contextlib.suppress(ConnectionError, asyncio.TimeoutError):
            await asyncio.wait_for(
                self.backend_writer.wait_closed(), BURST_IO_TIMEOUT
            )


BurstSessionKey = tuple[bytes, str]


class BurstSessionRegistry:
    """Bounded registry; keys never contain raw client secrets."""

    def __init__(
        self,
        max_sessions: int = BURST_MAX_SESSIONS,
        max_sessions_per_secret: int = BURST_MAX_SESSIONS_PER_SECRET,
        max_active_uploads: int = BURST_MAX_ACTIVE_UPLOADS,
        idle_timeout: float = BURST_IDLE_TIMEOUT,
    ) -> None:
        if (
            max_sessions <= 0
            or max_sessions_per_secret <= 0
            or max_active_uploads <= 0
            or idle_timeout <= 0
        ):
            raise ValueError("burst session limits must be positive")
        self.max_sessions = max_sessions
        self.max_sessions_per_secret = max_sessions_per_secret
        self.max_active_uploads = max_active_uploads
        self.idle_timeout = idle_timeout
        self.sessions: dict[BurstSessionKey, BurstSession] = {}
        self.opening: set[BurstSessionKey] = set()
        self.lock = asyncio.Lock()

    async def open(
        self, key: BurstSessionKey, backend: tuple[str, int]
    ) -> BurstSession:
        async with self.lock:
            if key in self.sessions or key in self.opening:
                raise ProtocolError("burst session already exists")
            if len(self.sessions) + len(self.opening) >= self.max_sessions:
                raise ProtocolError("burst session limit reached")
            secret_scope = key[0]
            secret_sessions = sum(
                session_key[0] == secret_scope
                for session_key in (*self.sessions.keys(), *self.opening)
            )
            if secret_sessions >= self.max_sessions_per_secret:
                raise ProtocolError("burst per-secret session limit reached")
            self.opening.add(key)

        backend_writer: asyncio.StreamWriter | None = None
        try:
            backend_reader, backend_writer = await asyncio.wait_for(
                asyncio.open_connection(*backend), timeout=8.0
            )
            session = BurstSession(
                backend_reader,
                backend_writer,
                max_active_uploads=self.max_active_uploads,
            )
            async with self.lock:
                self.opening.discard(key)
                if key in self.sessions:
                    raise ProtocolError("burst session already exists")
                self.sessions[key] = session
            return session
        except BaseException:
            async with self.lock:
                self.opening.discard(key)
            if backend_writer is not None:
                backend_writer.close()
                with contextlib.suppress(ConnectionError, asyncio.TimeoutError):
                    await backend_writer.wait_closed()
            raise

    async def get(self, key: BurstSessionKey) -> BurstSession:
        stale: BurstSession | None = None
        async with self.lock:
            session = self.sessions.get(key)
            if session is None:
                raise ProtocolError("unknown burst session")
            if session.closed:
                stale = self.sessions.pop(key)
            else:
                return session
        if stale is not None:
            await stale.close()
        raise ProtocolError("burst session is closed")

    async def remove(
        self, key: BurstSessionKey, expected: BurstSession | None = None
    ) -> None:
        async with self.lock:
            session = self.sessions.get(key)
            if session is None or (expected is not None and session is not expected):
                return
            del self.sessions[key]
        await session.close()

    async def close(self) -> None:
        async with self.lock:
            sessions = tuple(self.sessions.values())
            self.sessions.clear()
        await asyncio.gather(
            *(session.close() for session in sessions), return_exceptions=True
        )

    async def reap_idle(self) -> None:
        """Continuously remove abandoned controls without unbounded state."""
        interval = min(30.0, max(1.0, self.idle_timeout / 2))
        while True:
            await asyncio.sleep(interval)
            await self.reap_expired()

    async def reap_expired(self, now: float | None = None) -> int:
        current = time.monotonic() if now is None else now
        async with self.lock:
            expired = [
                (key, session)
                for key, session in self.sessions.items()
                if session.idle_at(current, self.idle_timeout)
            ]
            for key, _ in expired:
                del self.sessions[key]
        await asyncio.gather(
            *(session.close() for _, session in expired),
            return_exceptions=True,
        )
        return len(expired)


def burst_session_key(secret: bytes, session_id: str) -> BurstSessionKey:
    return hashlib.sha256(secret).digest(), session_id


def _valid_burst_session_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 32
        and all(character in "0123456789abcdef" for character in value)
    )


async def _receive_burst_json(
    tunnel: WebSocketStream | HTTPChunkStream,
) -> dict[str, object]:
    payload = unpack_envelope(
        await asyncio.wait_for(tunnel.receive_binary(), timeout=BURST_HEADER_TIMEOUT)
    )
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProtocolError("invalid burst request") from error
    if not isinstance(document, dict):
        raise ProtocolError("invalid burst request")
    return document


async def _send_burst_json(
    tunnel: WebSocketStream | HTTPChunkStream, document: dict[str, object]
) -> None:
    payload = json.dumps(document, separators=(",", ":")).encode("utf-8")
    await tunnel.send_binary(pack_envelope(payload))


async def run_burst_open(
    tunnel: WebSocketStream | HTTPChunkStream,
    registry: BurstSessionRegistry,
    matched_secret: bytes,
    backend: tuple[str, int],
) -> None:
    request = await _receive_burst_json(tunnel)
    session_id = request.get("session_id")
    if (
        type(request.get("version")) is not int
        or request.get("version") != 1
        or not _valid_burst_session_id(session_id)
    ):
        raise ProtocolError("invalid burst open request")
    assert isinstance(session_id, str)
    key = burst_session_key(matched_secret, session_id)
    session = await registry.open(key, backend)
    tasks: set[asyncio.Task[object]] = set()

    async def watch_control() -> bool:
        # Upload data belongs on burst-upload flows. Reading here exists only to
        # promptly detect a closed control flow and release the backend session.
        try:
            await tunnel.receive_binary()
        except EOFError:
            # A terminating HTTP request chunk is only a request-side half-close;
            # the response/download side can remain alive. WebSocket close is a
            # logical close of both directions and owns the session lifetime.
            if not isinstance(tunnel, HTTPChunkStream):
                return True
            # HTTP zero-chunk only half-closes the request body. Consume its
            # terminating CRLF, then wait for physical EOF while the response
            # remains usable. Normal session completion cancels this watcher.
            if await tunnel.reader.readexactly(2) != b"\r\n":
                raise ProtocolError("invalid HTTP burst control ending")
            if await tunnel.reader.read(1):
                raise ProtocolError("unexpected data after HTTP burst control")
            return True
        raise ProtocolError("unexpected data on burst control flow")

    try:
        await _send_burst_json(
            tunnel,
            {
                "version": 1,
                "session_id": session_id,
                "status": "open",
            },
        )
        control_task = asyncio.create_task(watch_control())
        upload_fin_task = asyncio.create_task(session.upload_finished.wait())
        download_fin_task = asyncio.create_task(session.download_finished_event.wait())
        tasks = {control_task, upload_fin_task, download_fin_task}
        upload_done = False
        download_done = False
        while True:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            if control_task in done:
                control_dead = control_task.result()
                tasks.remove(control_task)
                if control_dead:
                    break
                # HTTP request half-close: the response and backend stay live.
            if upload_fin_task in done:
                upload_fin_task.result()
                upload_done = True
                tasks.remove(upload_fin_task)
            if download_fin_task in done:
                download_fin_task.result()
                download_done = True
                tasks.remove(download_fin_task)
            if session.failed or (upload_done and download_done):
                break
            if not tasks:
                break
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await registry.remove(key, session)
        await tunnel.close()


async def run_burst_upload(
    tunnel: WebSocketStream | HTTPChunkStream,
    registry: BurstSessionRegistry,
    matched_secret: bytes,
) -> None:
    request = await _receive_burst_json(tunnel)
    session_id = request.get("session_id")
    sequence = request.get("sequence")
    fin = request.get("fin")
    length = request.get("length")
    if (
        type(request.get("version")) is not int
        or request.get("version") != 1
        or not _valid_burst_session_id(session_id)
        or type(sequence) is not int
        or sequence < 0
        or type(fin) is not bool
        or type(length) is not int
        or not 0 <= length <= BURST_MAX_DATA
        or (length == 0 and not fin)
    ):
        raise ProtocolError("invalid burst upload request")
    assert isinstance(session_id, str)
    assert isinstance(sequence, int)
    assert isinstance(fin, bool)
    assert isinstance(length, int)

    session = await registry.get(burst_session_key(matched_secret, session_id))
    await session.begin_upload()
    try:
        data = b""
        if length:
            data = unpack_envelope(
                await asyncio.wait_for(
                    tunnel.receive_binary(), timeout=BURST_PAYLOAD_TIMEOUT
                )
            )
            if len(data) != length:
                raise ProtocolError("burst upload length mismatch")

        status, next_sequence, fin_written = await session.submit(sequence, data, fin)
        await _send_burst_json(
            tunnel,
            {
                "version": 1,
                "session_id": session_id,
                "sequence": sequence,
                "status": status,
                "next_sequence": next_sequence,
                "fin": fin_written,
            },
        )
    finally:
        await session.end_upload()
        await tunnel.close()


async def run_burst_download(
    tunnel: WebSocketStream | HTTPChunkStream,
    registry: BurstSessionRegistry,
    matched_secret: bytes,
) -> None:
    request = await _receive_burst_json(tunnel)
    session_id = request.get("session_id")
    sequence = request.get("sequence")
    max_length = request.get("max_length")
    if (
        type(request.get("version")) is not int
        or request.get("version") != 1
        or not _valid_burst_session_id(session_id)
        or type(sequence) is not int
        or sequence < 0
        or type(max_length) is not int
        or not 1 <= max_length <= BURST_MAX_DATA
    ):
        raise ProtocolError("invalid burst download request")
    assert isinstance(session_id, str)
    assert isinstance(sequence, int)
    assert isinstance(max_length, int)

    session = await registry.get(burst_session_key(matched_secret, session_id))
    await session.begin_download()
    try:
        status, next_sequence, data, fin = await session.read_download(
            sequence, max_length
        )
        await _send_burst_json(
            tunnel,
            {
                "version": 1,
                "session_id": session_id,
                "sequence": sequence,
                "status": status,
                "next_sequence": next_sequence,
                "length": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "fin": fin,
            },
        )
        if data:
            await tunnel.send_binary(pack_envelope(data))
    finally:
        await session.end_download()
        await tunnel.close()


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

    async def refund_rate_limit(self, peer: str) -> None:
        """Return one authenticated burst attempt without changing active count."""
        async with self.lock:
            recent = self.attempts.get(peer)
            if recent:
                recent.pop()
                if not recent:
                    del self.attempts[peer]


@dataclass
class BurstAdmissionRecord:
    tokens: float
    last_refill: float
    last_seen: float
    active: int = 0


class BurstAdmissionControl:
    """O(1)-memory token buckets for authenticated, secret-scoped microflows."""

    def __init__(
        self,
        max_per_minute: int = BURST_CONNECTIONS_PER_MINUTE,
        max_active_per_secret: int = BURST_ACTIVE_CONNECTIONS_PER_SECRET,
        max_secret_records: int = 65536,
    ) -> None:
        if (
            max_per_minute <= 0
            or max_active_per_secret <= 0
            or max_secret_records <= 0
        ):
            raise ValueError("burst admission limits must be positive")
        self.max_per_minute = max_per_minute
        self.max_active_per_secret = max_active_per_secret
        self.max_secret_records = max_secret_records
        self.records: OrderedDict[bytes, BurstAdmissionRecord] = OrderedDict()
        self.lock = asyncio.Lock()

    async def acquire(self, secret_scope: bytes) -> bool:
        now = time.monotonic()
        async with self.lock:
            record = self.records.get(secret_scope)
            if record is None:
                while len(self.records) >= self.max_secret_records:
                    evictable = next(
                        (
                            key
                            for key, candidate in self.records.items()
                            if candidate.active == 0
                        ),
                        None,
                    )
                    if evictable is None:
                        return False
                    del self.records[evictable]
                record = BurstAdmissionRecord(
                    tokens=float(self.max_per_minute),
                    last_refill=now,
                    last_seen=now,
                )
                self.records[secret_scope] = record
            else:
                elapsed = max(0.0, now - record.last_refill)
                record.tokens = min(
                    float(self.max_per_minute),
                    record.tokens + elapsed * self.max_per_minute / 60.0,
                )
                record.last_refill = now
                record.last_seen = now
                self.records.move_to_end(secret_scope)
            if record.active >= self.max_active_per_secret or record.tokens < 1.0:
                return False
            record.tokens -= 1.0
            record.active += 1
            return True

    async def release(self, secret_scope: bytes) -> None:
        async with self.lock:
            record = self.records.get(secret_scope)
            if record is not None:
                record.active = max(0, record.active - 1)
                record.last_seen = time.monotonic()


async def acquire_authenticated_burst(
    matched_secret: bytes,
    admission: AdmissionControl | None,
    admission_peer: str | None,
    burst_admission: BurstAdmissionControl | None,
) -> tuple[bytes, bool]:
    """Apply secret quota first; only admitted bursts earn an IP-rate refund."""
    secret_scope = hashlib.sha256(matched_secret).digest()
    if burst_admission is not None and not await burst_admission.acquire(secret_scope):
        return secret_scope, False
    if admission is not None and admission_peer is not None:
        await admission.refund_rate_limit(admission_peer)
    return secret_scope, True


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
    burst_registry: BurstSessionRegistry | None = None,
    admission: AdmissionControl | None = None,
    admission_peer: str | None = None,
    burst_admission: BurstAdmissionControl | None = None,
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
            and headers.get("x-stream-network", "")
            in {
                "tcp",
                "udp",
                "probe",
                "clamp",
                "burst-open",
                "burst-upload",
                "burst-download",
            }
        )
        if not websocket_request and not http_stream_request:
            await relay_plain_http(reader, writer, raw_head, decoy)
            return

        if websocket_request:
            requested_protocols = {
                value.strip()
                for value in headers.get("sec-websocket-protocol", "").split(",")
            }
            if "morokss.burst.open.v1" in requested_protocols:
                selected_protocol = "morokss.burst.open.v1"
                network_mode = "burst-open"
            elif "morokss.burst.upload.v1" in requested_protocols:
                selected_protocol = "morokss.burst.upload.v1"
                network_mode = "burst-upload"
            elif "morokss.burst.download.v1" in requested_protocols:
                selected_protocol = "morokss.burst.download.v1"
                network_mode = "burst-download"
            elif "morokss.clamp.v1" in requested_protocols:
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

        if network_mode in {"burst-open", "burst-upload", "burst-download"}:
            if burst_registry is None:
                burst_registry = getattr(replay_cache, "_burst_registry", None)
                if burst_registry is None:
                    burst_registry = BurstSessionRegistry()
                    setattr(replay_cache, "_burst_registry", burst_registry)
            secret_scope, burst_acquired = await acquire_authenticated_burst(
                matched_secret,
                admission,
                admission_peer,
                burst_admission,
            )
            if not burst_acquired:
                await tunnel.close()
                return
            try:
                await tunnel.send_binary(pack_envelope(b""))
                if network_mode == "burst-open":
                    await run_burst_open(
                        tunnel, burst_registry, matched_secret, backend
                    )
                elif network_mode == "burst-upload":
                    await run_burst_upload(tunnel, burst_registry, matched_secret)
                else:
                    await run_burst_download(tunnel, burst_registry, matched_secret)
            finally:
                if burst_admission is not None:
                    await burst_admission.release(secret_scope)
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
    burst_registry = BurstSessionRegistry(
        max_sessions=args.max_burst_sessions,
        max_sessions_per_secret=args.max_burst_sessions_per_secret,
        max_active_uploads=args.max_burst_active_uploads,
        idle_timeout=args.burst_idle_timeout,
    )
    admission = AdmissionControl(args.max_clients, args.max_connections_per_minute)
    burst_admission = BurstAdmissionControl(
        args.max_burst_connections_per_minute,
        args.max_burst_active_connections_per_secret,
    )
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
                burst_registry=burst_registry,
                admission=admission,
                admission_peer=peer,
                burst_admission=burst_admission,
            )
        finally:
            await admission.release()

    server = await asyncio.start_server(
        limited_client,
        *listen,
        ssl=tls,
        ssl_handshake_timeout=10.0,
        limit=128 * 1024,
    )
    addresses = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    print(
        f"MorokSS server listening on {addresses}; backend={args.backend}; "
        f"accepted_secrets={len(secrets)}"
    )
    burst_reaper = asyncio.create_task(burst_registry.reap_idle())
    try:
        async with server:
            await server.serve_forever()
    finally:
        burst_reaper.cancel()
        await asyncio.gather(burst_reaper, return_exceptions=True)
        await burst_registry.close()


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
    parser.add_argument(
        "--max-burst-connections-per-minute",
        type=int,
        default=BURST_CONNECTIONS_PER_MINUTE,
        help="authenticated burst microflows allowed per client secret",
    )
    parser.add_argument(
        "--max-burst-active-connections-per-secret",
        type=int,
        default=BURST_ACTIVE_CONNECTIONS_PER_SECRET,
    )
    parser.add_argument(
        "--max-burst-sessions", type=int, default=BURST_MAX_SESSIONS
    )
    parser.add_argument(
        "--max-burst-sessions-per-secret",
        type=int,
        default=BURST_MAX_SESSIONS_PER_SECRET,
    )
    parser.add_argument(
        "--max-burst-active-uploads",
        type=int,
        default=BURST_MAX_ACTIVE_UPLOADS,
    )
    parser.add_argument(
        "--burst-idle-timeout", type=float, default=BURST_IDLE_TIMEOUT
    )
    return parser


def main() -> None:
    asyncio.run(run(build_parser().parse_args()))


if __name__ == "__main__":
    main()
