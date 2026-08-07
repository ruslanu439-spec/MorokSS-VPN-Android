import asyncio
import json
import unittest
from collections import deque
from unittest import mock

from morokss.protocol import HTTPChunkStream, ProtocolError, pack_envelope, unpack_envelope
from morokss.server import (
    BURST_MAX_DATA,
    AdmissionControl,
    BurstAdmissionControl,
    BurstSession,
    BurstSessionRegistry,
    acquire_authenticated_burst,
    burst_session_key,
    run_burst_download,
    run_burst_open,
    run_burst_upload,
)


SECRET = b"test-secret-that-is-longer-than-thirty-two-bytes"
OTHER_SECRET = b"other-secret-that-is-longer-than-thirty-two-bytes"
SESSION_ID = "0123456789abcdef0123456789abcdef"


class FakeWriter:
    def __init__(self) -> None:
        self.data = bytearray()
        self.drain_count = 0
        self.eof_count = 0
        self.closed = False

    def write(self, data: bytes) -> None:
        self.data.extend(data)

    async def drain(self) -> None:
        self.drain_count += 1

    def can_write_eof(self) -> bool:
        return True

    def write_eof(self) -> None:
        self.eof_count += 1

    def close(self) -> None:
        self.closed = True

    def is_closing(self) -> bool:
        return self.closed

    async def wait_closed(self) -> None:
        return None


class BlockingReader:
    def __init__(self) -> None:
        self.waiter = asyncio.Event()

    async def read(self, _size: int) -> bytes:
        await self.waiter.wait()
        return b""


class EOFReader:
    async def read(self, _size: int) -> bytes:
        return b""


class ChunkReader:
    def __init__(self, *chunks: bytes) -> None:
        self.chunks = deque(chunks)

    async def read(self, size: int) -> bytes:
        if not self.chunks:
            return b""
        chunk = self.chunks.popleft()
        if len(chunk) <= size:
            return chunk
        self.chunks.appendleft(chunk[size:])
        return chunk[:size]


class HTTPPhysicalReader:
    def __init__(self, eof: bool) -> None:
        self.eof = eof
        self.waiter = asyncio.Event()

    async def readexactly(self, size: int) -> bytes:
        if size != 2:
            raise AssertionError(f"unexpected read size: {size}")
        return b"\r\n"

    async def read(self, _size: int) -> bytes:
        if self.eof:
            return b""
        await self.waiter.wait()
        return b""


class FakeTunnel:
    def __init__(self, *incoming: bytes) -> None:
        self.incoming = deque(incoming)
        self.sent: list[bytes] = []
        self.closed = False

    async def receive_binary(self) -> bytes:
        if not self.incoming:
            raise EOFError("test control flow closed")
        return self.incoming.popleft()

    async def send_binary(self, payload: bytes) -> None:
        self.sent.append(payload)

    async def close(self) -> None:
        self.closed = True


class FakeHTTPChunkTunnel(FakeTunnel, HTTPChunkStream):
    def __init__(self, *incoming: bytes, physical_eof: bool = False) -> None:
        FakeTunnel.__init__(self, *incoming)
        self.reader = HTTPPhysicalReader(physical_eof)


def burst_json(**values: object) -> bytes:
    return pack_envelope(json.dumps(values, separators=(",", ":")).encode())


def decode_burst_json(payload: bytes) -> dict[str, object]:
    return json.loads(unpack_envelope(payload).decode())


class BurstSessionTests(unittest.IsolatedAsyncioTestCase):
    async def test_reorders_chunks_and_writes_each_sequence_once(self) -> None:
        writer = FakeWriter()
        session = BurstSession(BlockingReader(), writer)

        self.assertEqual(("pending", 0, False), await session.submit(1, b"B", False))
        self.assertEqual(
            ("duplicate", 0, False), await session.submit(1, b"B", False)
        )
        self.assertEqual(("written", 2, False), await session.submit(0, b"A", False))
        self.assertEqual(bytes(writer.data), b"AB")

        self.assertEqual(
            ("duplicate", 2, False), await session.submit(0, b"A", False)
        )
        self.assertEqual(bytes(writer.data), b"AB")

        self.assertEqual(("written", 3, True), await session.submit(2, b"", True))
        self.assertEqual(1, writer.eof_count)
        self.assertEqual(
            ("duplicate", 3, True), await session.submit(2, b"", True)
        )
        self.assertEqual(1, writer.eof_count)
        with self.assertRaises(ProtocolError):
            await session.submit(3, b"late", False)

    async def test_completed_retry_must_match_recent_payload(self) -> None:
        session = BurstSession(BlockingReader(), FakeWriter())
        await session.submit(0, b"original", False)
        with self.assertRaises(ProtocolError):
            await session.submit(0, b"changed", False)

    async def test_active_uploads_are_capped(self) -> None:
        session = BurstSession(
            BlockingReader(), FakeWriter(), max_active_uploads=1
        )
        await session.begin_upload()
        with self.assertRaises(ProtocolError):
            await session.begin_upload()
        await session.end_upload()
        await session.begin_upload()
        await session.end_upload()

    async def test_backend_write_failure_closes_and_wakes_session(self) -> None:
        writer = FakeWriter()

        async def fail_drain() -> None:
            raise ConnectionError("backend failed")

        writer.drain = fail_drain
        session = BurstSession(BlockingReader(), writer)
        await session.submit(1, b"pending", False)
        with self.assertRaises(ConnectionError):
            await session.submit(0, b"first", False)
        self.assertTrue(session.failed)
        self.assertTrue(session.closed)
        self.assertTrue(session.upload_finished.is_set())
        self.assertEqual({}, session.pending)
        self.assertTrue(writer.closed)

    async def test_close_clears_state_even_if_writer_is_already_closing(self) -> None:
        writer = FakeWriter()
        session = BurstSession(BlockingReader(), writer)
        session.pending[1] = (b"pending", False)
        session.pending_bytes = 7
        session.closed = True
        writer.close()
        await session.close()
        self.assertEqual({}, session.pending)
        self.assertEqual(0, session.pending_bytes)
        self.assertTrue(session.upload_finished.is_set())

    async def test_conflicting_duplicate_and_pending_memory_are_rejected(self) -> None:
        writer = FakeWriter()
        session = BurstSession(
            BlockingReader(),
            writer,
            max_pending_chunks=2,
            max_pending_bytes=4,
            max_sequence_gap=8,
        )
        await session.submit(2, b"1234", False)
        with self.assertRaises(ProtocolError):
            await session.submit(2, b"xxxx", False)
        with self.assertRaises(ProtocolError):
            await session.submit(1, b"x", False)
        with self.assertRaises(ProtocolError):
            await session.submit(9, b"x", False)
        self.assertEqual(4, session.pending_bytes)
        self.assertEqual({2}, set(session.pending))

    async def test_final_chunk_cannot_skip_already_pending_data(self) -> None:
        session = BurstSession(BlockingReader(), FakeWriter())
        await session.submit(2, b"after", False)
        with self.assertRaises(ProtocolError):
            await session.submit(1, b"final", True)

    async def test_download_chunks_are_retry_safe_and_finish_in_order(self) -> None:
        session = BurstSession(ChunkReader(b"reply"), FakeWriter())
        self.assertEqual(
            ("written", 1, b"reply", False), await session.read_download(0, 8192)
        )
        self.assertEqual(
            ("duplicate", 1, b"reply", False), await session.read_download(0, 8192)
        )
        self.assertEqual(
            ("written", 2, b"", True), await session.read_download(1, 8192)
        )
        self.assertTrue(session.download_finished)
        self.assertTrue(session.download_finished_event.is_set())
        self.assertEqual(
            ("duplicate", 2, b"", True), await session.read_download(1, 8192)
        )
        with self.assertRaises(ProtocolError):
            await session.read_download(2, 8192)

    async def test_future_download_waits_for_earlier_parallel_poll(self) -> None:
        session = BurstSession(ChunkReader(b"A", b"B"), FakeWriter())
        second = asyncio.create_task(session.read_download(1, 1))
        await asyncio.sleep(0)
        self.assertFalse(second.done())
        self.assertEqual(("written", 1, b"A", False), await session.read_download(0, 1))
        self.assertEqual(("written", 2, b"B", False), await second)


class BurstRegistryTests(unittest.IsolatedAsyncioTestCase):
    async def test_registry_scopes_session_id_by_secret_hash_and_caps_sessions(self) -> None:
        registry = BurstSessionRegistry(max_sessions=2)
        first_writer = FakeWriter()
        second_writer = FakeWriter()
        connections = mock.AsyncMock(
            side_effect=[
                (BlockingReader(), first_writer),
                (BlockingReader(), second_writer),
            ]
        )
        first_key = burst_session_key(SECRET, SESSION_ID)
        second_key = burst_session_key(OTHER_SECRET, SESSION_ID)
        self.assertNotIn(SECRET, first_key)

        with mock.patch("morokss.server.asyncio.open_connection", connections):
            first = await registry.open(first_key, ("127.0.0.1", 8388))
            second = await registry.open(second_key, ("127.0.0.1", 8388))
            self.assertIs(first, await registry.get(first_key))
            self.assertIs(second, await registry.get(second_key))
            with self.assertRaises(ProtocolError):
                await registry.open(first_key, ("127.0.0.1", 8388))
            with self.assertRaises(ProtocolError):
                await registry.open(
                    burst_session_key(SECRET, "f" * 32), ("127.0.0.1", 8388)
                )

        await registry.close()
        self.assertTrue(first_writer.closed)
        self.assertTrue(second_writer.closed)

    async def test_per_secret_cap_and_idle_reaping(self) -> None:
        registry = BurstSessionRegistry(
            max_sessions=3,
            max_sessions_per_secret=1,
            idle_timeout=10,
        )
        writer = FakeWriter()
        with mock.patch(
            "morokss.server.asyncio.open_connection",
            new=mock.AsyncMock(return_value=(BlockingReader(), writer)),
        ):
            key = burst_session_key(SECRET, SESSION_ID)
            session = await registry.open(key, ("127.0.0.1", 8388))
            with self.assertRaises(ProtocolError):
                await registry.open(
                    burst_session_key(SECRET, "a" * 32), ("127.0.0.1", 8388)
                )

        self.assertEqual(1, await registry.reap_expired(session.last_activity + 11))
        self.assertTrue(writer.closed)
        with self.assertRaises(ProtocolError):
            await registry.get(key)


class BurstAdmissionTests(unittest.IsolatedAsyncioTestCase):
    async def test_authenticated_bucket_is_secret_scoped_and_active_bounded(self) -> None:
        admission = BurstAdmissionControl(
            max_per_minute=2,
            max_active_per_secret=1,
        )
        scope = burst_session_key(SECRET, SESSION_ID)[0]
        other_scope = burst_session_key(OTHER_SECRET, SESSION_ID)[0]
        self.assertTrue(await admission.acquire(scope))
        self.assertFalse(await admission.acquire(scope))
        await admission.release(scope)
        self.assertTrue(await admission.acquire(scope))
        await admission.release(scope)
        self.assertFalse(await admission.acquire(scope))
        self.assertTrue(await admission.acquire(other_scope))
        await admission.release(other_scope)

    async def test_authenticated_attempt_can_be_refunded_from_ip_rate_limit(self) -> None:
        admission = AdmissionControl(max_active=2, max_per_minute=1)
        self.assertTrue(await admission.acquire("192.0.2.1"))
        await admission.refund_rate_limit("192.0.2.1")
        await admission.release()
        self.assertTrue(await admission.acquire("192.0.2.1"))
        await admission.release()

    async def test_over_quota_secret_does_not_earn_ip_rate_refund(self) -> None:
        peer = "192.0.2.1"
        admission = AdmissionControl(max_active=2, max_per_minute=1)
        burst_admission = BurstAdmissionControl(
            max_per_minute=1,
            max_active_per_secret=1,
        )
        scope = burst_session_key(SECRET, SESSION_ID)[0]
        self.assertTrue(await burst_admission.acquire(scope))
        await burst_admission.release(scope)

        self.assertTrue(await admission.acquire(peer))
        returned_scope, allowed = await acquire_authenticated_burst(
            SECRET, admission, peer, burst_admission
        )
        self.assertEqual(scope, returned_scope)
        self.assertFalse(allowed)
        await admission.release()
        self.assertFalse(await admission.acquire(peer))


class BurstFlowTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.registry = BurstSessionRegistry()
        self.backend_writer = FakeWriter()
        self.backend_reader = BlockingReader()
        self.connection_patch = mock.patch(
            "morokss.server.asyncio.open_connection",
            new=mock.AsyncMock(return_value=(self.backend_reader, self.backend_writer)),
        )
        self.connection_patch.start()
        self.key = burst_session_key(SECRET, SESSION_ID)
        await self.registry.open(self.key, ("127.0.0.1", 8388))

    async def asyncTearDown(self) -> None:
        self.connection_patch.stop()
        await self.registry.close()

    async def test_upload_validates_data_writes_and_acknowledges(self) -> None:
        tunnel = FakeTunnel(
            burst_json(
                version=1,
                session_id=SESSION_ID,
                sequence=0,
                fin=False,
                length=3,
            ),
            pack_envelope(b"abc"),
        )
        await run_burst_upload(tunnel, self.registry, SECRET)

        self.assertEqual(bytes(self.backend_writer.data), b"abc")
        self.assertTrue(tunnel.closed)
        self.assertEqual(
            {
                "version": 1,
                "session_id": SESSION_ID,
                "sequence": 0,
                "status": "written",
                "next_sequence": 1,
                "fin": False,
            },
            decode_burst_json(tunnel.sent[0]),
        )

        retry = FakeTunnel(
            burst_json(
                version=1,
                session_id=SESSION_ID,
                sequence=0,
                fin=False,
                length=3,
            ),
            pack_envelope(b"abc"),
        )
        await run_burst_upload(retry, self.registry, SECRET)
        self.assertEqual(bytes(self.backend_writer.data), b"abc")
        self.assertEqual("duplicate", decode_burst_json(retry.sent[0])["status"])

    async def test_upload_rejects_wrong_secret_length_and_oversized_chunk(self) -> None:
        wrong_secret = FakeTunnel(
            burst_json(
                version=1,
                session_id=SESSION_ID,
                sequence=0,
                fin=False,
                length=0,
            )
        )
        with self.assertRaises(ProtocolError):
            await run_burst_upload(wrong_secret, self.registry, OTHER_SECRET)

        wrong_length = FakeTunnel(
            burst_json(
                version=1,
                session_id=SESSION_ID,
                sequence=0,
                fin=False,
                length=3,
            ),
            pack_envelope(b"ab"),
        )
        with self.assertRaises(ProtocolError):
            await run_burst_upload(wrong_length, self.registry, SECRET)

        oversized = FakeTunnel(
            burst_json(
                version=1,
                session_id=SESSION_ID,
                sequence=0,
                fin=False,
                length=BURST_MAX_DATA + 1,
            )
        )
        with self.assertRaises(ProtocolError):
            await run_burst_upload(oversized, self.registry, SECRET)

    async def test_download_returns_hashed_data_and_duplicate(self) -> None:
        session = await self.registry.get(self.key)
        session.backend_reader = ChunkReader(b"reply")
        tunnel = FakeTunnel(
            burst_json(
                version=1,
                session_id=SESSION_ID,
                sequence=0,
                max_length=8192,
            )
        )
        await run_burst_download(tunnel, self.registry, SECRET)
        ack = decode_burst_json(tunnel.sent[0])
        self.assertEqual("written", ack["status"])
        self.assertEqual(5, ack["length"])
        self.assertEqual(b"reply", unpack_envelope(tunnel.sent[1]))

        retry = FakeTunnel(
            burst_json(
                version=1,
                session_id=SESSION_ID,
                sequence=0,
                max_length=8192,
            )
        )
        await run_burst_download(retry, self.registry, SECRET)
        self.assertEqual("duplicate", decode_burst_json(retry.sent[0])["status"])
        self.assertEqual(b"reply", unpack_envelope(retry.sent[1]))

    async def test_open_detaches_session_when_control_dies(self) -> None:
        # Use a separate registry because asyncSetUp already occupies this key.
        registry = BurstSessionRegistry()
        writer = FakeWriter()
        with mock.patch(
            "morokss.server.asyncio.open_connection",
            new=mock.AsyncMock(return_value=(BlockingReader(), writer)),
        ):
            tunnel = FakeTunnel(
                burst_json(version=1, session_id="a" * 32)
            )
            await run_burst_open(
                tunnel, registry, SECRET, ("127.0.0.1", 8388)
            )

        self.assertEqual("open", decode_burst_json(tunnel.sent[0])["status"])
        self.assertTrue(tunnel.closed)
        self.assertFalse(writer.closed)
        session = await registry.get(burst_session_key(SECRET, "a" * 32))
        self.assertEqual(("written", 1, False), await session.submit(0, b"late", False))
        self.assertEqual(b"late", bytes(writer.data))
        await registry.close()
        self.assertTrue(writer.closed)

    async def test_probe_backend_echoes_after_control_detaches(self) -> None:
        registry = BurstSessionRegistry()
        session_id = "d" * 32
        key = burst_session_key(SECRET, session_id)
        tunnel = FakeTunnel(
            burst_json(version=1, session_id=session_id, probe=True)
        )
        with mock.patch(
            "morokss.server.asyncio.open_connection",
            new=asyncio.streams.open_connection,
        ):
            await asyncio.wait_for(
                run_burst_open(tunnel, registry, SECRET, ("127.0.0.1", 1)),
                timeout=3,
            )

        session = await registry.get(key)
        self.assertEqual(
            ("written", 1, False),
            await asyncio.wait_for(session.submit(0, b"probe", False), timeout=2),
        )
        self.assertEqual(
            ("written", 2, True),
            await asyncio.wait_for(session.submit(1, b"", True), timeout=2),
        )
        self.assertEqual(
            ("written", 1, b"probe", False),
            await asyncio.wait_for(session.read_download(0, 8192), timeout=7),
        )
        self.assertEqual(
            ("written", 2, b"", True),
            await asyncio.wait_for(session.read_download(1, 8192), timeout=7),
        )
        await asyncio.wait_for(registry.close(), timeout=5)

    async def test_download_poll_observes_eof_and_control_waits_for_upload_fin(self) -> None:
        registry = BurstSessionRegistry()
        writer = FakeWriter()
        session_id = "b" * 32
        key = burst_session_key(SECRET, session_id)
        with mock.patch(
            "morokss.server.asyncio.open_connection",
            new=mock.AsyncMock(return_value=(EOFReader(), writer)),
        ):
            tunnel = FakeHTTPChunkTunnel(
                burst_json(version=1, session_id=session_id)
            )
            control = asyncio.create_task(
                run_burst_open(
                    tunnel, registry, SECRET, ("127.0.0.1", 8388)
                )
            )
            for _ in range(20):
                if len(tunnel.sent) >= 1:
                    break
                await asyncio.sleep(0)

            self.assertEqual("open", decode_burst_json(tunnel.sent[0])["status"])
            self.assertFalse(control.done())
            session = await registry.get(key)
            self.assertEqual(
                ("written", 1, b"", True), await session.read_download(0, 8192)
            )
            self.assertTrue(session.download_finished)
            self.assertFalse(control.done())
            await session.submit(0, b"", True)
            await asyncio.wait_for(control, timeout=1)

        self.assertTrue(tunnel.closed)
        self.assertEqual(1, writer.eof_count)
        retained = await registry.get(key)
        self.assertTrue(retained.cleanup_scheduled)
        await registry.close()
        self.assertTrue(writer.closed)

    async def test_http_physical_eof_detaches_control_without_waiting_for_fin(self) -> None:
        registry = BurstSessionRegistry()
        writer = FakeWriter()
        session_id = "c" * 32
        key = burst_session_key(SECRET, session_id)
        with mock.patch(
            "morokss.server.asyncio.open_connection",
            new=mock.AsyncMock(return_value=(BlockingReader(), writer)),
        ):
            tunnel = FakeHTTPChunkTunnel(
                burst_json(version=1, session_id=session_id),
                physical_eof=True,
            )
            await asyncio.wait_for(
                run_burst_open(
                    tunnel, registry, SECRET, ("127.0.0.1", 8388)
                ),
                timeout=1,
            )

        self.assertTrue(tunnel.closed)
        self.assertFalse(writer.closed)
        self.assertIsNotNone(await registry.get(key))
        await registry.close()
        self.assertTrue(writer.closed)


if __name__ == "__main__":
    unittest.main()
