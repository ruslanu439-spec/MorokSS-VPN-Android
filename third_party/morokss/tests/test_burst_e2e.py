import asyncio
import contextlib
import datetime
import hashlib
import ipaddress
import os
import pathlib
import shutil
import ssl
import sys
import tempfile
import unittest
from dataclasses import dataclass

from morokss.protocol import ReplayCache
from morokss.server import BurstSessionRegistry, handle_client

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except ImportError:  # pragma: no cover - optional integration-test dependency
    x509 = None


SECRET = b"burst-e2e-test-secret-that-is-longer-than-thirty-two-bytes"
PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
RUN_GO_TESTS = os.environ.get("MOROKSS_RUN_GO_TESTS") == "1"
FLOW_BUDGET = 16 * 1024
BURST_CHUNK = int(os.environ.get("MOROKSS_BURST_E2E_CHUNK", 8 * 1024))
PAYLOAD_SIZE = int(os.environ.get("MOROKSS_BURST_E2E_BYTES", 8 * 1024 * 1024))
WIRE_TRANSPORT = os.environ.get("MOROKSS_BURST_E2E_TRANSPORT", "websocket")


@dataclass
class FlowObservation:
    index: int
    client_bytes: int = 0
    server_bytes: int = 0
    clamped: bool = False
    server_clamped: bool = False
    injected_drop: bool = False
    discarded_server_bytes: int = 0


class DirectionalClampProxy:
    """A bidirectional byte-budget clamp for every encrypted TCP flow."""

    def __init__(self, target: tuple[str, int], budget: int) -> None:
        self.target = target
        self.budget = budget
        self.flows: list[FlowObservation] = []
        self.tasks: set[asyncio.Task[object]] = set()
        self.injected_ack = asyncio.Event()
        self.claimed_ack = False
        self.server: asyncio.AbstractServer | None = None

    async def start(self) -> int:
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", 0)
        assert self.server.sockets
        return int(self.server.sockets[0].getsockname()[1])

    async def close(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
        tasks = tuple(self.tasks)
        if tasks:
            done, pending = await asyncio.wait(tasks, timeout=5)
            for task in pending:
                task.cancel()
            await asyncio.gather(*done, *pending, return_exceptions=True)

    @staticmethod
    async def read_tls_record(reader: asyncio.StreamReader) -> bytes:
        header = await reader.readexactly(5)
        length = int.from_bytes(header[3:5], "big")
        if length > (1 << 14) + 2048:
            raise ConnectionError("invalid TLS record length")
        return header + await reader.readexactly(length)

    async def handle(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.current_task()
        assert task is not None
        self.tasks.add(task)
        flow = FlowObservation(index=len(self.flows))
        self.flows.append(flow)
        server_writer: asyncio.StreamWriter | None = None
        try:
            server_reader, server_writer = await asyncio.open_connection(*self.target)
            suppress_download = asyncio.Event()
            async def client_to_server() -> None:
                nonlocal server_writer
                assert server_writer is not None
                while True:
                    record = await self.read_tls_record(client_reader)
                    if flow.client_bytes + len(record) > self.budget:
                        flow.clamped = True
                        return

                    trigger_lost_ack = (
                        flow.index > 0
                        and not self.claimed_ack
                        and flow.client_bytes + len(record) >= 4 * 1024
                    )
                    flow.client_bytes += len(record)
                    if trigger_lost_ack:
                        self.claimed_ack = True
                        suppress_download.set()
                    server_writer.write(record)
                    await server_writer.drain()
                    if flow.injected_drop:
                        return

            async def server_to_client() -> None:
                while True:
                    data = await self.read_tls_record(server_reader)
                    if suppress_download.is_set():
                        flow.discarded_server_bytes += len(data)
                        flow.injected_drop = True
                        self.injected_ack.set()
                        return
                    if flow.server_bytes + len(data) > self.budget:
                        flow.server_clamped = True
                        return
                    flow.server_bytes += len(data)
                    client_writer.write(data)
                    await client_writer.drain()

            forward = {
                asyncio.create_task(client_to_server()),
                asyncio.create_task(server_to_client()),
            }
            _, pending = await asyncio.wait(
                forward, return_when=asyncio.FIRST_COMPLETED
            )
            for pending_task in pending:
                pending_task.cancel()
            await asyncio.gather(*forward, return_exceptions=True)
        except (
            asyncio.IncompleteReadError,
            asyncio.TimeoutError,
            ConnectionError,
            OSError,
        ):
            pass
        finally:
            if server_writer is not None:
                server_writer.close()
                with contextlib.suppress(OSError, asyncio.TimeoutError):
                    await server_writer.wait_closed()
            client_writer.close()
            with contextlib.suppress(OSError, asyncio.TimeoutError):
                await client_writer.wait_closed()
            self.tasks.discard(task)


@unittest.skipUnless(
    RUN_GO_TESTS, "set MOROKSS_RUN_GO_TESTS=1 to build the Go client"
)
@unittest.skipIf(shutil.which("go") is None, "Go toolchain isn't available")
@unittest.skipIf(x509 is None, "cryptography is required for the TLS integration test")
class BurstEndToEndTests(unittest.IsolatedAsyncioTestCase):
    def create_certificate(
        self, directory: pathlib.Path
    ) -> tuple[pathlib.Path, pathlib.Path]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("localhost"),
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    ]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        cert_path = directory / "cert.pem"
        key_path = directory / "key.pem"
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        return cert_path, key_path

    async def test_forced_burst_survives_per_flow_clamp_and_lost_ack(self) -> None:
        async def echo_backend(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                while data := await reader.read(64 * 1024):
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()
                with contextlib.suppress(OSError, asyncio.TimeoutError):
                    await writer.wait_closed()

        backend_server = await asyncio.start_server(echo_backend, "127.0.0.1", 0)
        assert backend_server.sockets
        backend_port = int(backend_server.sockets[0].getsockname()[1])
        outer_server: asyncio.AbstractServer | None = None
        proxy: DirectionalClampProxy | None = None
        registry = BurstSessionRegistry()
        client_process: asyncio.subprocess.Process | None = None
        local_writer: asyncio.StreamWriter | None = None
        temp_dir_for_cleanup: str | None = None

        try:
            with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir_text:
                temp_dir_for_cleanup = temp_dir_text
                temp_dir = pathlib.Path(temp_dir_text)
                binary_name = (
                    "morokss-client.exe" if sys.platform == "win32" else "morokss-client"
                )
                binary_path = temp_dir / binary_name
                build = await asyncio.create_subprocess_exec(
                    "go",
                    "build",
                    "-o",
                    str(binary_path),
                    "./cmd/morokss-client",
                    cwd=PROJECT_ROOT,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, build_error = await asyncio.wait_for(build.communicate(), timeout=90)
                self.assertEqual(
                    build.returncode, 0, build_error.decode(errors="replace")
                )

                cert_path, key_path = self.create_certificate(temp_dir)
                tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                tls.load_cert_chain(cert_path, key_path)
                tls.set_alpn_protocols(["http/1.1"])
                replay_cache = ReplayCache()
                outer_server = await asyncio.start_server(
                    lambda reader, writer: handle_client(
                        reader,
                        writer,
                        secret=SECRET,
                        backend=("127.0.0.1", backend_port),
                        decoy=None,
                        replay_cache=replay_cache,
                        burst_registry=registry,
                    ),
                    "127.0.0.1",
                    0,
                    ssl=tls,
                )
                assert outer_server.sockets
                outer_port = int(outer_server.sockets[0].getsockname()[1])

                proxy = DirectionalClampProxy(
                    ("127.0.0.1", outer_port), FLOW_BUDGET
                )
                proxy_port = await proxy.start()

                port_reservation = await asyncio.start_server(
                    lambda _reader, writer: writer.close(), "127.0.0.1", 0
                )
                assert port_reservation.sockets
                local_port = int(port_reservation.sockets[0].getsockname()[1])
                port_reservation.close()
                await port_reservation.wait_closed()

                environment = os.environ.copy()
                environment["MOROKSS_SECRET"] = SECRET.decode("ascii")
                client_process = await asyncio.create_subprocess_exec(
                    str(binary_path),
                    "--listen",
                    f"127.0.0.1:{local_port}",
                    "--endpoint",
                    f"127.0.0.1:{proxy_port},localhost",
                    "--profile",
                    "chrome",
                    "--transport",
                    WIRE_TRANSPORT,
                    "--cover-sni-mode",
                    "off",
                    "--profile-cache",
                    "",
                    "--transport-cache",
                    "",
                    "--endpoint-cache",
                    "",
                    "--cover-sni-cache",
                    "",
                    "--burst-upload",
                    "--burst-chunk",
                    str(BURST_CHUNK),
                    "--burst-parallel",
                    "4",
                    "--insecure",
                    env=environment,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                startup_lines: list[bytes] = []
                for _ in range(20):
                    line = await asyncio.wait_for(
                        client_process.stderr.readline(), timeout=10
                    )
                    startup_lines.append(line)
                    if b"MorokSS Go client listening on" in line:
                        break
                self.assertTrue(
                    any(
                        b"MorokSS Go client listening on" in line
                        for line in startup_lines
                    ),
                    startup_lines,
                )

                local_reader, local_writer = await asyncio.open_connection(
                    "127.0.0.1", local_port
                )
                payload = hashlib.shake_256(b"morokss-burst-e2e-payload").digest(
                    PAYLOAD_SIZE
                )

                async def receive_echo() -> bytes:
                    received = bytearray()
                    while data := await local_reader.read(64 * 1024):
                        received.extend(data)
                    return bytes(received)

                receive_task = asyncio.create_task(receive_echo())
                local_writer.write(payload)
                await local_writer.drain()
                self.assertTrue(local_writer.can_write_eof())
                local_writer.write_eof()
                try:
                    echoed = await asyncio.wait_for(receive_task, timeout=180)
                except BaseException as error:
                    client_process.terminate()
                    try:
                        await asyncio.wait_for(client_process.wait(), timeout=5)
                    except asyncio.TimeoutError:
                        client_process.kill()
                        await client_process.wait()
                    client_log = b"".join(startup_lines)
                    client_log += await client_process.stderr.read()
                    flow_log = [
                        {
                            "index": flow.index,
                            "client_bytes": flow.client_bytes,
                            "server_bytes": flow.server_bytes,
                            "clamped": flow.clamped,
                            "server_clamped": flow.server_clamped,
                            "injected_drop": flow.injected_drop,
                            "discarded_server_bytes": flow.discarded_server_bytes,
                        }
                        for flow in proxy.flows
                    ]
                    raise AssertionError(
                        f"burst client failed: {error!r}; "
                        f"flows={flow_log}; stderr={client_log.decode(errors='replace')}"
                    ) from error

                self.assertEqual(len(echoed), PAYLOAD_SIZE)
                self.assertEqual(
                    hashlib.sha256(echoed).digest(),
                    hashlib.sha256(payload).digest(),
                )
                self.assertEqual(echoed, payload)

                data_flows = proxy.flows[1:]
                injected = [flow for flow in data_flows if flow.injected_drop]
                self.assertEqual(len(injected), 1)
                self.assertGreater(injected[0].discarded_server_bytes, 0)
                intact_flows = [flow for flow in data_flows if not flow.injected_drop]
                self.assertGreaterEqual(
                    len(intact_flows),
                    PAYLOAD_SIZE // BURST_CHUNK
                    + PAYLOAD_SIZE // (8 * 1024),
                )
                self.assertTrue(intact_flows)
                self.assertTrue(
                    all(
                        flow.client_bytes <= FLOW_BUDGET
                        and flow.server_bytes <= FLOW_BUDGET
                        for flow in intact_flows
                    ),
                    [
                        {
                            "index": flow.index,
                            "client_bytes": flow.client_bytes,
                            "server_bytes": flow.server_bytes,
                            "clamped": flow.clamped,
                            "server_clamped": flow.server_clamped,
                            "injected_drop": flow.injected_drop,
                        }
                        for flow in intact_flows
                        if flow.client_bytes > FLOW_BUDGET
                        or flow.server_bytes > FLOW_BUDGET
                    ],
                )

                local_writer.close()
                with contextlib.suppress(OSError, asyncio.TimeoutError):
                    await local_writer.wait_closed()
                local_writer = None
                client_process.terminate()
                try:
                    await asyncio.wait_for(client_process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    client_process.kill()
                    await client_process.wait()
                client_process = None
        finally:
            if local_writer is not None:
                local_writer.close()
            if client_process is not None and client_process.returncode is None:
                client_process.terminate()
                try:
                    await asyncio.wait_for(client_process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    client_process.kill()
                    await client_process.wait()
            if proxy is not None:
                await proxy.close()
            if outer_server is not None:
                outer_server.close()
                await outer_server.wait_closed()
            await registry.close()
            backend_server.close()
            await backend_server.wait_closed()
            if temp_dir_for_cleanup is not None:
                shutil.rmtree(temp_dir_for_cleanup, ignore_errors=True)
