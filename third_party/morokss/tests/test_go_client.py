import asyncio
import contextlib
import datetime
import ipaddress
import json
import os
import pathlib
import shutil
import socket
import ssl
import sys
import tempfile
import unittest

from morokss.protocol import ReplayCache
from morokss.server import handle_client

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except ImportError:  # pragma: no cover - optional integration-test dependency
    x509 = None


SECRET = b"test-secret-that-is-longer-than-thirty-two-bytes"
ROTATED_SECRET = b"rotated-secret-that-is-longer-than-thirty-two-bytes"
PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
RUN_GO_TESTS = os.environ.get("MOROKSS_RUN_GO_TESTS") == "1"


@unittest.skipUnless(RUN_GO_TESTS, "set MOROKSS_RUN_GO_TESTS=1 to build the Go client")
@unittest.skipIf(shutil.which("go") is None, "Go toolchain isn't available")
@unittest.skipIf(x509 is None, "cryptography is required for the TLS integration test")
class GoClientIntegrationTests(unittest.IsolatedAsyncioTestCase):
    def create_certificate(self, directory: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
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

    async def test_go_client_talks_to_python_server(self) -> None:
        class EchoDatagramProtocol(asyncio.DatagramProtocol):
            def connection_made(self, transport: asyncio.BaseTransport) -> None:
                self.transport = transport

            def datagram_received(
                self, data: bytes, address: tuple[str, int]
            ) -> None:
                self.transport.sendto(data, address)

        async def echo_backend(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                while data := await reader.read(8192):
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()
                with contextlib.suppress(ConnectionError):
                    await writer.wait_closed()

        backend_server = await asyncio.start_server(echo_backend, "127.0.0.1", 0)
        backend_port = backend_server.sockets[0].getsockname()[1]
        udp_backend_transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            EchoDatagramProtocol,
            local_addr=("127.0.0.1", backend_port),
        )
        outer_server = None
        client_process = None

        try:
            with tempfile.TemporaryDirectory() as temp_dir_text:
                temp_dir = pathlib.Path(temp_dir_text)
                binary_name = "morokss-client.exe" if sys.platform == "win32" else "morokss-client"
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
                self.assertEqual(build.returncode, 0, build_error.decode(errors="replace"))

                cert_path, key_path = self.create_certificate(temp_dir)
                tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                tls.load_cert_chain(cert_path, key_path)
                tls.set_alpn_protocols(["http/1.1"])
                replay_cache = ReplayCache()
                outer_server = await asyncio.start_server(
                    lambda reader, writer: handle_client(
                        reader,
                        writer,
                        secret=(ROTATED_SECRET, SECRET),
                        backend=("127.0.0.1", backend_port),
                        decoy=None,
                        replay_cache=replay_cache,
                    ),
                    "127.0.0.1",
                    0,
                    ssl=tls,
                )
                outer_port = outer_server.sockets[0].getsockname()[1]

                dead_listener = await asyncio.start_server(
                    lambda _reader, writer: writer.close(), "127.0.0.1", 0
                )
                dead_port = dead_listener.sockets[0].getsockname()[1]
                dead_listener.close()
                await dead_listener.wait_closed()

                local_listener = await asyncio.start_server(
                    lambda _reader, writer: writer.close(), "127.0.0.1", 0
                )
                local_port = local_listener.sockets[0].getsockname()[1]
                local_listener.close()
                await local_listener.wait_closed()

                environment = os.environ.copy()
                environment["MOROKSS_SECRET"] = SECRET.decode("ascii")
                client_process = await asyncio.create_subprocess_exec(
                    str(binary_path),
                    "--listen",
                    f"127.0.0.1:{local_port}",
                    "--udp-listen",
                    f"127.0.0.1:{local_port}",
                    "--endpoint",
                    f"127.0.0.1:{dead_port},localhost",
                    "--endpoint",
                    f"127.0.0.1:{outer_port},localhost",
                    "--profile",
                    "auto",
                    "--transport",
                    "http-stream",
                    "--profile-cache",
                    str(temp_dir / "profile-cache.json"),
                    "--endpoint-cache",
                    str(temp_dir / "endpoint-cache.json"),
                    "--insecure",
                    env=environment,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                startup_lines = []
                for _ in range(2):
                    startup_lines.append(
                        await asyncio.wait_for(client_process.stderr.readline(), timeout=10)
                    )
                    if b"MorokSS Go client listening on" in startup_lines[-1]:
                        break
                self.assertTrue(
                    any(b"MorokSS Go client listening on" in line for line in startup_lines),
                    startup_lines,
                )

                reader, writer = await asyncio.open_connection("127.0.0.1", local_port)
                message = b"go-client-to-python-server"
                writer.write(message)
                await writer.drain()
                reply = await asyncio.wait_for(reader.readexactly(len(message)), timeout=5)
                self.assertEqual(reply, message)
                cache = json.loads((temp_dir / "profile-cache.json").read_text("utf-8"))
                cached_entries = list(cache["servers"].values())
                self.assertEqual(len(cached_entries), 1)
                self.assertEqual(cached_entries[0]["profile"], "chrome")
                endpoint_cache = json.loads(
                    (temp_dir / "endpoint-cache.json").read_text("utf-8")
                )
                selected_endpoints = list(endpoint_cache["pools"].values())
                self.assertEqual(len(selected_endpoints), 1)
                self.assertEqual(
                    selected_endpoints[0]["endpoint"],
                    f"127.0.0.1:{outer_port}|localhost",
                )

                udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_socket.setblocking(False)
                try:
                    udp_message = b"go-udp-client-to-python-server"
                    await asyncio.get_running_loop().sock_sendto(
                        udp_socket,
                        udp_message,
                        ("127.0.0.1", local_port),
                    )
                    udp_reply, _ = await asyncio.wait_for(
                        asyncio.get_running_loop().sock_recvfrom(udp_socket, 65535),
                        timeout=8,
                    )
                    self.assertEqual(udp_reply, udp_message)
                finally:
                    udp_socket.close()

                endpoint_cache = json.loads(
                    (temp_dir / "endpoint-cache.json").read_text("utf-8")
                )
                selected_endpoints = list(endpoint_cache["pools"].values())
                self.assertEqual(len(selected_endpoints), 2)
                self.assertTrue(
                    all(
                        item["endpoint"]
                        == f"127.0.0.1:{outer_port}|localhost"
                        for item in selected_endpoints
                    )
                )
                writer.close()
                with contextlib.suppress(ConnectionError):
                    await writer.wait_closed()
                client_process.terminate()
                try:
                    await asyncio.wait_for(client_process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    client_process.kill()
                    await client_process.wait()
                client_process = None

                diagnose_process = await asyncio.create_subprocess_exec(
                    str(binary_path),
                    "--diagnose",
                    "--diagnose-network",
                    "all",
                    "--endpoint",
                    f"127.0.0.1:{dead_port},localhost",
                    "--endpoint",
                    f"127.0.0.1:{outer_port},localhost",
                    "--profile",
                    "auto",
                    "--transport",
                    "http-stream",
                    "--profile-cache",
                    str(temp_dir / "diagnose-profile-cache.json"),
                    "--transport-cache",
                    str(temp_dir / "diagnose-transport-cache.json"),
                    "--endpoint-cache",
                    str(temp_dir / "diagnose-endpoint-cache.json"),
                    "--insecure",
                    env=environment,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                diagnose_output, diagnose_error = await asyncio.wait_for(
                    diagnose_process.communicate(), timeout=30
                )
                self.assertEqual(
                    diagnose_process.returncode,
                    0,
                    diagnose_error.decode(errors="replace"),
                )
                report = json.loads(diagnose_output)
                self.assertEqual(report["schema_version"], 1)
                self.assertEqual(report["client_version"], "0.3.0")
                results = {item["network"]: item for item in report["results"]}
                self.assertEqual(set(results), {"tcp", "udp"})
                for result in results.values():
                    self.assertEqual(result["status"], "ready")
                    self.assertEqual(result["stage"], "ready")
                    self.assertEqual(result["selected"]["endpoint_index"], 2)
                    self.assertEqual(result["selected"]["tls_profile"], "chrome")
                    self.assertEqual(result["selected"]["transport"], "http-stream")
                    self.assertGreaterEqual(len(result["attempts"]), 2)
                    self.assertEqual(result["attempts"][0]["status"], "failed")
                    self.assertEqual(result["attempts"][-1]["status"], "ready")
                    self.assertNotIn("address", result["selected"])
                    self.assertNotIn("hostname", result["selected"])
                    self.assertTrue(
                        all("address" not in attempt for attempt in result["attempts"])
                    )
                    self.assertTrue(
                        all("hostname" not in attempt for attempt in result["attempts"])
                    )

                failed_diagnose = await asyncio.create_subprocess_exec(
                    str(binary_path),
                    "--diagnose",
                    "--endpoint",
                    f"127.0.0.1:{dead_port},localhost",
                    "--profile",
                    "chrome",
                    "--transport",
                    "http-stream",
                    "--endpoint-cache",
                    "",
                    "--profile-cache",
                    "",
                    "--transport-cache",
                    "",
                    "--insecure",
                    env=environment,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                failed_output, _ = await asyncio.wait_for(
                    failed_diagnose.communicate(), timeout=15
                )
                self.assertEqual(failed_diagnose.returncode, 1)
                failed_report = json.loads(failed_output)
                failed_result = failed_report["results"][0]
                self.assertEqual(failed_result["status"], "failed")
                self.assertEqual(failed_result["stage"], "tcp")
                self.assertEqual(failed_result["error_code"], "tcp_failed")
                self.assertNotIn(str(dead_port), failed_output.decode("utf-8"))
        finally:
            if client_process is not None and client_process.returncode is None:
                client_process.terminate()
                try:
                    await asyncio.wait_for(client_process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    client_process.kill()
                    await client_process.wait()
            if outer_server is not None:
                outer_server.close()
                await outer_server.wait_closed()
            udp_backend_transport.close()
            backend_server.close()
            await backend_server.wait_closed()
