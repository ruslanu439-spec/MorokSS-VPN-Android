import asyncio
import contextlib
import datetime
import ipaddress
import pathlib
import ssl
import struct
import tempfile
import time
import unittest
from unittest import mock

from morokss.client import open_websocket
from morokss.protocol import (
    HTTPChunkStream,
    ProtocolError,
    ReplayCache,
    WebSocketStream,
    accepted_paths,
    daily_path,
    load_secrets,
    make_auth,
    pack_datagram,
    pack_envelope,
    parse_endpoint,
    read_ws_frame,
    secret_for_path,
    unpack_envelope,
    unpack_datagram,
    verify_auth,
)
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


class ProtocolTests(unittest.TestCase):
    def test_endpoint_parser(self) -> None:
        self.assertEqual(parse_endpoint("127.0.0.1:443"), ("127.0.0.1", 443))
        with self.assertRaises(ValueError):
            parse_endpoint("missing-port")

    def test_daily_path_is_stable_and_rotates(self) -> None:
        now = 1_700_000_000
        self.assertEqual(daily_path(SECRET, now), daily_path(SECRET, now + 60))
        self.assertNotEqual(daily_path(SECRET, now), daily_path(SECRET, now + 86400))
        self.assertIn(daily_path(SECRET, now), accepted_paths(SECRET, now))

    def test_authentication_and_replay_defense(self) -> None:
        now = int(time.time())
        auth = make_auth(SECRET, now)
        cache = ReplayCache()
        self.assertTrue(verify_auth(auth, SECRET, cache, now=now))
        self.assertFalse(verify_auth(auth, SECRET, cache, now=now))
        self.assertFalse(verify_auth(auth, SECRET + b"x", ReplayCache(), now=now))
        self.assertFalse(
            verify_auth(make_auth(SECRET, now - 1000), SECRET, ReplayCache(), now=now)
        )

    def test_secret_rotation_selects_matching_secret(self) -> None:
        previous = b"previous-secret-that-is-longer-than-thirty-two-bytes"
        now = 1_700_000_000
        self.assertEqual(
            secret_for_path(daily_path(SECRET, now), (SECRET, previous), now), SECRET
        )
        self.assertEqual(
            secret_for_path(daily_path(previous, now), (SECRET, previous), now),
            previous,
        )
        self.assertIsNone(secret_for_path("/unknown", (SECRET, previous), now))

    def test_secret_rotation_loads_current_and_previous_values(self) -> None:
        previous = "previous-secret-that-is-longer-than-thirty-two-bytes"
        with mock.patch.dict(
            "os.environ",
            {
                "MOROKSS_SECRET": SECRET.decode("ascii"),
                "MOROKSS_PREVIOUS_SECRET": previous,
            },
            clear=True,
        ):
            self.assertEqual(load_secrets(), (SECRET, previous.encode("ascii")))

    def test_envelope_round_trip(self) -> None:
        for data in (b"", b"hello", b"x" * 8192):
            envelope = pack_envelope(data)
            self.assertEqual(unpack_envelope(envelope), data)
            self.assertGreaterEqual(len(envelope), len(data) + 2)

    def test_large_datagram_round_trip(self) -> None:
        data = b"u" * (32 * 1024)
        self.assertEqual(unpack_datagram(pack_datagram(data)), data)

    def test_invalid_envelope(self) -> None:
        with self.assertRaises(ProtocolError):
            unpack_envelope(b"\x00")
        with self.assertRaises(ProtocolError):
            unpack_envelope(struct.pack("!H", 100) + b"short")


class WebSocketStreamTests(unittest.IsolatedAsyncioTestCase):
    async def test_server_ignores_shutdown_timeout(self) -> None:
        reader = mock.Mock()
        writer = mock.Mock()
        writer.is_closing.return_value = False
        writer.wait_closed = mock.AsyncMock(side_effect=asyncio.TimeoutError)
        with mock.patch(
            "morokss.server.read_http_head",
            new=mock.AsyncMock(side_effect=asyncio.TimeoutError),
        ):
            await handle_client(
                reader,
                writer,
                secret=SECRET,
                backend=("127.0.0.1", 8388),
                decoy=None,
                replay_cache=ReplayCache(),
            )
        writer.close.assert_called_once_with()

    async def test_oversized_control_frame_is_rejected(self) -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(bytes((0x88, 126, 0, 126)) + bytes(126))
        reader.feed_eof()
        with self.assertRaises(ProtocolError):
            await read_ws_frame(reader, expect_masked=False)

    async def test_http_chunk_stream_round_trip(self) -> None:
        received = asyncio.Future()

        async def handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            stream = HTTPChunkStream(reader, writer)
            received.set_result(await stream.receive_binary())
            await stream.send_binary(b"reply")
            await stream.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        client = HTTPChunkStream(reader, writer)
        await client.send_binary(b"request")
        self.assertEqual(await asyncio.wait_for(received, 2), b"request")
        self.assertEqual(await client.receive_binary(), b"reply")
        await client.close()
        server.close()
        await server.wait_closed()

    async def test_masked_client_to_server_round_trip(self) -> None:
        received = asyncio.Future()

        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            websocket = WebSocketStream(reader, writer, client_side=False)
            received.set_result(await websocket.receive_binary())
            await websocket.send_binary(b"reply")
            await websocket.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        client = WebSocketStream(reader, writer, client_side=True)
        await client.send_binary(b"request")
        self.assertEqual(await asyncio.wait_for(received, 2), b"request")
        self.assertEqual(await client.receive_binary(), b"reply")
        await client.close()
        server.close()
        await server.wait_closed()


@unittest.skipIf(x509 is None, "cryptography is required for the TLS integration test")
class TunnelIntegrationTests(unittest.IsolatedAsyncioTestCase):
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
                    [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
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

    async def test_tls_websocket_auth_and_backend_relay(self) -> None:
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

        async def decoy_site(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            await reader.readuntil(b"\r\n\r\n")
            body = b"ordinary website"
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: "
                + str(len(body)).encode("ascii")
                + b"\r\nConnection: close\r\n\r\n"
                + body
            )
            await writer.drain()
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()

        backend_server = await asyncio.start_server(echo_backend, "127.0.0.1", 0)
        backend_port = backend_server.sockets[0].getsockname()[1]
        udp_backend_transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            EchoDatagramProtocol,
            local_addr=("127.0.0.1", backend_port),
        )
        decoy_server = await asyncio.start_server(decoy_site, "127.0.0.1", 0)
        decoy_port = decoy_server.sockets[0].getsockname()[1]

        with tempfile.TemporaryDirectory() as temp_dir:
            cert_path, key_path = self.create_certificate(pathlib.Path(temp_dir))
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(cert_path, key_path)
            outer_server = await asyncio.start_server(
                lambda reader, writer: handle_client(
                    reader,
                    writer,
                    secret=(ROTATED_SECRET, SECRET),
                    backend=("127.0.0.1", backend_port),
                    decoy=("127.0.0.1", decoy_port),
                    replay_cache=ReplayCache(),
                ),
                "127.0.0.1",
                0,
                ssl=tls,
            )
            outer_port = outer_server.sockets[0].getsockname()[1]
            websocket = await open_websocket(
                ("127.0.0.1", outer_port),
                "localhost",
                SECRET,
                insecure=True,
                ca_file=None,
            )
            await websocket.send_binary(pack_envelope(b"end-to-end"))
            reply = await asyncio.wait_for(websocket.receive_binary(), timeout=2)
            self.assertEqual(unpack_envelope(reply), b"end-to-end")
            await websocket.close()

            udp_websocket = await open_websocket(
                ("127.0.0.1", outer_port),
                "localhost",
                SECRET,
                insecure=True,
                ca_file=None,
                network="udp",
            )
            udp_payload = pack_datagram(b"udp-end-to-end")
            await udp_websocket.send_binary(udp_payload)
            udp_reply = await asyncio.wait_for(
                udp_websocket.receive_binary(), timeout=2
            )
            self.assertEqual(unpack_datagram(udp_reply), b"udp-end-to-end")
            await udp_websocket.close()

            insecure_tls = ssl._create_unverified_context()
            probe_reader, probe_writer = await asyncio.open_connection(
                "127.0.0.1",
                outer_port,
                ssl=insecure_tls,
                server_hostname="localhost",
            )
            probe_writer.write(
                b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            )
            await probe_writer.drain()
            probe_response = await asyncio.wait_for(probe_reader.read(), timeout=2)
            self.assertIn(b"200 OK", probe_response)
            self.assertTrue(probe_response.endswith(b"ordinary website"))
            probe_writer.close()
            with contextlib.suppress(ConnectionError):
                await probe_writer.wait_closed()

            outer_server.close()
            await outer_server.wait_closed()

        backend_server.close()
        await backend_server.wait_closed()
        udp_backend_transport.close()
        decoy_server.close()
        await decoy_server.wait_closed()


if __name__ == "__main__":
    unittest.main()
