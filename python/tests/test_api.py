import hashlib
import json
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from wipeme import APIError, Client

MESSAGE_ID = "1K7mQ2xR8VpC"
DELETION_KEY = "A" * 43


class Handler(BaseHTTPRequestHandler):
    requests = []

    def log_message(self, format, *args):
        pass

    def _record(self, body=b""):
        self.requests.append((self.command, self.path, dict(self.headers), body))

    def do_PUT(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self._record(body)
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"id": MESSAGE_ID, "created": True}).encode())

    def do_GET(self):
        self._record()
        if self.path == "/health":
            body = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        elif self.path == "/api/limits":
            body = json.dumps({"authenticated": False, "plan": "anonymous", "limits": {
                "messageBytes": 3145728, "maxExpirySeconds": 1209600, "devices": 0, "apiKeys": 0,
                "messagesPerMinute": 3, "uploadBytesPerHour": 31457280,
                "speedTestBytesPerRequest": 1048576, "speedTestBytesPerHour": 10485760}, "usage": None}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        elif self.path == "/api/network-test/download?bytes=64":
            body = bytes(64)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", "64")
            self.send_header("Cache-Control", "no-store")
        elif self.path.endswith("/missing"):
            body = b'{"error":"gone","code":"message_not_found"}'
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
        else:
            body = b"opaque\x00ciphertext"
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            content_hash = "0" * 64 if self.path.endswith("2K7mQ2xR8VpC") else hashlib.sha256(body).hexdigest()
            self.send_header("X-Wipe-Content-Hash", content_hash)
            self.send_header("X-Wipe-Cipher-Version", "1")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self._record(body)
        if self.path == "/api/network-test/upload":
            self.send_response(200); result = {"receivedBytes": len(body)}
        elif self.path == "/api/performance-reports":
            self.send_response(201); result = {"accepted": True, "id": "123e4567-e89b-42d3-a456-426614174000"}
        else:
            self.send_response(404); result = {"code": "not_found"}
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(result).encode())

    def do_DELETE(self):
        self._record()
        self.send_response(429)
        self.send_header("Content-Type", "application/json")
        self.send_header("Retry-After", "7")
        self.end_headers()
        self.wfile.write(b'{"error":"slow down","code":"message_rate_limited"}')


class APITests(unittest.TestCase):
    def test_rejects_fragment_in_base_url(self):
        with self.assertRaises(ValueError):
            Client("https://wipe.me/#private-secret")

    @classmethod
    def setUpClass(cls):
        Handler.requests = []
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.client = Client(f"http://127.0.0.1:{cls.server.server_port}", client_id="mobile-ios")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_create_sends_binary_and_required_headers(self):
        body = b"\x00encrypted\xff"
        result = self.client.create(
            MESSAGE_ID,
            body,
            deletion_key=DELETION_KEY,
            expires_at=int(time.time() * 1000) + 60_000,
        )
        self.assertTrue(result.created)
        method, path, headers, sent = Handler.requests[-1]
        self.assertEqual((method, path, sent), ("PUT", f"/api/messages/{MESSAGE_ID}", body))
        self.assertEqual(headers["X-Wipe-Client"], "mobile-ios")
        self.assertEqual(headers["X-Wipe-Content-Hash"], hashlib.sha256(body).hexdigest())
        self.assertNotIn("X-Wipe-On-Read", headers)

    def test_retrieve_returns_binary_metadata(self):
        headers = []
        result = self.client.retrieve(MESSAGE_ID, on_headers=headers.append)
        self.assertEqual(result.body, b"opaque\x00ciphertext")
        self.assertEqual(result.cipher_version, 1)
        self.assertEqual(result.content_hash, hashlib.sha256(result.body).hexdigest())
        self.assertEqual(headers[0]["contentHash"], result.content_hash)
        self.assertEqual(headers[0]["cipherVersion"], 1)

    def test_retrieve_rejects_content_hash_mismatch(self):
        with self.assertRaises(APIError) as caught:
            self.client.retrieve("2K7mQ2xR8VpC")
        self.assertEqual(caught.exception.code, "content_hash_mismatch")

    def test_upload_reports_actual_monotonic_bytes(self):
        events = []
        body = b"x" * 250_000
        self.client.create(MESSAGE_ID, body, deletion_key=DELETION_KEY,
                           expires_at=int(time.time() * 1000) + 60_000,
                           on_progress=events.append, progress_chunk_bytes=50_000)
        self.assertTrue(events)
        self.assertEqual(events[-1]["processedBytes"], len(body))
        self.assertEqual(events[-1]["percent"], 100)
        self.assertEqual([event["processedBytes"] for event in events], sorted(event["processedBytes"] for event in events))

    def test_delete_raises_typed_api_error(self):
        with self.assertRaises(APIError) as caught:
            self.client.delete(MESSAGE_ID, deletion_key=DELETION_KEY)
        self.assertEqual(caught.exception.status, 429)
        self.assertEqual(caught.exception.code, "message_rate_limited")
        self.assertEqual(caught.exception.message, "slow down")
        self.assertEqual(caught.exception.retry_after, 7.0)

    def test_health(self):
        self.assertEqual(self.client.health(), {"status": "ok"})

    def test_validates_free_tier_limits(self):
        with self.assertRaises(ValueError):
            self.client.create(
                MESSAGE_ID, b"x" * (3 * 1024 * 1024 + 1), deletion_key=DELETION_KEY,
                expires_at=int(time.time() * 1000) + 60_000,
            )
        with self.assertRaises(ValueError):
            self.client.create(
                MESSAGE_ID, b"x", deletion_key=DELETION_KEY,
                expires_at=int(time.time() * 1000) + 15 * 24 * 60 * 60 * 1000,
            )

    def test_extensible_client_identifier_validation(self):
        Client("http://example.invalid", client_id="mobile-android.v2")
        with self.assertRaises(ValueError):
            Client("http://example.invalid", client_id="Mobile Android")

    def test_limits_and_network_tests(self):
        self.assertEqual(self.client.limits()["limits"]["messageBytes"], 3145728)
        upload = self.client.test_upload_speed(bytes(32))
        self.assertEqual(upload.received_bytes, 32)
        self.assertGreater(upload.bytes_per_second, 0)
        download = self.client.test_download_speed(64)
        self.assertEqual(download.received_bytes, 64)
        self.assertEqual(len(download.data), 64)
        self.assertGreater(download.bytes_per_second, 0)
        with self.assertRaises(ValueError):
            self.client.test_download_speed(1048577)

    def test_performance_reports_are_validated_before_submission(self):
        report = {
            "schemaVersion": 1, "flow": "create", "result": "success",
            "encryptedBytes": 65536, "plaintextBytes": 64000,
            "estimated": {"encryptMs": 210, "uploadMs": 800, "totalMs": 1010},
            "actual": {"encryptMs": 225, "uploadMs": 920, "totalMs": 1145},
            "completedBytes": {"upload": 65536},
            "networkEstimate": {"uploadBytesPerSecond": 81920, "sampleAgeMs": 12000},
            "cryptoEstimate": {"encryptBytesPerSecond": 5000000, "sampleAgeMs": 60000},
            "estimateModel": "client-baseline-v1",
            "client": {"kind": "sdk-python", "version": "0.4.0", "platform": "server"},
        }
        self.assertTrue(self.client.submit_performance_report(report).accepted)
        with self.assertRaises(ValueError):
            self.client.submit_performance_report({**report, "messageId": MESSAGE_ID})


if __name__ == "__main__":
    unittest.main()
