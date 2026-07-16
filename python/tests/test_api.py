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
        elif self.path.endswith("/missing"):
            body = b'{"error":"gone","code":"message_not_found"}'
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
        else:
            body = b"opaque\x00ciphertext"
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("X-Wipe-Content-Hash", hashlib.sha256(body).hexdigest())
            self.send_header("X-Wipe-Cipher-Version", "1")
        self.end_headers()
        self.wfile.write(body)

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
        result = self.client.retrieve(MESSAGE_ID)
        self.assertEqual(result.body, b"opaque\x00ciphertext")
        self.assertEqual(result.cipher_version, 1)
        self.assertEqual(result.content_hash, hashlib.sha256(result.body).hexdigest())

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


if __name__ == "__main__":
    unittest.main()
