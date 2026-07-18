import base64
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from wipeme import (AttachmentInput, ProtocolError, decrypt, deletion_key_header,
                    derive_deletion_key, encrypt, generate_message_id, generate_secret)


class CryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads((Path(__file__).parents[2] / "fixtures/v1/message-only.json").read_text())

    def test_matches_shared_vector(self):
        fixture = self.fixture
        repeated = lambda size: bytes([0x2A]) * size
        result = encrypt(
            fixture["message_id"], fixture["secret"], fixture["message"],
            _kdf=(fixture["kdf"]["memory_kib"], fixture["kdf"]["iterations"], fixture["kdf"]["parallelism"]),
            _random_bytes=repeated,
        )
        self.assertEqual(base64.b64encode(result.envelope).decode(), fixture["expected_envelope_base64"])
        opened = decrypt(result.envelope, fixture["message_id"], fixture["secret"])
        self.assertEqual(opened.manifest["message"], fixture["message"])

    def test_production_deletion_key(self):
        fixture = self.fixture
        key = derive_deletion_key(fixture["message_id"], fixture["secret"])
        self.assertEqual(deletion_key_header(key), fixture["expected_production_deletion_key_base64url"])

    def test_multichunk_attachment_progress_and_tamper(self):
        fixture = self.fixture
        data = b"x" * (128 * 1024 + 7)
        events = []
        random_values = iter([b"m" * 12, b"i" * 16, b"n" * 8])
        result = encrypt(fixture["message_id"], fixture["secret"], "files", [AttachmentInput(data, "x.bin")],
                         crypto_chunk_bytes=64 * 1024, on_progress=events.append,
                         _kdf=(64, 1, 1), _random_bytes=lambda size: next(random_values))
        opened = decrypt(result.envelope, fixture["message_id"], fixture["secret"], on_progress=events.append)
        self.assertEqual(opened.attachments[0].data, data)
        self.assertEqual(events[-1]["percent"], 100)
        damaged = bytearray(result.envelope); damaged[-2] ^= 1
        with self.assertRaises(ProtocolError):
            decrypt(bytes(damaged), fixture["message_id"], fixture["secret"])

    def test_generates_canonical_capabilities(self):
        self.assertEqual(len(generate_message_id()), 12)
        self.assertEqual(len(generate_secret()), 16)


if __name__ == "__main__":
    unittest.main()
