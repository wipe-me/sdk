import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from wipeme import format_private_link, normalize_base58, parse_private_link


class LinkTests(unittest.TestCase):
    def test_normalizes_separators(self):
        self.assertEqual(normalize_base58("1K7m-Q2xR 8VpC", 12), "1K7mQ2xR8VpC")

    def test_rejects_ambiguous_character(self):
        with self.assertRaises(ValueError):
            normalize_base58("0K7mQ2xR8VpC", 12)

    def test_round_trip(self):
        link = format_private_link("https://wipe.me", "1K7mQ2xR8VpC", "7YWHMfk9JCB7P4eG")
        self.assertEqual(link, "https://wipe.me/1K7m-Q2xR-8VpC#7YWH-Mfk9-JCB7-P4eG")
        self.assertEqual(parse_private_link(link), ("1K7mQ2xR8VpC", "7YWHMfk9JCB7P4eG"))


if __name__ == "__main__":
    unittest.main()
