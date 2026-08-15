import unittest

from secure_panel.server import load_token


class ServerTests(unittest.TestCase):
    def test_rejects_short_token(self):
        with self.assertRaises(SystemExit):
            load_token("too-short")

    def test_accepts_strong_token(self):
        token = "a" * 32
        self.assertEqual(load_token(token), token)


if __name__ == "__main__":
    unittest.main()
