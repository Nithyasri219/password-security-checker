import unittest

from password_checker import password_strength


class PasswordStrengthTests(unittest.TestCase):
    def test_empty_password_is_weak(self):
        result = password_strength("")
        self.assertEqual(result["label"], "Weak")

    def test_common_password_is_penalized(self):
        result = password_strength("password")
        self.assertIn("Replace this commonly used password.", result["tips"])

    def test_strong_unique_password(self):
        result = password_strength("Mango!River-73@Lap")
        self.assertGreaterEqual(result["score"], 8)


if __name__ == "__main__":
    unittest.main()
