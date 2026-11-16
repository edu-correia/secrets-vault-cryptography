import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from src import cli
from src.vault import Vault


class TestPasswordFeedback(unittest.TestCase):
    def test_feedback_for_weak_and_generated_passwords(self):
        level, suggestions = Vault.check_password_strength("abc")
        self.assertEqual(level, "Muito fraca")
        self.assertIn("Prefira uma senha com pelo menos 12 caracteres.", suggestions)
        self.assertIn("Inclua números.", suggestions)
        self.assertEqual(
            Vault.check_password_strength(Vault.generate_secure_password()),
            ("Forte", []),
        )

    def test_feedback_allows_retry_before_accepting_password(self):
        weak = "abc"
        stronger = "N4!yWKq6vm9H$xBP"
        output = io.StringIO()
        with (
            patch("builtins.input", side_effect=["n", "t", "n", "s"]),
            patch.object(cli, "read_secret", side_effect=[weak, stronger]),
            redirect_stdout(output),
        ):
            self.assertEqual(cli.choose_password(), stronger)

        displayed = output.getvalue()
        self.assertIn("Força estimada: Muito fraca", displayed)
        self.assertIn("Inclua números.", displayed)
        self.assertIn("Força estimada: Forte", displayed)
        self.assertNotIn(weak, displayed)
        self.assertNotIn(stronger, displayed)
