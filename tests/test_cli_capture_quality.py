import unittest
from contextlib import redirect_stdout
from io import StringIO
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mimic.cli import cmd_gen, cmd_learn


class CaptureQualityCliTests(unittest.TestCase):
    @patch("mimic.cli.mitm.endpoints")
    @patch("mimic.cli._mitm_and_flows")
    def test_learn_is_metadata_only(self, load, endpoints):
        load.return_value = (Mock(), [{"id": "one"}])
        endpoints.return_value = [
            {
                "method": "GET",
                "path": "/users/{user_id}",
                "status": 200,
                "sample_count": 2,
            }
        ]
        args = SimpleNamespace(host="api.example.com", include_telemetry=True)

        with redirect_stdout(StringIO()) as output:
            cmd_learn(args)

        endpoints.assert_called_once_with(
            load.return_value[0],
            load.return_value[1],
            "api.example.com",
            include_bodies=False,
            include_telemetry=True,
        )
        self.assertIn("2 samples", output.getvalue())

    @patch("mimic.cli.codegen.build_prompt", return_value="bounded prompt")
    @patch("mimic.cli.mitm.endpoints")
    @patch("mimic.cli._mitm_and_flows")
    def test_gen_propagates_telemetry_override(self, load, endpoints, build_prompt):
        load.return_value = (Mock(), [{"id": "one"}])
        endpoints.return_value = [{"method": "GET", "path": "/users"}]
        args = SimpleNamespace(
            host="api.example.com",
            include_telemetry=True,
            prompt_only=True,
            out=None,
            model="sonnet",
            generator="claude",
        )

        with redirect_stdout(StringIO()) as output:
            cmd_gen(args)

        endpoints.assert_called_once_with(
            load.return_value[0],
            load.return_value[1],
            "api.example.com",
            include_telemetry=True,
        )
        build_prompt.assert_called_once_with("api.example.com", endpoints.return_value)
        self.assertIn("bounded prompt", output.getvalue())


if __name__ == "__main__":
    unittest.main()
