"""CLI discovery, installed metadata and stable export contracts."""
import ast
import contextlib
import importlib
import importlib.metadata
import io
import json
from pathlib import Path
import re
import unittest
from unittest.mock import patch

import access_graph
import access_snapshot
import json_output
import permissionhell as ph
import policy_drift


ROOT = Path(__file__).resolve().parents[1]
COMMANDS = ("diagnose", "audit", "process", "audit-processes", "graph", "policy-check",
            "snapshot", "diff", "monitor-init", "monitor-check")


class CliReleaseTests(unittest.TestCase):
    def output(self, args, code=0):
        with contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(SystemExit) as result:
            ph.main(args)
        self.assertEqual(result.exception.code, code)
        return output.getvalue()

    def test_all_commands_discoverable(self):
        text = self.output(["--help"])
        for command in COMMANDS:
            self.assertIn(command, text)

    def test_every_subcommand_help_has_example(self):
        for command in COMMANDS:
            with self.subTest(command=command):
                text = self.output([command, "--help"])
                self.assertIn("Example: permissionhell", text)
                self.assertIn(command, text)
                self.assertLess(len(text), 4000)

    def test_version_is_canonical(self):
        self.assertEqual(self.output(["--version"]).strip(), f"permissionhell {ph.__version__}")
        self.assertEqual(ph.__version__, "1.7.0")

    def test_unknown_command(self):
        self.output(["not-a-command"], 2)

    def test_missing_required_arguments(self):
        for command in COMMANDS:
            with self.subTest(command=command):
                self.output([command], 2)

    def test_help_does_not_inspect_linux(self):
        with patch.object(ph, "diagnose", side_effect=AssertionError("inspection")), \
                patch.object(ph, "inspect_process", side_effect=AssertionError("inspection")):
            for command in COMMANDS:
                self.output([command, "--help"])

    def test_invalid_saved_inputs_json(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            path.write_text("{bad")
            for command in (["policy-check", str(path), "--json"], ["diff", str(path), str(path), "--json"]):
                with self.subTest(command=command), patch.object(ph.sys, "platform", "linux"), contextlib.redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(ph.main(command), 2)
                self.assertEqual(json.loads(out.getvalue())["exit_code"], 2)


class PackageReleaseTests(unittest.TestCase):
    def distribution(self):
        try:
            return importlib.metadata.distribution("permissionhell")
        except importlib.metadata.PackageNotFoundError:
            self.skipTest("Install .[dev] or run the release checker to verify installed metadata")

    def test_installed_metadata_version(self):
        self.assertEqual(self.distribution().version, ph.__version__)

    def test_console_entry_point(self):
        entry = next(e for e in self.distribution().entry_points if e.name == "permissionhell")
        self.assertEqual(entry.group, "console_scripts")
        self.assertEqual(entry.value, "permissionhell:main")
        self.assertIs(entry.load(), ph.main)

    def test_every_packaged_module_importable(self):
        project = (ROOT / "pyproject.toml").read_text()
        modules = ast.literal_eval(re.search(r"py-modules = (\[[^\n]+\])", project)[1])
        for module in modules:
            with self.subTest(module=module):
                self.assertIsNotNone(importlib.import_module(module))

    def test_no_runtime_dependencies(self):
        requirements = self.distribution().requires or []
        self.assertTrue(all("extra ==" in requirement for requirement in requirements), requirements)

    def test_supported_python_metadata(self):
        self.assertEqual(self.distribution().metadata["Requires-Python"], ">=3.10")

    def test_stable_schema_versions(self):
        self.assertEqual(json_output.SCHEMA_VERSION, "1")
        self.assertEqual(access_graph.GRAPH_VERSION, "1")
        self.assertEqual(access_snapshot.SNAPSHOT_VERSION, 1)
        policy = policy_drift.parse_policy(json.dumps({"policy_version": 1, "resources": [
            {"path": "/file", "checks": [{"mode": "r", "accounts": {"allow": ["alice"]}}]}]}))
        self.assertEqual(policy.policy_version, 1)

    def test_schema_document_identifies_versions(self):
        text = (ROOT / "docs/schemas.md").read_text()
        for field in ("schema_version", "graph_version", "snapshot_version", "policy_version"):
            self.assertIn(field, text)
        self.assertIn('string "1"', text)
        self.assertIn("integer 1", text)


if __name__ == "__main__":
    unittest.main()
