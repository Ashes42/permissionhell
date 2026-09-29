"""Every public version label follows the package metadata source."""

import contextlib
import io
import pathlib
import unittest
from unittest.mock import patch

import permissionhell as ph
from test_audit_rendering import account_result, ordinary_accounts, report_for


class VersionDisplayTests(unittest.TestCase):
    def setUp(self):
        self.result = account_result(ordinary_accounts(1)[0])

    def headings(self):
        diagnosis = self.result.diagnosis
        return [ph.render_audit_explanation(ph.AuditExplanation(diagnosis)),
                ph.render_audit(report_for([self.result])),
                ph.render_report(diagnosis), ph.render_verbose_report(diagnosis)]

    def test_explain_current_release(self):
        self.assertEqual(self.headings()[0].splitlines()[0], "PERMISSION HELL v0.8 | AUDIT EXPLAIN")

    def test_normal_audit_current_release(self):
        self.assertEqual(self.headings()[1].splitlines()[0], "PERMISSION HELL v0.8 | ACCESS AUDIT")

    def test_diagnose_current_release(self):
        self.assertTrue(self.headings()[2].startswith("PERMISSION HELL v0.8 | READ"))
        self.assertEqual(self.headings()[3].splitlines()[0], "PERMISSION HELL v0.8")

    def test_cli_and_renderers_follow_canonical_version(self):
        for version, label in (("0.5.0", "v0.5"), ("1.2.0", "v1.2"), ("1.2.3", "v1.2.3")):
            with self.subTest(version=version), patch.object(ph, "__version__", version):
                with contextlib.redirect_stdout(io.StringIO()) as output, self.assertRaises(SystemExit) as exit:
                    ph.main(["--version"])
                self.assertEqual(exit.exception.code, 0)
                self.assertEqual(output.getvalue().strip(), f"permissionhell {version}")
                for report in self.headings():
                    self.assertTrue(report.startswith(f"PERMISSION HELL {label}"))
                self.assertIn(f"({label} DAC + ACL + mount model)", self.headings()[3])

    def test_package_metadata_uses_canonical_attribute(self):
        # The project supports Python 3.10, so avoid requiring tomllib for tests.
        project = pathlib.Path(ph.__file__).with_name("pyproject.toml").read_text()
        self.assertIn('dynamic = ["version"]', project)
        self.assertIn('[tool.setuptools.dynamic]\nversion = {attr = "permissionhell.__version__"}', project)
