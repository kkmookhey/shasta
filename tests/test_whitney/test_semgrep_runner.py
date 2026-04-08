"""Tests for the Semgrep runner module."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from whitney.code.semgrep_runner import (
    RULES_DIR,
    _parse_semgrep_json,
    run_semgrep,
    semgrep_available,
)
from shasta.evidence.models import Severity, ComplianceStatus, CheckDomain


# Sample Semgrep JSON output for testing the parser
SAMPLE_SEMGREP_JSON = json.dumps(
    {
        "version": "1.157.0",
        "results": [
            {
                "check_id": "src.whitney.code.rules.code-ai-api-key-exposed-openai",
                "path": "E:/test/app.py",
                "start": {"line": 5, "col": 1},
                "end": {"line": 5, "col": 45},
                "extra": {
                    "message": "OpenAI API key hardcoded in source code.",
                    "severity": "ERROR",
                    "metadata": {
                        "check_id": "code-ai-api-key-exposed",
                        "whitney_severity": "critical",
                        "soc2_controls": ["CC6.1"],
                        "remediation": "Move to environment variable.",
                    },
                    "lines": 'api_key = "sk-test1234567890abcdef"',
                },
            }
        ],
        "errors": [],
    }
)


class TestSemgrepAvailable:
    """Test semgrep CLI detection."""

    def test_semgrep_available_returns_bool(self):
        # Reset cache before testing
        import whitney.code.semgrep_runner as sr

        sr._SEMGREP_AVAILABLE = None
        result = semgrep_available()
        assert isinstance(result, bool)

    @patch("whitney.code.semgrep_runner.subprocess.run")
    def test_semgrep_unavailable_when_not_found(self, mock_run):
        import whitney.code.semgrep_runner as sr

        sr._SEMGREP_AVAILABLE = None
        mock_run.side_effect = FileNotFoundError("semgrep not found")
        assert semgrep_available() is False

    @patch("whitney.code.semgrep_runner.subprocess.run")
    def test_semgrep_available_when_present(self, mock_run):
        import whitney.code.semgrep_runner as sr

        sr._SEMGREP_AVAILABLE = None
        mock_run.return_value = MagicMock(returncode=0, stdout="1.157.0")
        assert semgrep_available() is True


class TestRunSemgrep:
    """Test the main run_semgrep function."""

    def test_returns_empty_when_semgrep_unavailable(self, tmp_path):
        with patch("whitney.code.semgrep_runner.semgrep_available", return_value=False):
            findings = run_semgrep(tmp_path)
            assert findings == []

    @patch("whitney.code.semgrep_runner.semgrep_available", return_value=True)
    @patch("whitney.code.semgrep_runner.subprocess.run")
    def test_handles_semgrep_error_gracefully(self, mock_run, _, tmp_path):
        mock_run.return_value = MagicMock(returncode=2, stderr="some error", stdout="")
        findings = run_semgrep(tmp_path)
        assert findings == []

    @patch("whitney.code.semgrep_runner.semgrep_available", return_value=True)
    @patch("whitney.code.semgrep_runner.subprocess.run")
    def test_handles_timeout_gracefully(self, mock_run, _, tmp_path):
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("semgrep", 300)
        findings = run_semgrep(tmp_path)
        assert findings == []

    @patch("whitney.code.semgrep_runner.semgrep_available", return_value=True)
    @patch("whitney.code.semgrep_runner.subprocess.run")
    def test_parses_findings_from_subprocess_output(self, mock_run, _, tmp_path):
        mock_run.return_value = MagicMock(
            returncode=1, stdout=SAMPLE_SEMGREP_JSON, stderr=""
        )
        findings = run_semgrep(tmp_path)
        assert len(findings) == 1
        assert findings[0].check_id == "code-ai-api-key-exposed"


class TestParseSemgrepJson:
    """Test JSON-to-Finding conversion."""

    def test_converts_basic_finding(self, tmp_path):
        findings = _parse_semgrep_json(SAMPLE_SEMGREP_JSON, tmp_path)
        assert len(findings) == 1
        f = findings[0]
        assert f.check_id == "code-ai-api-key-exposed"
        assert f.severity == Severity.CRITICAL
        assert f.status == ComplianceStatus.FAIL
        assert f.domain == CheckDomain.AI_GOVERNANCE
        assert "CC6.1" in f.soc2_controls
        assert f.remediation == "Move to environment variable."
        assert f.details["engine"] == "semgrep"
        assert "sk-test" in f.details["code_snippet"]

    def test_handles_empty_results(self, tmp_path):
        empty = json.dumps({"results": [], "errors": []})
        findings = _parse_semgrep_json(empty, tmp_path)
        assert findings == []

    def test_handles_invalid_json(self, tmp_path):
        findings = _parse_semgrep_json("not json", tmp_path)
        assert findings == []

    def test_uses_whitney_severity_metadata(self, tmp_path):
        data = json.dumps(
            {
                "results": [
                    {
                        "check_id": "test",
                        "path": "test.py",
                        "start": {"line": 1},
                        "extra": {
                            "message": "test",
                            "severity": "WARNING",  # Would normally map to HIGH
                            "metadata": {
                                "check_id": "code-test",
                                "whitney_severity": "low",  # Override
                            },
                        },
                    }
                ]
            }
        )
        findings = _parse_semgrep_json(data, tmp_path)
        assert findings[0].severity == Severity.LOW

    def test_falls_back_to_semgrep_severity(self, tmp_path):
        data = json.dumps(
            {
                "results": [
                    {
                        "check_id": "test",
                        "path": "test.py",
                        "start": {"line": 1},
                        "extra": {
                            "message": "test",
                            "severity": "ERROR",
                            "metadata": {"check_id": "code-test"},
                        },
                    }
                ]
            }
        )
        findings = _parse_semgrep_json(data, tmp_path)
        assert findings[0].severity == Severity.CRITICAL


class TestRulesDirectoryExists:
    """Verify the Semgrep rules directory is shipped with Whitney."""

    def test_rules_dir_exists(self):
        assert RULES_DIR.is_dir(), f"Rules directory missing: {RULES_DIR}"

    def test_rules_dir_has_yaml_files(self):
        yaml_files = list(RULES_DIR.glob("*.yaml"))
        assert len(yaml_files) >= 13, f"Expected at least 13 rule files, found {len(yaml_files)}"

    def test_each_rule_file_has_content(self):
        for yaml_file in RULES_DIR.glob("*.yaml"):
            content = yaml_file.read_text(encoding="utf-8")
            assert "rules:" in content, f"{yaml_file.name} missing 'rules:' key"
            assert "check_id:" in content, f"{yaml_file.name} missing check_id metadata"


@pytest.mark.skipif(not semgrep_available(), reason="semgrep not installed")
class TestSemgrepRulesAgainstFixtures:
    """Test that each Semgrep rule fires against known-vulnerable code."""

    def test_api_key_rule_catches_hardcoded_key(self, tmp_path):
        from tests.test_whitney.conftest import write_file

        write_file(tmp_path, "app.py", 'api_key = "sk-abcdef1234567890abcdefghij"\n')
        findings = run_semgrep(tmp_path)
        check_ids = {f.check_id for f in findings}
        assert "code-ai-api-key-exposed" in check_ids

    def test_model_versioning_rule_catches_unpinned(self, tmp_path):
        from tests.test_whitney.conftest import write_file

        write_file(tmp_path, "app.py", 'model = "gpt-4"\nx = client.chat.completions.create(model="gpt-4")\n')
        findings = run_semgrep(tmp_path)
        check_ids = {f.check_id for f in findings}
        assert "code-no-model-versioning" in check_ids

    def test_clean_code_produces_no_findings(self, tmp_path):
        from tests.test_whitney.conftest import write_file

        write_file(
            tmp_path,
            "app.py",
            'import os\napi_key = os.environ.get("OPENAI_API_KEY")\n',
        )
        findings = run_semgrep(tmp_path)
        # Clean code should produce no api-key findings
        api_key_findings = [f for f in findings if f.check_id == "code-ai-api-key-exposed"]
        assert len(api_key_findings) == 0
