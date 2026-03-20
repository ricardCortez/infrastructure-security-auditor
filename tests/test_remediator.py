"""Tests for PlaybookGenerator (Phase 2 stub).

These tests cover the stub implementation to satisfy coverage requirements.
The actual functionality is reserved for Phase 2.
"""

from __future__ import annotations

import pytest

from src.remediator.playbook_gen import PlaybookGenerator


class TestPlaybookGenerator:

    def test_instantiation_stores_findings(self) -> None:
        findings = [{"check": "Test", "status": "FAIL"}]
        gen = PlaybookGenerator(findings)
        assert gen.findings is findings

    def test_instantiation_with_empty_findings(self) -> None:
        gen = PlaybookGenerator([])
        assert gen.findings == []

    def test_generate_powershell_raises_not_implemented(self) -> None:
        gen = PlaybookGenerator([])
        with pytest.raises(NotImplementedError, match="Phase 2"):
            gen.generate_powershell()

    def test_generate_ansible_raises_not_implemented(self) -> None:
        gen = PlaybookGenerator([])
        with pytest.raises(NotImplementedError, match="Phase 2"):
            gen.generate_ansible()

    def test_generate_powershell_message_contains_phase_2(self) -> None:
        gen = PlaybookGenerator([{"check": "SMBv1 Protocol", "status": "FAIL"}])
        with pytest.raises(NotImplementedError) as exc_info:
            gen.generate_powershell()
        assert "Phase 2" in str(exc_info.value)

    def test_generate_ansible_message_contains_phase_2(self) -> None:
        gen = PlaybookGenerator([{"check": "Firewall Status", "status": "FAIL"}])
        with pytest.raises(NotImplementedError) as exc_info:
            gen.generate_ansible()
        assert "Phase 2" in str(exc_info.value)
