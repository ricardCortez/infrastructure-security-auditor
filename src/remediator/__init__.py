"""Remediator package – automated remediation playbook generation (Phase 2).

Will auto-generate PowerShell and Ansible remediation scripts directly
from Analyzer findings, enabling one-click remediation of detected
misconfigurations. Currently a stub — reserved for Phase 2.

Classes:
    PlaybookGenerator: Generates PowerShell / Ansible playbooks (stub).
"""

from src.remediator.playbook_gen import PlaybookGenerator

__all__ = ["PlaybookGenerator"]
