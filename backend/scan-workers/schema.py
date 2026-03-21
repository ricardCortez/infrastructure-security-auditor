from dataclasses import dataclass
from typing import Optional
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    asset_id: int
    title: str
    severity: Severity
    cvss_score: Optional[float] = None
    cwe: Optional[str] = None
    description: Optional[str] = None
    remediation: Optional[str] = None
    plugin_id: Optional[str] = None
    source: str = "unknown"
