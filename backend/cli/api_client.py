"""Local SQLite-backed API client — no server or Docker required."""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from . import local_db as db


class LocalResponse:
    """Thin wrapper that mimics requests.Response so command code is unchanged."""

    def __init__(self, status_code: int, data: Any = None, text: str = "") -> None:
        self.status_code = status_code
        self._data = data
        self.text = text or str(data or "")

    def json(self) -> Any:  # noqa: D102
        return self._data


# Endpoint → table name (None = special handler)
_REPORT_DIR: Path = Path.home() / ".psi" / "reports"

# Endpoint → table name (None = special handler)
_ROUTES: Dict[str, Optional[str]] = {
    r"^/assets$":            "assets",
    r"^/assets/(\d+)$":     "assets",
    r"^/findings$":          "findings",
    r"^/findings/(\d+)$":   "findings",
    r"^/jobs$":              "scan_jobs",
    r"^/jobs/(\d+)$":       "scan_jobs",
    r"^/reports$":           "reports",
    r"^/reports/generate$": None,
}


def _resolve(endpoint: str):
    """Return (table, row_id) for *endpoint*, or (None, None) if unrecognised."""
    for pattern, table in _ROUTES.items():
        m = re.match(pattern, endpoint)
        if m:
            row_id = int(m.group(1)) if m.lastindex else None
            return table, row_id
    return None, None


class LocalAPIClient:
    """CRUD client backed by local SQLite.

    Implements the same .get/.post/.put/.delete interface as the original
    HTTP APIClient so that all command modules work without modification.
    """

    # ── read ──────────────────────────────────────────────────────────

    def get(self, endpoint: str, params: Optional[Dict] = None, **_) -> LocalResponse:
        """Fetch one or many rows depending on whether an ID is in the endpoint."""
        table, row_id = _resolve(endpoint)
        if table is None:
            return LocalResponse(404, {"detail": "Not found"})

        if row_id is not None:
            row = db.get_by_id(table, row_id)
            return (LocalResponse(200, row)
                    if row else LocalResponse(404, {"detail": f"ID {row_id} not found"}))

        # Apply any query-string filters (e.g. severity=CRITICAL)
        filters = {k: v for k, v in (params or {}).items() if v is not None} or None
        return LocalResponse(200, db.get_all(table, filters))

    # ── write ─────────────────────────────────────────────────────────

    def post(self, endpoint: str, json: Optional[Dict] = None, **_) -> LocalResponse:
        """Insert a new row, or trigger special logic for /reports/generate."""
        if endpoint == "/reports/generate":
            return self._generate_report(json or {})

        table, _ = _resolve(endpoint)
        if table is None:
            return LocalResponse(404)

        row = db.insert(table, json or {})
        return LocalResponse(201, row)

    def put(self, endpoint: str, json: Optional[Dict] = None, **_) -> LocalResponse:
        """Update an existing row."""
        table, row_id = _resolve(endpoint)
        if table is None or row_id is None:
            return LocalResponse(404)
        row = db.update(table, row_id, json or {})
        return LocalResponse(200 if row else 404, row)

    def delete(self, endpoint: str, **_) -> LocalResponse:
        """Delete a row."""
        table, row_id = _resolve(endpoint)
        if table is None or row_id is None:
            return LocalResponse(404)
        ok = db.delete_by_id(table, row_id)
        return LocalResponse(200 if ok else 404, {"deleted": ok})

    # ── report generation ─────────────────────────────────────────────

    def _generate_report(self, options: Dict) -> LocalResponse:
        """Save findings to ~/.psi/reports/ and return metadata."""
        findings = db.get_all("findings")
        fmt = options.get("format", "json")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        report_dir = _REPORT_DIR
        report_dir.mkdir(parents=True, exist_ok=True)
        path = report_dir / f"psi_report_{ts}.{fmt}"

        if fmt == "json":
            path.write_text(json.dumps(findings, indent=2, default=str))
        else:
            lines = [
                f"PSI Security Report — {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                f"Total findings: {len(findings)}",
                "",
            ]
            for f in findings:
                lines.append(
                    f"  [{f.get('severity','?'):8}] {f.get('title','?')}"
                    f"  |  Asset {f.get('asset_id','?')}"
                    f"  |  {f.get('status','?')}"
                )
            actual_path = path.with_suffix(".txt")
            actual_path.write_text("\n".join(lines))
            path = actual_path

        record = db.insert("reports", {
            "format": fmt,
            "path": str(path),
            "findings_count": len(findings),
        })
        return LocalResponse(200, {
            "status": "generated",
            "path": str(path),
            "id": record["id"],
            "findings_count": len(findings),
        })


api = LocalAPIClient()
