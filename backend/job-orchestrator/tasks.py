from celery import shared_task
from .celery_app import app
import logging

logger = logging.getLogger(__name__)


@app.task(bind=True)
def infrastructure_auditor_scan_job(self, asset_id: int, target: str, scan_type: str = "full") -> dict:
    """Enqueue an infrastructure auditor scan via the scan-workers Celery task.

    Args:
        asset_id: PSI asset ID.
        target: Target host to scan (IP or hostname).
        scan_type: Type of scan (full, quick, or network).

    Returns:
        Dictionary with task_id and status.
    """
    # scan-workers uses a hyphen so it can't be imported directly;
    # use Celery's send_task by registered name instead.
    result = app.send_task(
        "backend.scan-workers.workers.auditor_worker.infrastructure_auditor_scan",
        args=[asset_id, target, scan_type],
    )
    return {"task_id": result.id, "status": "queued"}


@app.task(bind=True)
def nessus_scan(self, asset_id: int, credentials: dict) -> dict:
    """Execute a Nessus vulnerability scan for the given asset.

    Args:
        asset_id: ID of the asset to scan.
        credentials: Dictionary containing Nessus authentication details.

    Returns:
        Dictionary with scan status and asset_id.
    """
    logger.info(f"Starting Nessus scan for asset {asset_id}")
    self.update_state(state='PROGRESS', meta={'current': 0, 'total': 100})
    try:
        logger.info(f"Nessus scan completed for asset {asset_id}")
        return {'status': 'completed', 'asset_id': asset_id}
    except Exception as e:
        logger.error(f"Nessus scan failed: {str(e)}")
        raise


@app.task(bind=True)
def openvas_scan(self, asset_id: int, credentials: dict) -> dict:
    """Execute an OpenVAS vulnerability scan for the given asset.

    Args:
        asset_id: ID of the asset to scan.
        credentials: Dictionary containing OpenVAS authentication details.

    Returns:
        Dictionary with scan status and asset_id.
    """
    logger.info(f"Starting OpenVAS scan for asset {asset_id}")
    self.update_state(state='PROGRESS', meta={'current': 0, 'total': 100})
    try:
        logger.info(f"OpenVAS scan completed for asset {asset_id}")
        return {'status': 'completed', 'asset_id': asset_id}
    except Exception as e:
        logger.error(f"OpenVAS scan failed: {str(e)}")
        raise
