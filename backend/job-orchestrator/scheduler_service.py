from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

scheduler = BackgroundScheduler()


def start_scheduler() -> None:
    """Start the background scheduler if not already running."""
    if not scheduler.running:
        scheduler.start()
        logger.info("Scheduler started")


def stop_scheduler() -> None:
    """Stop the background scheduler gracefully."""
    if scheduler.running:
        scheduler.shutdown()
        logger.info("Scheduler stopped")


def add_job(job_type: str, trigger: str, **kwargs) -> dict:
    """Schedule a new job.

    Args:
        job_type: Type identifier for the job.
        trigger: APScheduler trigger type (cron, interval, date).
        **kwargs: Additional trigger arguments.

    Returns:
        Dictionary with job_id and status.
    """
    job_id = f"{job_type}_{datetime.utcnow().timestamp()}"
    scheduler.add_job(
        func=execute_job,
        trigger=trigger,
        args=[job_type],
        id=job_id,
        replace_existing=False,
        **kwargs,
    )
    return {"job_id": job_id, "status": "scheduled"}


def execute_job(job_type: str) -> None:
    """Execute the appropriate Celery task for the given job type.

    Args:
        job_type: Type identifier for the job to execute.
    """
    logger.info(f"Executing job: {job_type}")
    from .tasks import nessus_scan, openvas_scan
    if job_type == "nessus":
        nessus_scan.delay(0, {})
    elif job_type == "openvas":
        openvas_scan.delay(0, {})
