from celery.result import AsyncResult
import logging

logger = logging.getLogger(__name__)


class StatusTracker:
    """Tracks the status of asynchronous Celery tasks."""

    @staticmethod
    def get_job_status(task_id: str) -> dict:
        """Get the current status of a Celery task.

        Args:
            task_id: The Celery task ID to query.

        Returns:
            Dictionary with task_id, status, result, and error fields.
        """
        result = AsyncResult(task_id)
        return {
            'task_id': task_id,
            'status': result.status,
            'result': result.result if result.status == 'SUCCESS' else None,
            'error': str(result.info) if result.status == 'FAILURE' else None,
        }
