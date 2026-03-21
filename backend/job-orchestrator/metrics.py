from prometheus_client import Counter, Histogram

job_counter = Counter(
    'psi_jobs_total',
    'Total jobs executed',
    ['job_type', 'status'],
)

job_duration = Histogram(
    'psi_job_duration_seconds',
    'Job duration in seconds',
    ['job_type'],
)
