from celery import Celery
from kombu import Queue, Exchange

app = Celery('psi')
app.conf.update(
    broker_url='redis://redis:6379/0',
    result_backend='redis://redis:6379/1',
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,
    task_soft_time_limit=25 * 60,
)

default_exchange = Exchange('psi', type='direct')

app.conf.task_queues = (
    Queue('nessus', exchange=default_exchange, routing_key='nessus'),
    Queue('openvas', exchange=default_exchange, routing_key='openvas'),
    Queue('default', exchange=default_exchange, routing_key='default'),
)

app.conf.task_routes = {
    'tasks.nessus_scan': {'queue': 'nessus'},
    'tasks.openvas_scan': {'queue': 'openvas'},
}
