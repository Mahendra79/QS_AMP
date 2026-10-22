from celery import shared_task


@shared_task
def run_scan_task(job_id):
    from .discovery_service import run_scan
    run_scan(job_id)
