from celery import shared_task


@shared_task
def run_due_scans_task():
    from .monitoring_service import run_due_scans
    return run_due_scans()
