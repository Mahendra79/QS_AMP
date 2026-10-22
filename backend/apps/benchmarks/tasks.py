from celery import shared_task


@shared_task
def execute_run_task(run_id, force_demo=False):
    from .benchmark_service import execute_run
    execute_run(run_id, force_demo)
