from django.core.management.base import BaseCommand

from apps.monitoring.monitoring_service import run_due_scans


class Command(BaseCommand):
    help = "Run monitoring scans that are currently due. Invoke from cron when Celery beat is not enabled."

    def handle(self, *args, **options):
        count = run_due_scans()
        self.stdout.write(self.style.SUCCESS(f"Processed {count} monitoring configuration(s)."))
