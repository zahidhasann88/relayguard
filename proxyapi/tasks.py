"""Celery tasks: request-log persistence and scheduled retention."""

import logging
from datetime import timedelta

from celery import shared_task
from django.conf import settings
from django.db import DatabaseError
from django.utils import timezone

from .models import RequestLog
from .request_log import write_request_log

logger = logging.getLogger(__name__)

# One unbounded DELETE over months of traffic holds a long transaction and a lot
# of locks; batching keeps each statement short.
PURGE_BATCH_SIZE = 5000


@shared_task(
    name="proxyapi.tasks.persist_request_log",
    ignore_result=True,
    # Only transient database problems are worth retrying; a bad-data error would
    # just be repeated three times with backoff in between.
    autoretry_for=(DatabaseError,),
    retry_backoff=True,
    max_retries=3,
)
def persist_request_log(api_key_id, endpoint, method, status, latency_ms, ip):
    write_request_log(api_key_id, endpoint, method, status, latency_ms, ip)


@shared_task(name="proxyapi.tasks.purge_old_request_logs")
def purge_old_request_logs(days: int | None = None) -> int:
    """Delete request logs older than ``days`` and return how many were removed."""
    if days is None:
        days = settings.REQUEST_LOG_RETENTION_DAYS
    cutoff = timezone.now() - timedelta(days=days)

    total = 0
    while True:
        batch = list(RequestLog.objects.filter(timestamp__lt=cutoff).values_list("pk", flat=True)[:PURGE_BATCH_SIZE])
        if not batch:
            break
        deleted, _ = RequestLog.objects.filter(pk__in=batch).delete()
        total += deleted
        if len(batch) < PURGE_BATCH_SIZE:
            break

    if total:
        logger.info("Purged %s request logs older than %s days", total, days)
    return total
