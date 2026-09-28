"""Importing the Celery app here binds ``shared_task`` decorators to it whenever
Django starts, not only when a worker is launched.
"""

from .celery import app as celery_app

__all__ = ["celery_app"]
