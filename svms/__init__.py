# svms/__init__.py
from __future__ import absolute_import, unicode_literals
# Import the celery app
from svms_project.celery import app as celery_app

__all__ = ('celery_app',)
