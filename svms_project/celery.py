# svms_project/celery.py
import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'svms_project.settings')

app = Celery('svms_project')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()
