# celery_app.py
import os
from celery import Celery

# isolated broker on port 6381
BROKER_URL = os.getenv("BROKER_URL", "redis://localhost:6379/0")

celery_app = Celery("attack_sim_worker", broker=BROKER_URL, include=["tasks"], )

# optional queue name to keep things separate even if broker is shared later
celery_app.conf.task_default_queue = os.getenv("CELERY_QUEUE", "attack_sim")
