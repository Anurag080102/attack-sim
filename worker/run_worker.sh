#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
source .venv/bin/activate
export BROKER_URL=redis://localhost:6381/0
export CELERY_QUEUE=attack_sim
export JWT_SECRET=${JWT_SECRET:-dev-secret-change-me}
export PYTHONPATH=$(pwd)
exec celery -A celery_app.celery_app worker --loglevel=INFO --queues "$CELERY_QUEUE"
