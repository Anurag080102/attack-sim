from celery_app import celery_app
from make_token import make

job_id = "job-allow-1"
token = make()

r = celery_app.send_task("scan.run", args=[job_id, token], queue="attack_sim")
print("queued:", r.id)

