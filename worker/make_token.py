# make_token.py
import os
from datetime import datetime, timedelta, timezone
from jose import jwt

JWT_ALG = os.getenv("JWT_ALG", "HS256")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")

def make():
    now = datetime.now(timezone.utc)
    payload = {
        "job_id": "job-allow-1",
        "target_ip": "127.0.0.1",
        "allowed_plugins": ["discovery","headers_tls"],
        "allowed_ports": [8080],
        "valid_from": (now - timedelta(minutes=5)).isoformat(),
        "valid_until": (now + timedelta(hours=1)).isoformat(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

if __name__ == "__main__":
    print(make())
