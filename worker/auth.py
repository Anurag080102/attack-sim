# auth.py
import os
from datetime import datetime, timezone
from jose import jwt, JWTError

JWT_ALG = os.getenv("JWT_ALG", "HS256")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")

class TokenError(Exception): pass

def verify_consent_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except JWTError as e:
        raise TokenError(f"invalid token: {e}")

    # required claims we expect
    required = ["job_id", "target_ip", "allowed_plugins", "allowed_ports", "valid_from", "valid_until"]
    missing = [k for k in required if k not in payload]
    if missing:
        raise TokenError(f"missing claims: {missing}")

    # time window check (ISO 8601 strings)
    now = datetime.now(timezone.utc)
    vf = datetime.fromisoformat(payload["valid_from"].replace("Z", "+00:00"))
    vu = datetime.fromisoformat(payload["valid_until"].replace("Z", "+00:00"))
    if not (vf <= now <= vu):
        raise TokenError("token outside validity window")

    return payload
