# tasks.py
from celery_app import celery_app
from auth import verify_consent_token, TokenError
from discovery import run_discovery
from web_checks import fetch_http_info, determine_web_targets
from plugin_loader import load_plugins, run_plugins

import asyncio
import json

DEFAULT_PORTS = [22, 80, 443, 8080]


@celery_app.task(name="scan.run")
def run_scan(job_id: str, consent_token: str):
    # 1) token verification
    try:
        claims = verify_consent_token(consent_token)
    except TokenError as e:
        print(f"[worker] DENY job={job_id}: {e}")
        return {"ok": False, "job_id": job_id, "reason": str(e)}

    if claims.get("job_id") != job_id:
        print(f"[worker] DENY job={job_id}: job_id mismatch {claims.get('job_id')}")
        return {"ok": False, "job_id": job_id, "reason": "job_id mismatch"}

    print(f"[worker] ALLOW job={job_id} target={claims['target_ip']}")

    # 2) determine ports to scan
    allowed_ports = claims.get("allowed_ports") or DEFAULT_PORTS
    ports = [int(p) for p in allowed_ports]

    # 3) discovery phase
    try:
        discovery_result = run_discovery(
            claims["target_ip"], ports=ports, concurrency=20, timeout=0.8
        )
    except Exception as e:
        print(f"[worker] ERROR discovery job={job_id}: {e}")
        return {"ok": False, "job_id": job_id, "reason": f"discovery error: {e}"}

    # 4) web checks phase
    web_urls = determine_web_targets(claims["target_ip"], discovery_result["services"])
    web_results = []

    if web_urls:
        print(f"[worker] starting web checks for: {web_urls}")
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            tasks = [fetch_http_info(url) for url in web_urls]
            web_results = loop.run_until_complete(asyncio.gather(*tasks))
        except Exception as e:
            print(f"[worker] ERROR web checks job={job_id}: {e}")
        finally:
            loop.close()
    else:
        print("[worker] no web services discovered; skipping web checks")

    # 5) plugin phase
    plugins = load_plugins()
    plugin_findings = run_plugins(
        plugins,
        claims["target_ip"],
        discovery_result,
        web_results
    )

    # 6) prepare final result
    final_payload = {
        "ok": True,
        "job_id": claims["job_id"],
        "target_ip": claims["target_ip"],
        "discovery": discovery_result,
        "web_checks": web_results,
        "findings": plugin_findings,
    }

    print("[worker] FINAL RESULTS:", json.dumps(final_payload, indent=2))
    return final_payload
