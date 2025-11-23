# web_checks.py
import httpx
import ssl
from typing import Dict, Any, List

#    Perform a safe HTTP/HTTPS request to collect headers, cookies, and TLS info.
 #   Returns a dictionary of structured data or an error message.
async def fetch_http_info(url: str, timeout: float = 3.0) -> Dict[str, Any]:


    result = {
        "url": url,
        "ok": False,
        "status_code": None,
        "headers": {},
        "cookies": {},
        "tls": {},
        "error": None,
    }

    try:
        async with httpx.AsyncClient(verify=True, timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(url)

        # HTTP info
        result["ok"] = True
        result["status_code"] = resp.status_code
        result["headers"] = dict(resp.headers)
        result["cookies"] = dict(resp.cookies)

        # TLS info (only for https)
        if url.startswith("https://"):
            ssl_info = resp.extensions.get("tls_info")
            if ssl_info:
                result["tls"] = {
                    "version": ssl_info.version.name if hasattr(ssl_info.version, "name") else str(ssl_info.version),
                    "cipher": ssl_info.cipher.name if hasattr(ssl_info.cipher, "name") else str(ssl_info.cipher),
                }

    except Exception as e:
        result["error"] = str(e)

    return result


#     Convert discovery service hints to full URLs like 'http://ip:80' or 'https://ip:443'.

def determine_web_targets(target_ip: str, services: Dict[str, str]) -> List[str]:
    urls = []

    for port, hint in services.items():
        if hint == "http":
            urls.append(f"http://{target_ip}:{port}")
        elif hint == "https":
            urls.append(f"https://{target_ip}:{port}")

    return urls
