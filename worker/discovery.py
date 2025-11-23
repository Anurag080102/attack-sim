# discovery.py
import asyncio
import socket
from typing import List, Dict, Any

DEFAULT_PORTS = [22, 80, 443, 8080]

async def _tcp_probe(ip: str, port: int, timeout: float) -> Dict[str, Any]:
    """
    Try to open a TCP connection, perform a light banner grab (non-blocking).
    Returns a dict with keys: port, open (bool), banner (str or None), service_hint (http|https|unknown).
    """
    info = {"port": port, "open": False, "banner": None, "service_hint": "unknown"}
    try:
        # open connection with timeout
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        info["open"] = True

        # Try a safe banner probe: send a minimal HTTP HEAD request (some servers reply to any bytes)
        try:
            probe = b"HEAD / HTTP/1.0\r\n\r\n"
            writer.write(probe)
            await writer.drain()
            # read small amount to avoid blocking
            data = await asyncio.wait_for(reader.read(256), timeout=timeout)
            if data:
                text = data.decode(errors="ignore")
                info["banner"] = text.splitlines()[0] if text else None
                # crude detection of http/https by typical response or by port
                if "HTTP/" in text or "Server:" in text or "Content-Type" in text:
                    info["service_hint"] = "http"
        except Exception:
            # even if banner probe fails, we'll still try to get peername or leave banner None
            pass

        # Heuristic: if port is 443 and we didn't detect HTTP text, hint https
        if info["service_hint"] == "unknown" and port == 443:
            info["service_hint"] = "https"

        # close connection
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        # closed or filtered
        pass
    except Exception:
        # unexpected: log upstream
        pass

    return info


async def _run_ports(ip: str, ports: List[int], concurrency: int, timeout: float) -> List[Dict[str, Any]]:
    sem = asyncio.Semaphore(concurrency)
    results = []

    async def _worker(p):
        async with sem:
            return await _tcp_probe(ip, p, timeout)

    tasks = [asyncio.create_task(_worker(p)) for p in ports]
    for t in asyncio.as_completed(tasks):
        try:
            r = await t
            results.append(r)
        except Exception:
            # keep going on errors
            pass
    return results


def run_discovery(ip: str, ports: List[int] = None, concurrency: int = 50, timeout: float = 0.8) -> Dict[str, Any]:
    """
    Synchronous wrapper to run the async scan from sync code (like Celery).
    - ip: target IP or hostname (worker should validate)
    - ports: list of integer ports (if None, uses DEFAULT_PORTS)
    - concurrency: max concurrent connections
    - timeout: seconds per connection/banners read (e.g., 0.8s)
    Returns a summary dict.
    """
    if ports is None:
        ports = DEFAULT_PORTS
    # ensure ports are ints & unique
    ports = sorted({int(p) for p in ports})

    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        res = loop.run_until_complete(_run_ports(ip, ports, concurrency, timeout))
    finally:
        try:
            loop.close()
        except Exception:
            pass

    open_ports = []
    services = {}
    banners = {}
    for r in res:
        if r.get("open"):
            p = r["port"]
            open_ports.append(p)
            hint = r.get("service_hint") or "unknown"
            services[str(p)] = hint
            if r.get("banner"):
                banners[str(p)] = r["banner"]

    return {
        "target": ip,
        "open_ports": sorted(open_ports),
        "services": services,
        "banners": banners,
        "metrics": {"scanned_ports": len(ports)}
    }
