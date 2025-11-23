# test_header_plugin.py
def run(target_ip, discovery, web_checks):
    """
    Simple test plugin:
    - If any HTTP service exists and returns a Server header,
      report it as an informational finding.
    """
    if not web_checks:
        return {
            "plugin": "test_header_plugin",
            "severity": "Info",
            "description": "No web services found to test",
        }

    first = web_checks[0]
    server_header = first["headers"].get("server", "unknown")

    return {
        "plugin": "test_header_plugin",
        "severity": "Low",
        "description": f"Server header identified: {server_header}",
        "evidence": {
            "url": first["url"],
            "server": server_header,
        }
    }
