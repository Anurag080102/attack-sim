import importlib
import os
import traceback
from typing import List, Dict, Any
import sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))



PLUGIN_FOLDER = os.path.join(os.path.dirname(__file__), "plugins")


def load_plugins() -> List:

    plugins = []

    for filename in os.listdir(PLUGIN_FOLDER):
        if not filename.endswith(".py") or filename == "__init__.py":
            continue

        module_name = f"worker.plugins.{filename[:-3]}"

        try:
            module = importlib.import_module(module_name)
            if hasattr(module, "run"):
                plugins.append(module)
            else:
                print(f"[worker] plugin {filename} has no run() function, skipping")
        except Exception as e:
            print(f"[worker] error loading plugin {filename}: {e}")
            traceback.print_exc()

    print(f"[worker] loaded plugins: {[p.__name__ for p in plugins]}")
    return plugins



def run_plugins(plugins: List, target_ip: str, discovery: Dict, web: List) -> List[Dict[str, Any]]:

    findings = []

    for plugin in plugins:
        try:
            result = plugin.run(target_ip, discovery, web)
            if result:
                findings.append(result)
        except Exception as e:
            findings.append({
                "plugin": plugin.__name__,
                "severity": "Error",
                "description": f"Plugin crashed: {e}",
            })
            traceback.print_exc()

    return findings
