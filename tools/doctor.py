"""Non-mutating environment diagnostics; never print credentials or proxy values."""
import importlib.util
import platform
import shutil
import time
import urllib.request
from .runtime import redact


def diagnose(network=False):
    result = dict(system=platform.system(),architecture=platform.machine(),
                  tools={t:bool(shutil.which(t)) for t in ("git","java","mvn")},
                  optional_python_packages={t:importlib.util.find_spec(t) is not None for t in ("tree_sitter","tree_sitter_java","pip")})
    if network:
        checks = []
        for url in ("https://repo.maven.apache.org/maven2/", "https://repo.jenkins-ci.org/public/", "https://raw.githubusercontent.com/iris-sast/iris/d2059f299a80a68ea4a0b0315eec2f42b8743776/data/project_info.csv"):
            start = time.perf_counter()
            item = dict(url=url)
            try:
                with urllib.request.urlopen(url,timeout=15) as response:
                    item.update(status=response.status,bytes_prefix=len(response.read(1024)))
            except Exception as exc:
                item.update(error=redact(exc),error_type=type(exc).__name__)
            item["seconds"] = round(time.perf_counter()-start,3)
            checks.append(item)
        result["network"] = checks
    return result
