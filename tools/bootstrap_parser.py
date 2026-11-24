"""Install optional parser wheels into a private cache without changing system Python.

Uses only wheels compatible with the running CPython and verifies PyPI SHA256.
No package installation scripts or shell commands are executed.
"""
import hashlib
import io
import json
from pathlib import Path
import platform
import sys
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT/".cache/parser"


def bootstrap():
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("Use pip with requirements-annotation.txt on this platform")
    TARGET.mkdir(parents=True,exist_ok=True)
    metadata = []
    for name,version in (("tree-sitter","0.25.2"),("tree-sitter-java","0.23.5")):
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{version}/json",timeout=30) as response:
            info = json.load(response)
        python_tag = f"cp{sys.version_info.major}{sys.version_info.minor}"
        files = [f for f in info["urls"] if f["filename"].endswith(".whl") and "manylinux" in f["filename"] and "x86_64" in f["filename"] and (python_tag+"-" in f["filename"] or "cp39-abi3" in f["filename"])]
        if not files:
            raise RuntimeError("No compatible pinned wheel for "+name+"; install requirements in Python3.12 venv")
        wheel = sorted(files,key=lambda f:f["filename"])[0]
        with urllib.request.urlopen(wheel["url"],timeout=60) as response:
            buf = response.read()
        if hashlib.sha256(buf).hexdigest()!=wheel["digests"]["sha256"]:
            raise ValueError("Parser wheel SHA256 mismatch")
        with zipfile.ZipFile(io.BytesIO(buf)) as archive:
            for member in archive.infolist():
                if not (TARGET/member.filename).resolve().is_relative_to(TARGET.resolve()):
                    raise ValueError("Wheel path traversal")
            archive.extractall(TARGET)
        metadata.append(dict(package=name,version=version,filename=wheel["filename"],sha256=wheel["digests"]["sha256"]))
    (TARGET/"install.json").write_text(json.dumps(metadata,indent=2)+"\n")
    print(json.dumps(metadata,indent=2))


if __name__ == "__main__":
    bootstrap()
