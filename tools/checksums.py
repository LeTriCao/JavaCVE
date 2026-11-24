"""Seal distributable inputs; historical evidence files are never rewritten."""
import json
from .catalog import ROOT
from .build import digest


def seal():
    paths = []
    for name in ("data","docs","evidence","licenses","smoke","fixtures","tools","tests",".github"):
        paths += [p for p in (ROOT/name).rglob("*") if p.is_file() and "__pycache__" not in p.parts and p.suffix not in (".pyc", ".jar")]
    paths += [p for p in ROOT.iterdir() if p.is_file() and p.name != "checksums.json" and p.suffix in (".py",".md", ".toml", ".txt")]
    paths += [ROOT/"LICENSE",ROOT/".gitignore",ROOT/".gitattributes"]
    manifest = {p.relative_to(ROOT).as_posix():digest(p) for p in sorted(set(paths)) if p.exists()}
    (ROOT/"checksums.json").write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print("Sealed",len(manifest),"files")
