"""Copy selected immutable run receipts/logs for release, redacting local paths."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.runtime import ROOT, read_run, redact


def clean(value):
    if isinstance(value,str):
        return redact(value)
    if isinstance(value,list):
        return [clean(v) for v in value]
    if isinstance(value,dict):
        return {k:clean(v) for k,v in value.items()}
    return value


def publish(paths):
    for argument in paths:
        source,data=read_run(argument)
        if data["status"] not in ("PASS","FAIL"):
            raise ValueError("Refuse to publish unfinished run: "+data["run_id"])
        destination=ROOT/"evidence/v0.2.0"/data["run_id"]
        destination.mkdir(parents=True,exist_ok=False)
        public=clean(data)
        public.update(public_receipt=True,original_run_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                      redaction="Local workspace/home paths and credentials removed. Raw run and artifacts retained locally; rebuild sources for artifact replay on another machine.")
        (destination/"run.json").write_text(json.dumps(public,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        for name in ("file-comparison.json","quality-review.json","unconfirmed.json"):
            if (source.parent/name).exists():
                (destination/name).write_text(json.dumps(clean(json.loads((source.parent/name).read_text(encoding="utf-8"))),ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        if (source.parent/"logs").exists():
            (destination/"logs").mkdir()
            for log in (source.parent/"logs").glob("*.log"):
                (destination/"logs"/log.name).write_text(redact(log.read_text(encoding="utf-8",errors="replace")),encoding="utf-8")
        print(destination.relative_to(ROOT))


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("runs",nargs="+",type=Path)
    publish(parser.parse_args().runs)
