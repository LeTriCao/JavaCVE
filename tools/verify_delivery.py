"""Validate a fresh clone or extracted archive without reusing its source checkout."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile


def main():
    p=argparse.ArgumentParser()
    p.add_argument("source",type=Path)
    p.add_argument("--archive",action="store_true")
    p.add_argument("--security",action="store_true")
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    records=[]
    with tempfile.TemporaryDirectory(prefix="javacve-delivery-") as temporary:
        temporary=Path(temporary)
        if args.archive:
            with zipfile.ZipFile(args.source) as archive:
                for name in archive.namelist():
                    if not (temporary/name).resolve().is_relative_to(temporary):
                        raise ValueError("Archive path traversal")
                archive.extractall(temporary)
            children=list(temporary.iterdir())
            if len(children)!=1 or not children[0].is_dir():
                raise ValueError("Expected one distribution directory")
            checkout=children[0]
        else:
            checkout=temporary/"JavaCVE"
            subprocess.run(["git","clone","--no-hardlinks",str(args.source.resolve()),str(checkout)],check=True)
        commands=[[sys.executable,"run.py","demo"],
                  [sys.executable,"-m","unittest","discover","-s","tests","-v"],
                  [sys.executable,"run.py","list","--cwe","CWE-22"],
                  [sys.executable,"run.py","report"],
                  [sys.executable,"run.py","split"]]
        if args.security:
            commands.append([sys.executable,"run.py","all","--cve","CVE-2021-29425"])
        for command in commands:
            result=subprocess.run(command,cwd=checkout,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=1500)
            records.append(dict(command=command[1:],exit_code=result.returncode,output=result.stdout.replace(str(temporary),"<fresh-checkout>")))
            print(command[1:],result.returncode,flush=True)
            args.output.parent.mkdir(parents=True,exist_ok=True)
            args.output.write_text(json.dumps(dict(source=str(args.source),archive=args.archive,security=args.security,
                                                  status="PASS" if all(r["exit_code"]==0 for r in records) else "FAIL",checks=records),ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
            if result.returncode:
                print(result.stdout)
                return result.returncode
    return 0


if __name__=="__main__":
    sys.exit(main())
