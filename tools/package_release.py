"""Package exactly the tagged Git tree; exclude caches, logs and third-party binaries."""
import hashlib
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[1]


def package():
    commit=subprocess.check_output(["git","rev-parse","v0.2.0^{}"],cwd=ROOT,text=True).strip()
    target=ROOT/"dist"
    target.mkdir(exist_ok=True)
    archive=target/"JavaCVE-v0.2.0.zip"
    if archive.exists():
        raise FileExistsError("Release package already exists; retain it and use a fresh output for a different tag")
    with archive.open("xb") as stream:
        subprocess.run(["git","archive","--format=zip","--prefix=JavaCVE-v0.2.0/","v0.2.0"],cwd=ROOT,stdout=stream,check=True)
    report=target/"JavaCVE-v0.2.0-report.docx"
    report.write_bytes(subprocess.check_output(["git","show","v0.2.0:docs/generated/COURSE_REPORT.docx"],cwd=ROOT))
    checks=[]
    for path in (archive,report):
        with path.open("rb") as stream:
            checks.append(hashlib.file_digest(stream,"sha256").hexdigest()+"  "+path.name)
    (target/"SHA256SUMS.txt").write_text("\n".join(checks)+"\n",encoding="utf-8")
    print("commit",commit)
    print("\n".join(checks))


if __name__=="__main__":
    package()
