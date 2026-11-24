"""Append-only run records, timed subprocesses and portable error diagnostics."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.2.0"


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def redact(text):
    text = re.sub(r"(https?://)[^/@\s]+:[^/@\s]+@", r"\1[REDACTED]@", str(text))
    text = re.sub(r"(?i)(authorization[:=]\s*(?:bearer|token)?\s*)\S+", r"\1[REDACTED]", text)
    text = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+)\b", "[REDACTED]", text)
    return text.replace(str(ROOT), "<workspace>").replace(str(Path.home()), "<home>")


class StepError(RuntimeError):
    def __init__(self, message, code=1, category="COMMAND_FAILED"):
        super().__init__(message)
        self.code, self.category = code, category


def category(text):
    low = text.lower()
    if any(s in low for s in ("could not resolve host", "unknown host", "name or service not known", "network is unreachable", "connection timed out", "temporary failure in name resolution")):
        return "NETWORK"
    if any(s in low for s in ("pkix", "certificate verify", "ssl certificate")):
        return "TLS"
    if any(s in low for s in ("could not resolve dependencies", "non-resolvable parent", "could not find artifact", "failed to collect dependencies", "pluginresolutionexception")):
        return "DEPENDENCY"
    return "COMMAND_FAILED"


class Run:
    def __init__(self, action, arguments=None):
        self.started = time.perf_counter()
        self.directory = ROOT / "runs" / uuid.uuid4().hex
        self.directory.mkdir(parents=True)
        try:
            commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, stderr=subprocess.DEVNULL, text=True).strip()
            dirty = bool(subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT, text=True))
        except (OSError, subprocess.SubprocessError):
            commit, dirty = None, None
        self.report = dict(run_id=self.directory.name, release=VERSION, command=action,
                           start_utc=utc(), status="running", exit_code=None,
                           arguments=redact(arguments or ""), project_commit=commit, working_tree_dirty=dirty,
                           dataset_sha256=hashlib.sha256((ROOT / "data/versions.jsonl").read_bytes()).hexdigest(),
                           environment=dict(system=platform.system(), architecture=platform.machine(),
                                            python=platform.python_version(), platform=platform.platform(),
                                            locale=os.environ.get("LANG")), steps=[], snapshots=[])
        self.save()

    def save(self):
        p = self.directory / "run.json"
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, p)

    def execute(self, name, command, cwd=ROOT, env=None, timeout=600, owner=None):
        step = dict(stage=name, command=[redact(x) for x in command], start_utc=utc(), status="running")
        if owner:
            step.update(cve_id=owner[0], phase=owner[1], commit=owner[2])
        log = self.directory / "logs" / (str(len(self.report["steps"])) + "-" + name + ".log")
        log.parent.mkdir(exist_ok=True)
        step["log"] = str(log.relative_to(self.directory))
        self.report["steps"].append(step)
        self.save()
        start = time.perf_counter()
        result, code, reason = "", 0, None
        try:
            proc = subprocess.run(list(map(str, command)), cwd=cwd, env=env, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True, errors="replace", timeout=timeout)
            result, code = proc.stdout, proc.returncode
            if code:
                reason = category(result)
        except subprocess.TimeoutExpired as exc:
            result = exc.stdout or b""
            if isinstance(result, bytes):
                result = result.decode("utf-8", errors="replace")
            code, reason = 124, "TIMEOUT"
        except FileNotFoundError as exc:
            result, code, reason = str(exc), 127, "MISSING_DEPENDENCY"
        except OSError as exc:
            result, code, reason = str(exc), 1, "OS_ERROR"
        log.write_text(redact(result), encoding="utf-8")
        step.update(end_utc=utc(), seconds=round(time.perf_counter()-start, 6), exit_code=code,
                    status="PASS" if code == 0 else "FAIL", error_category=reason)
        self.save()
        if code:
            raise StepError(f"{name}: {reason}; see {step['log']}", code, reason)
        return result

    def finish(self, error=None):
        self.report.update(end_utc=utc(), seconds=round(time.perf_counter()-self.started, 6),
                           status="FAIL" if error else "PASS", exit_code=getattr(error, "code", 1) if error else 0)
        if error:
            self.report.update(error=redact(error), error_type=type(error).__name__,
                               error_category=getattr(error, "category", "VALIDATION"))
        self.save()
        print(self.report["status"], self.directory.relative_to(ROOT) / "run.json", flush=True)


def read_run(path):
    path = Path(path)
    if not path.exists():
        path = ROOT / "runs" / str(path) / "run.json"
    if path.is_dir():
        path /= "run.json"
    return path.resolve(), json.loads(path.read_text(encoding="utf-8"))
