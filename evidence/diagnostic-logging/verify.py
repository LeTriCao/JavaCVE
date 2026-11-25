"""Compile and check the ordinary JVM logging control, without external dependencies."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
SOURCE = HERE / "JvmLoggingControl.java"
COMPILE = ["-proc:none", "-encoding", "UTF-8", "-classpath", ".", "-d", ".", SOURCE.name]
LAUNCH = ["-classpath", ".", "JvmLoggingControl"]
IGNORED_ENV = ("CLASSPATH", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "JDK_JAVAC_OPTIONS", "_JAVA_OPTIONS")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jdk", type=Path, help="JDK root (defaults to javac/java on PATH)")
    parser.add_argument("--out", type=Path, help="Create a new directory for the result")
    args = parser.parse_args()
    env = {k: v for k, v in os.environ.items() if k not in IGNORED_ENV}
    javac, java = [str(args.jdk.resolve() / "bin" / name) if args.jdk else name for name in ("javac", "java")]
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    with tempfile.TemporaryDirectory() as temporary:
        def run(command):
            return subprocess.run(command, cwd=temporary, env=env, check=True, timeout=60,
                                  text=True, encoding="utf-8", stderr=subprocess.STDOUT,
                                  stdout=subprocess.PIPE).stdout
        shutil.copyfile(SOURCE, Path(temporary) / SOURCE.name)
        compiler = run([javac, "-version"]).strip()
        run([javac, *COMPILE])
        output = run([java, *LAUNCH])
    lines = output.splitlines()
    message = "Invalid sample value"
    exception = "java.lang.IllegalArgumentException"
    cause = "java.lang.NumberFormatException"
    checks = {
        "ordinary_control": "STAGE=VALID_INTEGER\nPARSED_INTEGER=42\nSTAGE=INVALID_INTEGER" in output,
        "exception_type_and_stage": f"EXCEPTION_STAGE=INVALID_INTEGER\nEXCEPTION_CLASS={exception}" in output,
        "outer_message": f"EXCEPTION_MESSAGE_BEGIN\n{message}\nEXCEPTION_MESSAGE_END" in output,
        "cause_chain": (f"CAUSE_0_CLASS={exception}\nCAUSE_0_MESSAGE={message}\nCAUSE_1_CLASS={cause}" in output
                        and any(s.startswith("CAUSE_1_MESSAGE=") and "example" in s for s in lines)
                        and not any(s.startswith("CAUSE_2_") for s in lines)),
        "trace": (f"STACK_TRACE_BEGIN\n{exception}: {message}" in output
                  and f"Caused by: {cause}:" in output and "at JvmLoggingControl.main(" in output
                  and lines[-1:] == ["STACK_TRACE_END"]),
        "runtime_config": (all(any(s.startswith(key + "=") and s != key + "=" for s in lines)
                               for key in ("JAVA_VERSION", "JAVA_RUNTIME_VERSION", "JAVA_VENDOR", "JAVA_VM_NAME", "JAVA_HOME"))
                           and "JAVA_CLASSPATH=." in lines),
    }
    if not all(checks.values()):
        raise SystemExit(f"Logging check failed: {checks}")
    # Preserve stack, messages and classpath while removing the machine-specific JDK path.
    public_log = "\n".join("JAVA_HOME=<jdk-runtime>" if s.startswith("JAVA_HOME=") else s for s in lines) + "\n"
    receipt = dict(status="PASS", reviewer="AI", scope="Standard-library integer parsing and Throwable logging",
                   start_utc=started, end_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
                   compiler=compiler, compile_command=["javac", *COMPILE], java_command=["java", *LAUNCH],
                   compile_exit_code=0, java_exit_code=0, checks=checks, excluded_environment=list(IGNORED_ENV),
                   source_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                   verifier_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   public_log_sha256=hashlib.sha256(public_log.encode()).hexdigest(),
                   logging_source_receipt="evidence/v0.2.0/a4e197b267ca44baa4896be94b9f65b5/run.json")
    if args.out:
        args.out.mkdir(parents=True, exist_ok=False)
        (args.out / "stdout.log").write_bytes(public_log.encode())
        (args.out / "receipt.json").write_bytes((json.dumps(receipt, indent=2) + "\n").encode())
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
