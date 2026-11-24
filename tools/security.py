"""Interpret the original Reproducible probe; missing or malformed output is an error."""
from .observations import require


def parse_probe(kind, output):
    tests = []
    if kind in {"spark-local", "xstream-local"}:
        for line in output.splitlines():
            if not line.startswith("ASSERT|"):
                continue
            parts = line.split("|")
            require(len(parts) == 4 and parts[1] in {"control", "security"} and parts[3] in {"true", "false"}, "Malformed local assertion")
            tests.append(dict(name=parts[2],role=parts[1],observed=parts[3],**{"pass":parts[3]=="true"}))
        require(len(tests) == (4 if kind == "spark-local" else 2), "Incomplete local probe")
        require(len({t["name"] for t in tests}) == len(tests), "Duplicate local assertion")
        return tests
    if kind == "commons-io":
        lines = [line for line in output.splitlines() if " => " in line]
        require(len(lines) == 3, "Expected exactly three normalization observations")
        for line in lines:
            value, observed = line.split(" => ", 1)
            control = value == "dir/file.txt"
            tests.append(dict(name="benign_normalize" if control else "normalize_invalid_prefix_"+str(len(tests)+1),
                              role="control" if control else "security", observed=observed,
                              **{"pass": observed == ("dir/file.txt" if control else "null")}))
        require(sum(t["role"] == "control" for t in tests) == 1, "Missing normalization control")
    elif kind == "plexus-utils":
        values = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        require({"OUTPUT", "EXIT", "EXECUTABLE_OUTPUT", "EXECUTABLE_EXIT"} <= values.keys(), "Incomplete shell observations")
        tests = [dict(name="literal_argument", role="control", observed=values["OUTPUT"],
                      **{"pass": values["OUTPUT"] == "$PILOT_ONLY_MARKER" and values["EXIT"] == "0"}),
                 dict(name="literal_executable_path", role="security", observed=values["EXECUTABLE_EXIT"],
                      **{"pass": values["EXECUTABLE_OUTPUT"] == "PILOT_SCRIPT_OK" and values["EXECUTABLE_EXIT"] == "0"})]
    else:
        require(kind in {"hutool", "zt-zip", "zip4j", "plexus-archiver"}, "Unknown security probe")
        for entry, name, role in [("good.txt", "benign_zip", "control"), ("../outside.txt", "parent_containment", "security"),
                                  ("../out-sibling.txt", "sibling_prefix_containment", "security")]:
            lines = [line for line in output.splitlines() if line.startswith(entry+" => ")]
            require(len(lines) == 1 and ("written=true" in lines[0] or "written=false" in lines[0]), "Missing ZIP observation: "+entry)
            tests.append(dict(name=name, role=role, observed=lines[0],
                              **{"pass": ("written=true" if role == "control" else "written=false") in lines[0]}))
    return tests
