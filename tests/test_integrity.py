import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools.catalog import unique, verify, verify_sources
from tools.runtime import category, redact, Run, StepError
from tools.security import parse_probe


class IntegrityTests(unittest.TestCase):
    def test_catalog_relations_and_counts(self):
        result = verify()
        self.assertEqual((result["cves"],result["methods"],result["present_versions"]),(10,126,187))
        self.assertEqual((result["expansion"]["cves"],result["expansion"]["method_versions"]),(10,222))

    def test_duplicate_primary_key_rejected(self):
        with self.assertRaisesRegex(ValueError,"Duplicate"):
            unique([{"id":"same"},{"id":"same"}],"id")

    def test_source_mutation_and_out_of_range_rejected(self):
        data = b"class A {\n void f() {}\n}\n"
        blob = hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
        records = {"cases":[{"cve_id":"CVE-TEST"}],
                   "files":[{"cve_id":"CVE-TEST","file_id":"f","file_path_before":"A.java","before_blob":blob,"file_path_after":None,"after_blob":None}],
                   "versions":[{"sample_id":"m:before","file_id":"f","phase":"before","start_line":2,"end_line":2,"is_test":False,"code_sha256":hashlib.sha256(b"void f() {}").hexdigest()}]}
        with tempfile.TemporaryDirectory() as tmp, patch("tools.catalog.rows",side_effect=lambda table:records[table]):
            base = Path(tmp)
            source = base/"CVE-TEST/before/A.java"
            source.parent.mkdir(parents=True)
            source.write_bytes(data)
            self.assertEqual(verify_sources(base)["checked_method_versions"],1)
            records["versions"][0]["end_line"] = 999
            with self.assertRaisesRegex(ValueError,"line range"):
                verify_sources(base)
            records["versions"][0]["end_line"] = 2
            source.write_bytes(data+b"// tampered\n")
            with self.assertRaisesRegex(ValueError,"blob mismatch"):
                verify_sources(base)

    def test_incomplete_probe_is_harness_error(self):
        for kind in ("commons-io","plexus-utils","zip4j"):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                parse_probe(kind,"")

    def test_security_failure_remains_observation(self):
        tests = parse_probe("zip4j","good.txt => accepted; written=true\n../outside.txt => accepted; written=true\n../out-sibling.txt => accepted; written=true\n")
        self.assertTrue(tests[0]["pass"])
        self.assertEqual(sum(not t["pass"] for t in tests),2)

    def test_diagnostics_do_not_expose_tokens(self):
        text = redact("https://user:secret@example.com/ Authorization: Bearer abcdef ghp_abc123")
        self.assertNotIn("secret",text)
        self.assertNotIn("abcdef",text)
        self.assertNotIn("ghp_abc123",text)
        self.assertEqual(category("Could not resolve host: example.com"),"NETWORK")
        self.assertEqual(category("Non-resolvable parent POM"),"DEPENDENCY")

    def test_failure_records_exit_code_and_log(self):
        import sys
        with tempfile.TemporaryDirectory() as tmp, patch("tools.runtime.ROOT",Path(tmp)):
            (Path(tmp)/"data").mkdir()
            (Path(tmp)/"data/versions.jsonl").write_text("{}\n")
            run = Run("test")
            with self.assertRaises(StepError) as exc:
                run.execute("failing",[sys.executable,"-c","import sys; print('diagnostic'); sys.exit(7)"])
            run.finish(exc.exception)
            saved = json.loads((run.directory/"run.json").read_text())
            self.assertEqual(saved["exit_code"],7)
            self.assertEqual(saved["steps"][0]["exit_code"],7)
            self.assertIn("diagnostic",(run.directory/saved["steps"][0]["log"]).read_text())


if __name__ == "__main__":
    unittest.main()
