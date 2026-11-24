import unittest
from tools.security import parse_probe


class LocalProbeTests(unittest.TestCase):
    def test_callback_execution_is_a_security_failure(self):
        output = "ASSERT|control|string_roundtrip|true\nASSERT|security|untrusted_event_handler_blocked|false\n"
        tests = parse_probe("xstream-local", output)
        self.assertTrue(tests[0]["pass"])
        self.assertFalse(tests[1]["pass"])

    def test_incomplete_or_malformed_output_fails(self):
        for output in ("", "ASSERT|control|roundtrip|true", "ASSERT|control|string_roundtrip|maybe\nASSERT|security|blocked|true"):
            with self.assertRaises(ValueError):
                parse_probe("xstream-local", output)
