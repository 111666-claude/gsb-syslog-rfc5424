import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from syslog5424 import core

LINE = '<165>1 2003-10-11T22:14:15.003Z host app 1234 ID47 - message'
SD_LINE = '<165>1 2003-10-11T22:14:15.003Z host app 1234 ID47 [ex a="text"] message'


class Syslog5424Test(unittest.TestCase):
    def test_version(self):
        self.assertEqual(core.parse_line(LINE, core.Counter())["version"], "1")

    def test_app(self):
        self.assertEqual(core.parse_line(LINE, core.Counter())["app"], "app")

    def test_message_tail(self):
        self.assertEqual(core.parse_line(LINE, core.Counter())["msg"], "message")

    def test_sd_plain_param(self):
        self.assertEqual(core.parse_line(SD_LINE, core.Counter())["sd"]["ex"]["a"], "text")

    def test_fields_present(self):
        parsed = core.parse_line(LINE, core.Counter())
        for field in ("pri", "facility", "severity", "version", "hostname", "app", "msgid", "sd", "msg"):
            self.assertIn(field, parsed)

    def test_counter_counts(self):
        counter = core.Counter()
        core.parse_line(LINE, counter)
        self.assertGreater(counter.scanned, 0)


if __name__ == "__main__":
    unittest.main()
