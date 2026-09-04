import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.ai_advisor import CommandSanitizer


class TestCommandSanitizer(unittest.TestCase):

    def test_nuclei_adds_exclude_tags_when_missing(self):
        cmd = "nuclei -u https://target.com -t cves/"
        result, warnings = CommandSanitizer.sanitize_command(cmd)
        self.assertIn("-exclude-tags dos,destructive,fuzz", result)
        self.assertTrue(len(warnings) > 0)

    def test_nuclei_does_not_duplicate_exclude_tags(self):
        cmd = "nuclei -u https://target.com -exclude-tags dos,destructive,fuzz"
        result, warnings = CommandSanitizer.sanitize_command(cmd)
        self.assertEqual(result.count("-exclude-tags"), 1)

    def test_sqlmap_removes_os_shell(self):
        cmd = "sqlmap -u 'http://t.com?id=1' --os-shell --batch"
        result, warnings = CommandSanitizer.sanitize_command(cmd)
        self.assertNotIn("--os-shell", result)
        self.assertTrue(any("--os-shell" in w for w in warnings))

    def test_sqlmap_removes_dump_all(self):
        cmd = "sqlmap -u 'http://t.com?id=1' --dump-all --batch"
        result, warnings = CommandSanitizer.sanitize_command(cmd)
        self.assertNotIn("--dump-all", result)

    def test_sqlmap_adds_required_flags(self):
        cmd = "sqlmap -u 'http://t.com?id=1'"
        result, warnings = CommandSanitizer.sanitize_command(cmd)
        self.assertIn("--level 1", result)
        self.assertIn("--risk 1", result)
        self.assertIn("--batch", result)

    def test_ffuf_adds_rate_cap(self):
        cmd = "ffuf -u https://t.com/FUZZ -w wordlist.txt"
        result, warnings = CommandSanitizer.sanitize_command(cmd)
        self.assertIn("-rate 20", result)

    def test_ffuf_does_not_duplicate_rate(self):
        cmd = "ffuf -u https://t.com/FUZZ -w wordlist.txt -rate 10"
        result, warnings = CommandSanitizer.sanitize_command(cmd)
        self.assertEqual(result.count("-rate"), 1)

    def test_dalfox_adds_skip_bav(self):
        cmd = "dalfox url https://t.com/search?q=test"
        result, warnings = CommandSanitizer.sanitize_command(cmd)
        self.assertIn("--skip-bav", result)

    def test_forbidden_tool_is_blocked(self):
        cmd = "msfconsole -x 'use exploit/multi/handler'"
        result, warnings = CommandSanitizer.sanitize_command(cmd)
        self.assertNotIn("msfconsole", result)
        self.assertTrue(any("blocked" in w.lower() for w in warnings))

    def test_curl_while_loop_is_blocked(self):
        cmd = "while true; do curl https://target.com; done"
        result, warnings = CommandSanitizer.sanitize_command(cmd)
        self.assertTrue(any("loop" in w.lower() for w in warnings))

    def test_sanitize_markdown_patches_code_blocks(self):
        md = '''
Run this:
```bash
nuclei -u https://target.com -t cves/
sqlmap -u "http://t.com?id=1" --dump-all
```
'''
        result, warnings = CommandSanitizer.sanitize_markdown(md)
        self.assertIn("-exclude-tags dos,destructive,fuzz", result)
        self.assertNotIn("--dump-all", result)
        self.assertTrue(len(warnings) > 0)

    def test_clean_command_has_no_warnings(self):
        cmd = ("nuclei -u https://t.com -t cves/ "
               "-exclude-tags dos,destructive,fuzz")
        result, warnings = CommandSanitizer.sanitize_command(cmd)
        self.assertEqual(cmd.strip(), result.strip())
        self.assertEqual(warnings, [])


if __name__ == '__main__':
    unittest.main()
