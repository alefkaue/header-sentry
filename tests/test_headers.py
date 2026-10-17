import unittest
from header_sentry import audit, parse

STRONG = """Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Strict-Transport-Security: max-age=31536000; includeSubDomains
"""

class HeaderTests(unittest.TestCase):
    def test_strong_example(self):
        self.assertEqual(audit(STRONG, True)['findings'], [])

    def test_missing_and_https_scope(self):
        self.assertIn('hsts', [x['rule'] for x in audit('', True)['findings']])
        self.assertNotIn('hsts', [x['rule'] for x in audit('')['findings']])

    def test_weak_csp_and_zero_hsts(self):
        value = STRONG.replace("default-src 'self'", "default-src * 'unsafe-inline'").replace('31536000', '0')
        rules = [x['rule'] for x in audit(value, True)['findings']]
        self.assertIn('csp_weak_script', rules)
        self.assertIn('hsts', rules)

    def test_report_only_is_not_enforcement(self):
        value = STRONG.replace('Content-Security-Policy:', 'Content-Security-Policy-Report-Only:')
        self.assertIn('missing_csp', [x['rule'] for x in audit(value)['findings']])

    def test_case_duplicates_and_bad_input(self):
        self.assertEqual(parse('X-Test: one\nX-TEST: two')['x-test'], ['one', 'two'])
        with self.assertRaises(ValueError):
            parse('broken')
        self.assertTrue(any(x['rule'].startswith('duplicate_') for x in audit(STRONG + 'Referrer-Policy: unsafe-url')['findings']))
