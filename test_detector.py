"""
Unit tests for CyberShield – detector.py
Uses only harmless, fictitious, or well-known safe URLs.
No URL is visited or sent to any external service.
"""

import unittest
from detector import analyze_url


class TestUrlValidation(unittest.TestCase):
    """Tests for URL format validation."""

    def test_empty_string(self):
        result = analyze_url("")
        self.assertFalse(result["valid"])
        self.assertEqual(result["category"], "Invalid")

    def test_missing_scheme(self):
        result = analyze_url("example.com")
        self.assertFalse(result["valid"])
        self.assertEqual(result["category"], "Invalid")

    def test_missing_netloc(self):
        result = analyze_url("http://")
        self.assertFalse(result["valid"])
        self.assertEqual(result["category"], "Invalid")

    def test_completely_random_string(self):
        result = analyze_url("notaurl!!")
        self.assertFalse(result["valid"])

    def test_whitespace_only(self):
        result = analyze_url("   ")
        self.assertFalse(result["valid"])


class TestLowRiskUrls(unittest.TestCase):
    """Well-formed, low-risk URLs should score 0 and be categorised Low."""

    def test_https_clean_url(self):
        result = analyze_url("https://www.example.com")
        self.assertTrue(result["valid"])
        self.assertEqual(result["category"], "Low")
        self.assertEqual(result["score"], 0)

    def test_https_with_path(self):
        result = analyze_url("https://docs.example.org/guide/setup")
        self.assertTrue(result["valid"])
        self.assertEqual(result["category"], "Low")

    def test_https_short_url(self):
        result = analyze_url("https://example.net")
        self.assertTrue(result["valid"])
        self.assertLessEqual(result["score"], 1)


class TestMediumRiskUrls(unittest.TestCase):
    """URLs with mild warning signs should land in Medium."""

    def test_http_with_login_keyword(self):
        # http (weight 1) + 'login' keyword (weight 1) = 2 → Medium
        result = analyze_url("http://example.com/login")
        self.assertTrue(result["valid"])
        self.assertEqual(result["category"], "Medium")
        self.assertGreaterEqual(result["score"], 1)

    def test_hyphenated_domain_http(self):
        # http + hyphen-in-domain = 2 → Medium
        result = analyze_url("http://my-bank.com/home")
        self.assertTrue(result["valid"])
        self.assertIn(result["category"], ("Medium", "High"))

    def test_keyword_only_https(self):
        # Only 'verify' keyword, HTTPS → score 1 → still Low or Medium
        result = analyze_url("https://service.example.com/verify-email")
        self.assertTrue(result["valid"])
        # Score should be low (≤ 2)
        self.assertLessEqual(result["score"], 2)


class TestHighRiskUrls(unittest.TestCase):
    """URLs with multiple red flags should land in High."""

    def test_ip_address_hostname(self):
        # IP hostname weight = 3 → High
        result = analyze_url("http://192.168.1.1/login")
        self.assertTrue(result["valid"])
        self.assertEqual(result["category"], "High")
        self.assertGreaterEqual(result["score"], 4)

    def test_at_symbol_in_url(self):
        # @ in netloc weight = 3 → High
        result = analyze_url("http://evil.com@safe-looking.example.com")
        self.assertTrue(result["valid"])
        self.assertGreaterEqual(result["score"], 3)

    def test_very_long_url(self):
        # Long URL (weight 2) + http (weight 1) = 3 → Medium/High
        long_url = "http://example.com/" + "a" * 90
        result = analyze_url(long_url)
        self.assertTrue(result["valid"])
        self.assertGreaterEqual(result["score"], 2)

    def test_multiple_subdomains(self):
        # 5 parts in hostname → weight 2
        result = analyze_url("https://a.b.c.d.example.com/page")
        self.assertTrue(result["valid"])
        self.assertGreaterEqual(result["score"], 2)

    def test_double_slash_redirect(self):
        result = analyze_url("http://example.com//redirect?url=evil.com")
        self.assertTrue(result["valid"])
        self.assertGreaterEqual(result["score"], 2)

    def test_combined_high_risk(self):
        """IP + long URL + login keyword → definitely High."""
        long_path = "/login?" + "x=" * 40
        result = analyze_url(f"http://10.0.0.1{long_path}")
        self.assertTrue(result["valid"])
        self.assertEqual(result["category"], "High")


class TestSpecificRules(unittest.TestCase):
    """Fine-grained tests for individual rule triggers."""

    def test_ip_hostname_rule_triggered(self):
        result = analyze_url("http://203.0.113.5/")
        reasons_text = " ".join(result["reasons"]).lower()
        self.assertIn("ip address", reasons_text)

    def test_at_symbol_rule_triggered(self):
        result = analyze_url("http://attacker.com@legitimate.example.com/")
        reasons_text = " ".join(result["reasons"]).lower()
        self.assertIn("@", reasons_text)

    def test_https_rule_not_triggered_for_https(self):
        """HTTPS URLs should NOT trigger the HTTP warning."""
        result = analyze_url("https://clean.example.com/")
        reasons_text = " ".join(result["reasons"]).lower()
        self.assertNotIn("unencrypted", reasons_text)

    def test_keyword_amazon_flagged(self):
        result = analyze_url("http://not-amazon.com/amazon/signin")
        reasons_text = " ".join(result["reasons"]).lower()
        self.assertIn("amazon", reasons_text)

    def test_result_has_required_keys(self):
        result = analyze_url("https://example.com")
        for key in ("valid", "score", "category", "reasons", "url"):
            self.assertIn(key, result)

    def test_reasons_is_list(self):
        result = analyze_url("https://example.com")
        self.assertIsInstance(result["reasons"], list)
        self.assertGreater(len(result["reasons"]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
