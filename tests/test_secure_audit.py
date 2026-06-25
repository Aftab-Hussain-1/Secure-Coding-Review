import unittest
from pathlib import Path

from core.analyzer import SecurityAnalyzer


class TestSecureAudit(unittest.TestCase):
    def test_sample_has_expected_rules(self):
        base = Path(__file__).resolve().parents[1]
        target = base / "samples" / "vulnerable_app.py"

        analyzer = SecurityAnalyzer()
        result = analyzer.analyze_file(str(target))

        self.assertGreater(len(result.findings), 0)

        rule_ids = {f.rule_id for f in result.findings}
        expected = {
            "INJ-001",
            "INJ-002",
            "INJ-003",
            "DESER-001",
            "AUTH-001",
            "AUTH-002",
            "AUTH-003",
            "XSS-001",
            "PATH-001",
            "CONF-001",
            "CONF-002",
            "INFO-001",
        }
        self.assertTrue(expected.issubset(rule_ids))


if __name__ == "__main__":
    unittest.main()

