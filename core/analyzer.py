"""
Static Analyzer Engine
=======================
Performs pattern-based and AST-based analysis of Python source files
to identify security vulnerabilities defined in the rules engine.
"""

import ast
import re
import os
import hashlib
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from pathlib import Path

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from rules.vulnerability_rules import (
    VulnerabilityRule, VULNERABILITY_RULES, SEVERITY_ORDER
)


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    category: str
    severity: str
    cwe_id: str
    owasp_category: str
    description: str
    file_path: str
    line_number: int
    line_content: str
    detection_method: str
    matched_pattern: str
    remediation: str
    example_bad: str
    example_good: str
    references: List[str]
    confidence: str
    fingerprint: str = ""

    def __post_init__(self):
        raw = f"{self.rule_id}:{self.file_path}:{self.line_number}"
        self.fingerprint = hashlib.md5(raw.encode()).hexdigest()[:12]


@dataclass
class AnalysisResult:
    target_file: str
    file_size_bytes: int
    total_lines: int
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    scan_duration_ms: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "MEDIUM")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "LOW")

    @property
    def risk_score(self) -> int:
        weights = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 4, "LOW": 1}
        raw = sum(weights.get(f.severity, 0) for f in self.findings)
        return min(100, raw)

    @property
    def risk_grade(self) -> str:
        s = self.risk_score
        if s == 0:
            return "A"
        if s <= 10:
            return "B"
        if s <= 30:
            return "C"
        if s <= 60:
            return "D"
        return "F"


class PatternAnalyzer:
    def scan(self, source_lines: List[str], rule: VulnerabilityRule,
             file_path: str) -> List[Finding]:
        findings = []
        for lineno, line in enumerate(source_lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pattern in rule.patterns:
                try:
                    m = re.search(pattern, line, re.IGNORECASE)
                    if m:
                        confidence = self._assess_confidence(line)
                        findings.append(Finding(
                            rule_id=rule.rule_id,
                            rule_name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            cwe_id=rule.cwe_id,
                            owasp_category=rule.owasp_category,
                            description=rule.description,
                            file_path=file_path,
                            line_number=lineno,
                            line_content=line.rstrip(),
                            detection_method="pattern",
                            matched_pattern=pattern,
                            remediation=rule.remediation,
                            example_bad=rule.example_bad,
                            example_good=rule.example_good,
                            references=rule.references,
                            confidence=confidence,
                        ))
                        break
                except re.error:
                    pass
        return findings

    def _assess_confidence(self, line: str) -> str:
        line_lower = line.lower()
        input_tokens = ["request", "args", "form", "input", "param",
                        "user", "data", "query", "body"]
        if any(tok in line_lower for tok in input_tokens):
            return "HIGH"
        test_tokens = ["test", "mock", "fake", "example", "sample"]
        if any(tok in line_lower for tok in test_tokens):
            return "LOW"
        return "MEDIUM"


class ASTAnalyzer:
    def scan(self, source: str, rule: VulnerabilityRule,
             file_path: str) -> List[Finding]:
        findings = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return findings

        source_lines = source.splitlines()
        for node in ast.walk(tree):
            for check in rule.ast_checks:
                kind, name = check.split(":", 1) if ":" in check else ("", check)
                if self._node_matches(node, kind, name):
                    lineno = getattr(node, "lineno", 0)
                    line_content = (source_lines[lineno - 1]
                                    if 0 < lineno <= len(source_lines) else "")
                    findings.append(Finding(
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        category=rule.category,
                        severity=rule.severity,
                        cwe_id=rule.cwe_id,
                        owasp_category=rule.owasp_category,
                        description=rule.description,
                        file_path=file_path,
                        line_number=lineno,
                        line_content=line_content,
                        detection_method="ast",
                        matched_pattern=check,
                        remediation=rule.remediation,
                        example_bad=rule.example_bad,
                        example_good=rule.example_good,
                        references=rule.references,
                        confidence="MEDIUM",
                    ))
        return findings

    def _dotted_name(self, expr: ast.AST) -> str:
        if isinstance(expr, ast.Name):
            return expr.id
        if isinstance(expr, ast.Attribute):
            base = self._dotted_name(expr.value)
            return f"{base}.{expr.attr}" if base else expr.attr
        return ""

    def _assign_targets(self, targets: List[ast.AST]) -> List[str]:
        out = []
        for t in targets:
            if isinstance(t, ast.Name):
                out.append(t.id)
            elif isinstance(t, ast.Attribute):
                out.append(self._dotted_name(t))
        return out

    def _node_matches(self, node: ast.AST, kind: str, name: str) -> bool:
        name_lower = name.lower()

        if kind == "Call":
            if not isinstance(node, ast.Call):
                return False
            dotted = self._dotted_name(node.func)
            if not dotted:
                return False
            return dotted == name or dotted.lower() == name_lower or dotted.split(".")[-1].lower() == name_lower

        if kind == "Import":
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                return False
            if isinstance(node, ast.Import):
                return any(a.name == name for a in node.names)
            return (node.module or "") == name

        if kind == "Assign":
            if not isinstance(node, ast.Assign):
                return False
            targets = self._assign_targets(node.targets)
            return any(t.lower() == name_lower or t.split(".")[-1].lower() == name_lower for t in targets)

        if kind == "Attribute":
            if not isinstance(node, ast.Attribute):
                return False
            dotted = self._dotted_name(node)
            return dotted == name or dotted.lower() == name_lower

        return False


class SecurityAnalyzer:
    def __init__(self, rules: Optional[List[VulnerabilityRule]] = None):
        self.rules = rules or VULNERABILITY_RULES
        self.pattern_analyzer = PatternAnalyzer()
        self.ast_analyzer = ASTAnalyzer()

    def analyze_file(self, file_path: str) -> AnalysisResult:
        import time
        t0 = time.time()

        path = Path(file_path)
        result = AnalysisResult(
            target_file=str(path),
            file_size_bytes=path.stat().st_size if path.exists() else 0,
            total_lines=0,
        )

        if not path.exists():
            result.errors.append(f"File not found: {file_path}")
            return result

        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            result.errors.append(f"Could not read file: {e}")
            return result

        source_lines = source.splitlines()
        result.total_lines = len(source_lines)

        seen_fingerprints: set = set()
        all_findings: List[Finding] = []

        for rule in self.rules:
            for f in self.pattern_analyzer.scan(source_lines, rule, str(path)):
                if f.fingerprint not in seen_fingerprints:
                    seen_fingerprints.add(f.fingerprint)
                    all_findings.append(f)
            for f in self.ast_analyzer.scan(source, rule, str(path)):
                if f.fingerprint not in seen_fingerprints:
                    seen_fingerprints.add(f.fingerprint)
                    all_findings.append(f)

        all_findings.sort(
            key=lambda x: (SEVERITY_ORDER.get(x.severity, 99), x.line_number)
        )
        result.findings = all_findings
        result.scan_duration_ms = (time.time() - t0) * 1000
        return result

    def analyze_directory(self, dir_path: str,
                          extensions: Tuple[str, ...] = (".py",)) -> List[AnalysisResult]:
        results = []
        for root, _, files in os.walk(dir_path):
            for fname in files:
                if any(fname.endswith(ext) for ext in extensions):
                    fp = os.path.join(root, fname)
                    results.append(self.analyze_file(fp))
        return results

