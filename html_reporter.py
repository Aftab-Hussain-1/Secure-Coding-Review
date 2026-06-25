"""
HTML Report Generator
=====================
Produces a self-contained, interactive HTML security audit report.
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Any
from collections import defaultdict
from pathlib import Path

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.analyzer import AnalysisResult, Finding
from rules.vulnerability_rules import SEVERITY_COLORS


def _severity_badge(sev: str) -> str:
    color = SEVERITY_COLORS.get(sev, "#6b7280")
    return f'<span class="badge" style="background:{color}">{sev}</span>'


def generate_html_report(results: List[AnalysisResult], output_path: str) -> str:
    all_findings: List[Finding] = []
    for r in results:
        all_findings.extend(r.findings)

    total_files = len(results)
    total_findings = len(all_findings)
    total_lines = sum(r.total_lines for r in results)

    sev_counts = defaultdict(int)
    for f in all_findings:
        sev_counts[f.severity] += 1

    cat_counts = defaultdict(int)
    for f in all_findings:
        cat_counts[f.category] += 1

    # Composite risk
    weights = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 4, "LOW": 1}
    raw_score = sum(weights.get(f.severity, 0) for f in all_findings)
    risk_score = min(100, raw_score)
    if risk_score == 0:   grade = "A"
    elif risk_score <= 10: grade = "B"
    elif risk_score <= 30: grade = "C"
    elif risk_score <= 60: grade = "D"
    else:                  grade = "F"

    grade_color = {"A": "#16a34a", "B": "#65a30d", "C": "#ca8a04",
                   "D": "#ea580c", "F": "#dc2626"}.get(grade, "#6b7280")

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build findings rows
    findings_rows = ""
    for i, f in enumerate(all_findings):
        color = SEVERITY_COLORS.get(f.severity, "#6b7280")
        refs_html = " ".join(
            f'<a href="{r}" target="_blank" class="ref-link">{r.split("/")[2]}</a>'
            for r in f.references
        )
        findings_rows += f"""
        <tr class="finding-row" data-severity="{f.severity}" data-category="{f.category}">
          <td><span class="badge" style="background:{color}">{f.severity}</span></td>
          <td><span class="rule-id">{f.rule_id}</span></td>
          <td class="finding-name" onclick="toggleDetail('detail-{i}')">{f.rule_name} ▾</td>
          <td>{f.category}</td>
          <td class="cwe-tag">{f.cwe_id}</td>
          <td class="file-path">{os.path.basename(f.file_path)}:{f.line_number}</td>
          <td><span class="conf-{f.confidence.lower()}">{f.confidence}</span></td>
        </tr>
        <tr id="detail-{i}" class="detail-row hidden">
          <td colspan="7">
            <div class="detail-box">
              <div class="detail-grid">
                <div class="detail-section">
                  <h4>📋 Description</h4>
                  <p>{f.description}</p>
                  <h4>📍 Vulnerable Code (line {f.line_number})</h4>
                  <pre class="code-bad"><code>{f.line_content.strip()}</code></pre>
                </div>
                <div class="detail-section">
                  <h4>🔴 Vulnerable Pattern</h4>
                  <pre class="code-bad"><code>{f.example_bad}</code></pre>
                  <h4>✅ Secure Alternative</h4>
                  <pre class="code-good"><code>{f.example_good}</code></pre>
                </div>
              </div>
              <h4>🛠️ Remediation Steps</h4>
              <pre class="remediation">{f.remediation}</pre>
              <h4>📚 References</h4>
              <div class="refs">{refs_html}</div>
              <div class="owasp-tag">OWASP: {f.owasp_category}</div>
            </div>
          </td>
        </tr>
        """

    # Severity chart data
    chart_data = json.dumps({
        "labels": list(sev_counts.keys()),
        "values": list(sev_counts.values()),
        "colors": [SEVERITY_COLORS.get(s, "#999") for s in sev_counts.keys()],
    })
    cat_data = json.dumps({
        "labels": list(cat_counts.keys()),
        "values": list(cat_counts.values()),
    })

    # Category breakdown table
    cat_rows = ""
    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
        cat_rows += f"<tr><td>{cat}</td><td>{count}</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Audit Report — {scan_time}</title>
<style>
  :root {{
    --bg: #0f1117;
    --surface: #1a1d27;
    --surface2: #242838;
    --border: #2d3148;
    --text: #e2e8f0;
    --text-muted: #8892b0;
    --accent: #7c3aed;
    --accent2: #06b6d4;
    --font-mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
    --font-sans: 'Inter', system-ui, -apple-system, sans-serif;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-sans);
    line-height: 1.6;
  }}

  /* ── HEADER ── */
  .header {{
    background: linear-gradient(135deg, #1a1d27 0%, #0f1117 50%, #1a0a2e 100%);
    border-bottom: 1px solid var(--border);
    padding: 2.5rem 3rem;
    position: relative;
    overflow: hidden;
  }}
  .header::before {{
    content: '';
    position: absolute; inset: 0;
    background: radial-gradient(ellipse at 70% 50%, rgba(124,58,237,.15) 0%, transparent 60%);
    pointer-events: none;
  }}
  .header-inner {{
    max-width: 1200px;
    margin: 0 auto;
    display: flex;
    align-items: center;
    gap: 2rem;
  }}
  .shield-icon {{
    font-size: 3.5rem;
    filter: drop-shadow(0 0 16px rgba(124,58,237,.5));
  }}
  .header-text h1 {{
    font-size: 2rem;
    font-weight: 800;
    letter-spacing: -0.02em;
    background: linear-gradient(90deg, #c4b5fd, #67e8f9);
    background-clip: text;
    -webkit-background-clip: text;
    color: transparent;
    -webkit-text-fill-color: transparent;
  }}
  .header-text p {{
    color: var(--text-muted);
    margin-top: .25rem;
    font-size: .875rem;
  }}
  .header-meta {{
    margin-left: auto;
    text-align: right;
    font-size: .8rem;
    color: var(--text-muted);
    font-family: var(--font-mono);
  }}

  /* ── LAYOUT ── */
  .main {{ max-width: 1200px; margin: 0 auto; padding: 2rem 3rem; }}

  /* ── SCORE CARD ── */
  .score-grid {{
    display: grid;
    grid-template-columns: 200px 1fr;
    gap: 1.5rem;
    margin-bottom: 2rem;
  }}
  .grade-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 2rem;
    gap: .5rem;
  }}
  .grade-letter {{
    font-size: 5rem;
    font-weight: 900;
    color: {grade_color};
    line-height: 1;
    filter: drop-shadow(0 0 20px {grade_color}66);
  }}
  .grade-label {{ font-size: .75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: .1em; }}
  .risk-score {{ font-size: 1.1rem; font-weight: 700; color: {grade_color}; }}

  .stats-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
  }}
  .stat-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.25rem;
    text-align: center;
  }}
  .stat-card.critical {{ border-top: 3px solid #dc2626; }}
  .stat-card.high     {{ border-top: 3px solid #ea580c; }}
  .stat-card.medium   {{ border-top: 3px solid #ca8a04; }}
  .stat-card.info     {{ border-top: 3px solid #2563eb; }}
  .stat-number {{ font-size: 2.5rem; font-weight: 800; }}
  .stat-number.critical {{ color: #dc2626; }}
  .stat-number.high     {{ color: #ea580c; }}
  .stat-number.medium   {{ color: #ca8a04; }}
  .stat-number.info     {{ color: #2563eb; }}
  .stat-label {{ font-size: .75rem; color: var(--text-muted); margin-top: .25rem; text-transform: uppercase; letter-spacing: .08em; }}

  /* ── SECTION HEADERS ── */
  .section {{ margin-bottom: 2.5rem; }}
  .section-title {{
    font-size: 1rem;
    font-weight: 700;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: .1em;
    border-bottom: 1px solid var(--border);
    padding-bottom: .75rem;
    margin-bottom: 1.25rem;
  }}

  /* ── CHARTS ── */
  .charts-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1.5rem;
    margin-bottom: 2rem;
  }}
  .chart-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.5rem;
  }}
  .chart-card h3 {{ font-size: .85rem; color: var(--text-muted); margin-bottom: 1rem; text-transform: uppercase; letter-spacing: .08em; }}
  canvas {{ width: 100% !important; }}

  /* ── FILTERS ── */
  .filters {{
    display: flex;
    gap: .75rem;
    flex-wrap: wrap;
    margin-bottom: 1rem;
  }}
  .filter-btn {{
    background: var(--surface2);
    border: 1px solid var(--border);
    color: var(--text-muted);
    padding: .375rem 1rem;
    border-radius: 999px;
    font-size: .8rem;
    cursor: pointer;
    font-family: var(--font-sans);
    transition: all .15s;
  }}
  .filter-btn:hover, .filter-btn.active {{
    background: var(--accent);
    border-color: var(--accent);
    color: #fff;
  }}

  /* ── FINDINGS TABLE ── */
  .table-wrapper {{
    overflow-x: auto;
    border-radius: 12px;
    border: 1px solid var(--border);
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: .85rem;
  }}
  thead tr {{ background: var(--surface2); }}
  th {{
    padding: .875rem 1rem;
    text-align: left;
    font-size: .7rem;
    text-transform: uppercase;
    letter-spacing: .1em;
    color: var(--text-muted);
    white-space: nowrap;
  }}
  .finding-row td {{
    padding: .75rem 1rem;
    border-top: 1px solid var(--border);
    vertical-align: middle;
  }}
  .finding-row:hover td {{ background: var(--surface2); }}
  .finding-name {{
    cursor: pointer;
    font-weight: 600;
    color: var(--accent2);
  }}
  .finding-name:hover {{ text-decoration: underline; }}
  .file-path {{ font-family: var(--font-mono); font-size: .75rem; color: var(--text-muted); }}
  .rule-id {{ font-family: var(--font-mono); font-size: .7rem; color: var(--text-muted); }}
  .cwe-tag {{ font-family: var(--font-mono); font-size: .75rem; color: #c4b5fd; }}

  /* ── BADGES ── */
  .badge {{
    display: inline-block;
    padding: .2em .7em;
    border-radius: 999px;
    font-size: .7rem;
    font-weight: 700;
    color: #fff;
    text-transform: uppercase;
    letter-spacing: .06em;
  }}
  .conf-high   {{ color: #dc2626; font-weight: 700; font-size: .75rem; }}
  .conf-medium {{ color: #ca8a04; font-weight: 700; font-size: .75rem; }}
  .conf-low    {{ color: #6b7280; font-weight: 700; font-size: .75rem; }}

  /* ── DETAIL PANEL ── */
  .hidden {{ display: none; }}
  .detail-row td {{ padding: 0; border-top: none; }}
  .detail-box {{
    background: #0a0d16;
    border-top: 2px solid var(--accent);
    border-bottom: 1px solid var(--border);
    padding: 1.5rem 2rem;
  }}
  .detail-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 2rem;
    margin-bottom: 1rem;
  }}
  .detail-section h4 {{
    font-size: .75rem;
    text-transform: uppercase;
    letter-spacing: .1em;
    color: var(--text-muted);
    margin: 1rem 0 .4rem;
  }}
  .detail-section h4:first-child {{ margin-top: 0; }}
  .detail-section p {{ font-size: .85rem; color: var(--text); line-height: 1.7; }}
  pre.code-bad, pre.code-good, pre.remediation {{
    background: var(--surface);
    border-radius: 8px;
    padding: .75rem 1rem;
    font-family: var(--font-mono);
    font-size: .78rem;
    overflow-x: auto;
    line-height: 1.6;
    white-space: pre-wrap;
    word-break: break-word;
  }}
  pre.code-bad  {{ border-left: 3px solid #dc2626; }}
  pre.code-good {{ border-left: 3px solid #16a34a; }}
  pre.remediation {{ border-left: 3px solid var(--accent); color: var(--text-muted); }}
  .refs {{ display: flex; flex-wrap: wrap; gap: .5rem; margin-top: .5rem; }}
  .ref-link {{
    display: inline-block;
    background: var(--surface2);
    color: var(--accent2);
    padding: .25rem .75rem;
    border-radius: 999px;
    font-size: .75rem;
    text-decoration: none;
  }}
  .ref-link:hover {{ background: var(--border); }}
  .owasp-tag {{
    margin-top: .75rem;
    font-size: .75rem;
    color: var(--accent);
    font-family: var(--font-mono);
  }}

  /* ── CAT TABLE ── */
  .cat-table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
  .cat-table td {{ padding: .5rem .75rem; border-top: 1px solid var(--border); }}
  .cat-table tr:first-child td {{ border-top: none; }}

  /* ── FOOTER ── */
  .footer {{
    text-align: center;
    padding: 2rem;
    color: var(--text-muted);
    font-size: .75rem;
    border-top: 1px solid var(--border);
    margin-top: 3rem;
  }}

  @media (max-width: 768px) {{
    .main {{ padding: 1rem; }}
    .score-grid {{ grid-template-columns: 1fr; }}
    .stats-grid {{ grid-template-columns: 1fr 1fr; }}
    .charts-grid {{ grid-template-columns: 1fr; }}
    .detail-grid {{ grid-template-columns: 1fr; }}
  }}
</style>
</head>
<body>

<div class="header">
  <div class="header-inner">
    <div class="shield-icon">🛡️</div>
    <div class="header-text">
      <h1>Secure Code Audit Report</h1>
      <p>Python Static Security Analysis · {total_files} file(s) · {total_lines:,} lines scanned</p>
    </div>
    <div class="header-meta">
      Generated: {scan_time}<br>
      Engine: SecureAudit v1.0<br>
      Language: Python
    </div>
  </div>
</div>

<div class="main">

  <!-- RISK SCORE -->
  <div class="score-grid">
    <div class="grade-card">
      <div class="grade-label">Security Grade</div>
      <div class="grade-letter">{grade}</div>
      <div class="risk-score">Risk Score: {risk_score}/100</div>
    </div>
    <div class="stats-grid">
      <div class="stat-card critical">
        <div class="stat-number critical">{sev_counts.get('CRITICAL', 0)}</div>
        <div class="stat-label">Critical</div>
      </div>
      <div class="stat-card high">
        <div class="stat-number high">{sev_counts.get('HIGH', 0)}</div>
        <div class="stat-label">High</div>
      </div>
      <div class="stat-card medium">
        <div class="stat-number medium">{sev_counts.get('MEDIUM', 0)}</div>
        <div class="stat-label">Medium</div>
      </div>
      <div class="stat-card info">
        <div class="stat-number info">{total_findings}</div>
        <div class="stat-label">Total Findings</div>
      </div>
    </div>
  </div>

  <!-- CHARTS -->
  <div class="charts-grid">
    <div class="chart-card">
      <h3>Findings by Severity</h3>
      <canvas id="severityChart" height="220"></canvas>
    </div>
    <div class="chart-card">
      <h3>Findings by Category</h3>
      <canvas id="categoryChart" height="220"></canvas>
    </div>
  </div>

  <!-- FINDINGS TABLE -->
  <div class="section">
    <div class="section-title">Security Findings ({total_findings})</div>
    <div class="filters">
      <button class="filter-btn active" onclick="filterFindings('all', this)">All ({total_findings})</button>
      <button class="filter-btn" onclick="filterFindings('CRITICAL', this)">Critical ({sev_counts.get('CRITICAL', 0)})</button>
      <button class="filter-btn" onclick="filterFindings('HIGH', this)">High ({sev_counts.get('HIGH', 0)})</button>
      <button class="filter-btn" onclick="filterFindings('MEDIUM', this)">Medium ({sev_counts.get('MEDIUM', 0)})</button>
    </div>
    <div class="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Rule ID</th>
            <th>Vulnerability</th>
            <th>Category</th>
            <th>CWE</th>
            <th>Location</th>
            <th>Confidence</th>
          </tr>
        </thead>
        <tbody id="findingsBody">
          {findings_rows}
        </tbody>
      </table>
    </div>
  </div>

  <!-- CATEGORY BREAKDOWN -->
  <div class="section">
    <div class="section-title">Category Breakdown</div>
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:12px;overflow:hidden;">
      <table class="cat-table">
        <thead>
          <tr style="background:var(--surface2)">
            <th style="padding:.875rem 1rem;text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;color:var(--text-muted)">Category</th>
            <th style="padding:.875rem 1rem;text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;color:var(--text-muted)">Count</th>
          </tr>
        </thead>
        <tbody>{cat_rows}</tbody>
      </table>
    </div>
  </div>

  <!-- REMEDIATION CHECKLIST -->
  <div class="section">
    <div class="section-title">Remediation Priority Checklist</div>
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1.5rem;">
      <p style="font-size:.85rem;color:var(--text-muted);margin-bottom:1rem;">Address findings in this priority order:</p>
      <ol style="padding-left:1.5rem;font-size:.875rem;line-height:2;">
        <li><strong style="color:#dc2626">CRITICAL first:</strong> SQL Injection, Command Injection, Code Injection (eval), Insecure Deserialization</li>
        <li><strong style="color:#ea580c">HIGH next:</strong> XSS, Hardcoded Secrets, Weak Password Hashing, Path Traversal</li>
        <li><strong style="color:#ca8a04">MEDIUM then:</strong> Debug Mode, Open Redirect, Insecure Random, Information Disclosure</li>
        <li><strong style="color:#2563eb">LOW/INFO:</strong> Code quality issues, security best practice improvements</li>
      </ol>
    </div>
  </div>

</div>

<div class="footer">
  SecureAudit · Python Static Security Analysis Tool · {scan_time} ·
  Findings are potential vulnerabilities and require manual verification.
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<script>
const chartDefaults = {{
  plugins: {{
    legend: {{ labels: {{ color: '#8892b0', font: {{ size: 12 }} }} }},
  }},
  responsive: true,
  maintainAspectRatio: true,
}};

const sevData = {chart_data};
new Chart(document.getElementById('severityChart'), {{
  type: 'doughnut',
  data: {{
    labels: sevData.labels,
    datasets: [{{ data: sevData.values, backgroundColor: sevData.colors, borderWidth: 2, borderColor: '#1a1d27' }}]
  }},
  options: {{ ...chartDefaults, cutout: '60%' }}
}});

const catData = {cat_data};
new Chart(document.getElementById('categoryChart'), {{
  type: 'bar',
  data: {{
    labels: catData.labels,
    datasets: [{{
      data: catData.values,
      backgroundColor: '#7c3aed88',
      borderColor: '#7c3aed',
      borderWidth: 2,
      borderRadius: 6,
    }}]
  }},
  options: {{
    ...chartDefaults,
    scales: {{
      x: {{ ticks: {{ color: '#8892b0' }}, grid: {{ color: '#2d3148' }} }},
      y: {{ ticks: {{ color: '#8892b0', stepSize: 1 }}, grid: {{ color: '#2d3148' }}, beginAtZero: true }}
    }},
    plugins: {{ legend: {{ display: false }} }}
  }}
}});

function toggleDetail(id) {{
  const row = document.getElementById(id);
  row.classList.toggle('hidden');
}}

function filterFindings(severity, btn) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.finding-row').forEach(row => {{
    const isMatch = severity === 'all' || row.dataset.severity === severity;
    row.style.display = isMatch ? '' : 'none';
    // Also hide associated detail row
    const next = row.nextElementSibling;
    if (next && next.classList.contains('detail-row')) {{
      if (!isMatch) next.classList.add('hidden');
    }}
  }});
}}
</script>
</body>
</html>"""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    return output_path
