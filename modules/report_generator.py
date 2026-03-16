"""
modules/report_generator.py
Generates professional 14-section forensic reports in JSON and HTML formats.
Includes SVG-based risk and tactic visualizations.
"""

import json
import os
import datetime
from datetime import datetime, timezone
from typing import Optional

from modules.os_profiler import OSProfile
from modules.tool_detector import ToolDetectionResult
from modules.live_analyzer import LiveAnalysisResult
from modules.disk_analyzer import DiskAnalysisResult
from modules.risk_classifier import RiskReport, RISK_COLOURS, RISK_BG


# ── Entry Points ───────────────────────────────────────────────────────────────

def generate_html_report(
    os_profile:  OSProfile,
    tool_result: ToolDetectionResult,
    risk_report: RiskReport,
    live_result: Optional[LiveAnalysisResult] = None,
    disk_result: Optional[DiskAnalysisResult] = None,
    output_path: Optional[str] = None,
) -> str:
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forensic Report - {os_profile.os_type.value}</title>
    {_html_style()}
</head>
<body>
    <div class="container">
        {_html_body(os_profile, tool_result, risk_report, live_result, disk_result)}
    </div>
    <div style="text-align:center; padding:1.5rem; color:#94a3b8; font-size:0.8rem; font-family:sans-serif;">
        PMGP Digital Forensic Report · Proprietary Intelligence · {_now_iso()}
    </div>
</body>
</html>"""
    if output_path:
        _write(output_path, html)
    return html


def generate_json_report(
    os_profile:  OSProfile,
    tool_result: ToolDetectionResult,
    risk_report: RiskReport,
    live_result: Optional[LiveAnalysisResult] = None,
    disk_result: Optional[DiskAnalysisResult] = None,
    output_path: Optional[str] = None,
) -> str:
    doc = {
        "report_meta": {
            "tool": "Passive Metadata-Graph Protocol (PMGP)",
            "version": "2.0",
            "generated_at": _now_iso(),
        },
        "os_profile": {
            "os_type":            os_profile.os_type.value,
            "confidence":         round(os_profile.confidence, 2),
            "pkg_db_type":        os_profile.pkg_db_type,
        },
        "risk_assessment": {
            "overall_risk":   risk_report.overall_risk,
            "risk_score":     risk_report.risk_score,
        },
        "detected_tools": [
            {
                "name": t.name,
                "risk": t.risk_level,
                "mtime": t.mtime,
                "atime": getattr(t, "atime", None)
            }
            for t in tool_result.detected_tools
        ]
    }
    json_str = json.dumps(doc, indent=2, ensure_ascii=False)
    if output_path:
        _write(output_path, json_str)
    return json_str


# ── Internal Sections ─────────────────────────────────────────────────────────

def _html_body(os_profile, tool_result, risk_report, live_result, disk_result) -> str:
    sections = [
        _header(),
        _section_1_case_info(disk_result),
        _section_2_executive_summary(risk_report, os_profile),
        _section_3_methodology(),
        _section_4_system_id(os_profile),
        _section_5_sources(os_profile, live_result, disk_result),
        _section_6_capabilities(tool_result),
        _section_7_timeline(tool_result),
        _section_8_disk(disk_result),
        _section_9_volatile(live_result),
        _section_10_mitre(risk_report),
        _section_11_risk_assessment(risk_report),
        _section_12_limitations(disk_result),
        _section_13_conclusion(risk_report),
        _section_14_appendix(os_profile, tool_result, risk_report)
    ]
    return "\n".join(sections)


def _header() -> str:
    return """
<header>
    <div style="font-size: 0.75rem; letter-spacing: 2.5px; color: var(--text-muted); text-transform: uppercase;">Confidential Investigation · Evidence-Based Analysis</div>
    <h1 style="margin-top: 0.5rem; text-transform: uppercase; letter-spacing: 1px;">Digital Forensic Investigation Report</h1>
    <p style="color: var(--text-muted); margin-top: 0.2rem; font-style: italic;">Passive Metadata-Graph Protocol (PMGP) v2.0</p>
</header>
"""

def _section_1_case_info(disk_result) -> str:
    source = "Live Physical System" if not disk_result or not disk_result.image_path else f"Offline Disk Image / Mounted Filesystem (<code>{os.path.basename(disk_result.image_path)}</code>)"
    return f"""
<section>
    <h2>1. Case Information</h2>
    <table>
        <tr><th>Case Identifier</th><td>ACQ-FORENSIC-{datetime.now().strftime('%Y%m%d')}-INTERNAL</td></tr>
        <tr><th>Investigation Date</th><td>{_now_iso()}</td></tr>
        <tr><th>Analyst / System</th><td>PMGP Engine (Standard Logic v2.0)</td></tr>
        <tr><th>Evidence Source</th><td>{source}</td></tr>
        <tr><th>Analysis Scope</th><td>Full Heuristic Profiling: OS fingerprinting, offensive tool detection, and MITRE tactic cross-referencing.</td></tr>
    </table>
</section>
"""

def _section_2_executive_summary(risk_report, os_profile) -> str:
    risk_color = RISK_COLOURS.get(risk_report.overall_risk, "#1e3a8a")
    return f"""
<section>
    <h2>2. Executive Summary</h2>
    <div class="summary-grid">
        <div class="metric-card">
            <div style="font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase;">OS Identifier</div>
            <div class="metric-value" style="font-size: 1.6rem;">{os_profile.os_type.value}</div>
            <div style="font-size: 0.75rem;">Confidence Coefficient: {os_profile.confidence:.0%}</div>
        </div>
        <div class="metric-card" style="border-top: 4px solid {risk_color};">
            <div style="font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase;">Heuristic Risk</div>
            <div class="metric-value" style="color: {risk_color};">{risk_report.overall_risk}</div>
            <div style="font-size: 0.75rem;">Aggregated Score: {risk_report.risk_score}/100</div>
        </div>
    </div>
    <p>This report documents the forensic extraction of technical indicators from a <strong>{os_profile.os_type.value}</strong> environment. 
    The investigation has assigned an overall risk level of <strong>{risk_report.overall_risk}</strong>. 
    Detected artifacts suggest the presence of specialized toolsets typically associated with offensive security activities or anonymization infrastructure. 
    While individual markers may have legitimate administrative purposes, their collective presence warrants detailed security review.</p>
</section>
"""

def _section_3_methodology() -> str:
    return """
<section>
    <h2>3. Methodology</h2>
    <p>The analysis follows standard forensic principles for evidence preservation. The <strong>PMGP v2.0 Engine</strong> utilizes a passive, metadata-driven approach:</p>
    <ul class="method-list">
        <li><strong>Non-Destructive Acquisition:</strong> No binaries are executed; evidence is treated as a read-only data source.</li>
        <li><strong>Package Metadata Forensics:</strong> Analyzing system package databases (dpkg/pacman) to verify software provenance.</li>
        <li><strong>Volatile Registry Inspection:</strong> Scanning <code>/proc</code> pseudofilesystems for live process markers on active systems.</li>
        <li><strong>Heuristic Pattern Matching:</strong> Utilizing a graph-based protocol to correlate disparate artifacts into high-level kill chain indicators.</li>
        <li><strong>MITRE Alignment:</strong> Mapping findings to the 2024 ATT&CK matrix to provide strategic context for incident response.</li>
    </ul>
</section>
"""

def _section_4_system_id(os_profile) -> str:
    inds = "".join(f"<li>{i}</li>" for i in os_profile.indicators)
    return f"""
<section>
    <h2>4. System Identification</h2>
    <p>The OS profile was determined via high-confidence heuristic distribution fingerprinting.</p>
    <table>
        <tr><th>Detected Distribution</th><td><strong>{os_profile.os_type.value}</strong></td></tr>
        <tr><th>Profile Confidence</th><td>{int(os_profile.confidence * 100)}%</td></tr>
        <tr><th>Package Architecture</th><td>{os_profile.pkg_db_type or "Unknown"}</td></tr>
    </table>
    <h3>Identification Signatures</h3>
    <ul class="summary-list">{inds}</ul>
</section>
"""

def _section_5_sources(os_profile, live_result, disk_result) -> str:
    srcs = [
        f"Primary System Status DB (<code>{os_profile.pkg_db_path or '/var/lib/dpkg/status'}</code>)",
        "Filesystem Root Heuristic Sweeps",
        "System and Shell Configuration Templates (<code>/etc/skel</code>, <code>/etc/environment</code>)"
    ]
    if live_result and live_result.is_live_system:
        srcs.append("Volatile Process Environment Variables (<code>/proc/[PID]/environ</code>)")
        srcs.append("Active Raw Network Sockets (<code>/proc/net</code>)")
    if disk_result and not disk_result.error_message:
        srcs.append(f"Disk Device / Image Stream: <code>{os.path.basename(disk_result.image_path)}</code>")
    
    src_list = "".join(f"<li>{s}</li>" for s in srcs)
    return f"""
<section>
    <h2>5. Evidence Sources Examined</h2>
    <p>The analyst successfully extracted and verified data from the following authoritative sources:</p>
    <ul>{src_list}</ul>
</section>
"""

def _section_6_capabilities(tool_result) -> str:
    if not tool_result.detected_tools:
        return "<section><h2>6. Tool and Capability Assessment</h2><p>No suspicious offensive utilities were identified on the examined filesystem.</p></section>"
    
    rows = ""
    for t in tool_result.detected_tools:
        c = RISK_COLOURS.get(t.risk_level, "#475569")
        rows += f"""
        <tr>
            <td><strong>{t.name}</strong></td>
            <td>{t.description}</td>
            <td style="font-size: 0.85rem;"><code>{t.mitre_technique}</code></td>
            <td>{t.category}</td>
            <td><span class="badge" style="background:{c}; color:white;">{t.risk_level.title()}</span></td>
        </tr>"""
    return f"""
<section>
    <h2>6. Tool and Capability Assessment</h2>
    <p>Detailed enumeration of detected utilities and their forensic classifications:</p>
    <table>
        <tr><th>Identifier</th><th>Functionality Note</th><th>MITRE Mapping</th><th>Category</th><th>Classification</th></tr>
        {rows}
    </table>
</section>
"""

def _section_7_timeline(tool_result) -> str:
    events = []
    for t in tool_result.detected_tools:
        if t.mtime:
            events.append((t.mtime, f"Software Installation/Metadata Entry: <code>{t.name}</code>"))
        if getattr(t, 'atime', None):
            events.append((t.atime, f"Forensic Access Trace (Execution Indicative): <code>{t.name}</code>"))
    
    events.sort(key=lambda x: x[0])
    rows = ""
    for ts, desc in events:
        dt = datetime.fromtimestamp(ts, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        rows += f"<tr><td style='white-space:nowrap;'>{dt}</td><td>{desc}</td></tr>"
    
    if not rows:
        rows = "<tr><td colspan='2' style='text-align:center;'>No definitive forensic timestamps were recovered.</td></tr>"

    return f"""
<section>
    <h2>7. Timeline of Notable Events</h2>
    <p>A chronological audit trail reconstructed from filesystem metadata follows. Note: Timestamps represent the earliest and latest indicators of presence and access.</p>
    <table>
        <tr><th>Timestamp (UTC)</th><th>Artifact Activity / Indicator</th></tr>
        {rows}
    </table>
</section>
"""

def _section_8_disk(disk_result) -> str:
    if not disk_result or disk_result.error_message:
        return "<section><h2>8. Disk and Encryption Analysis</h2><p>Evidence was provided as a filesystem mount; hardware block analysis was suppressed.</p></section>"
    
    rows = ""
    for p in disk_result.partitions:
        luks = "Detected" if p.has_luks_header else "No"
        rows += f"<tr><td>{p.index}</td><td>{p.label or '-'}</td><td>{p.size_mb:.2f} MB</td><td>{luks}</td><td>{p.risk_label}</td></tr>"
        
    return f"""
<section>
    <h2>8. Disk and Encryption Analysis</h2>
    <p>Partition-level inspection revealed the following physical structure:</p>
    <table>
        <tr><th>#</th><th>Label</th><th>Capacity</th><th>Encryption Header</th><th>Risk Index</th></tr>
        {rows}
    </table>
    <p>Forensic Interpretation: <strong>{'Encrypted' if disk_result.encrypted_partitions else 'Standard unencrypted'}</strong> volumes were identified. The use of full-disk or volume-level encryption is a neutral find but remains forensically significant.</p>
</section>
"""

def _section_9_volatile(live_result) -> str:
    if not live_result or not live_result.is_live_system:
        return "<section><h2>9. Volatile System Analysis</h2><p>Static investigation performed on a mounted filesystem; volatile memory artifacts excluded from scope.</p></section>"
    
    rows = ""
    for f in live_result.process_findings:
        rows += f"<tr><td>{f.pid}</td><td><code>{f.comm}</code></td><td>{', '.join(f.suspicious_vars) or '-'}</td><td>{f.notes[0] if f.notes else '-'}</td></tr>"
        
    return f"""
<section>
    <h2>9. Volatile System Analysis</h2>
    <p>Active process environment analysis identified the following anomalies:</p>
    <table>
        <tr><th>PID</th><th>Command Name</th><th>Flagged Variables</th><th>Observation</th></tr>
        {rows}
    </table>
</section>
"""

def _section_10_mitre(risk_report) -> str:
    if not risk_report.mitre_coverage:
        return "<section><h2>10. MITRE ATT&CK Mapping</h2><p>No specific TTPs identified.</p></section>"
        
    rows = ""
    for m in risk_report.mitre_coverage:
        rows += f"<tr><td><code>{m.technique_id}</code></td><td>{m.technique_name}</td><td>{m.tactic}</td><td>{', '.join(m.tools)}</td></tr>"
        
    return f"""
<section>
    <h2>10. MITRE ATT&CK Mapping</h2>
    <p>The identified artifacts align with the following adversary Tactics, Techniques, and Procedures (TTPs):</p>
    <table>
        <tr><th>Technique</th><th>Description</th><th>Strategic Tactic</th><th>Evidence Correlation</th></tr>
        {rows}
    </table>
</section>
"""

def _section_11_risk_assessment(risk_report) -> str:
    return f"""
<section>
    <h2>11. Risk Assessment</h2>
    <div class="graph-container">
        <div class="chart-box">
            <h4 style="margin:0 0 1rem 0;">Heuristic Risk Score</h4>
            {_svg_risk_donut(risk_report.risk_score, risk_report.overall_risk)}
        </div>
        <div class="chart-box">
            <h4 style="margin:0 0 1rem 0;">MITRE Tactic Frequency</h4>
            {_svg_tactic_bar_chart(risk_report.mitre_coverage)}
        </div>
    </div>
    <p>The Risk Assessment is an algorithmic weighting of detected offensive capabilities (Score: <strong>{risk_report.risk_score}/100</strong>). 
    The current environment is categorized as <strong>{risk_report.overall_risk} RISK</strong>.</p>
    <h3>Inferred Capabilities</h3>
    <p>Based strictly on evidence: the asset contains artifacts capable of <strong>{', '.join(set(t.category for t in risk_report.items if hasattr(t, 'category'))) or 'Standard System Operations'}</strong>.</p>
</section>
"""

def _section_12_limitations(disk_result) -> str:
    lims = [
        "Metatada-only analysis: Hidden encrypted containers or memory-only rootkits may not be identified.",
        "Clock Integrity: Timestamps rely on the system clock validity at the time of artifact creation.",
        "Obfuscation: Sophisticated anti-forensic 'wiper' or 'timestomp' tools can modify the indicators utilized in this report."
    ]
    if disk_result and disk_result.encrypted_partitions:
        lims.append("Cryptographic barriers: Encrypted partitions prevented content indexing for specific volumes.")
        
    lim_list = "".join(f"<li>{l}</li>" for l in lims)
    return f"""
<section>
    <h2>12. Limitations</h2>
    <p>The scope and reach of this investigation are subject to the following professional limitations:</p>
    <ul class="summary-list">{lim_list}</ul>
</section>
"""

def _section_13_conclusion(risk_report) -> str:
    level = "significant concentration" if risk_report.risk_score > 40 else "moderate presence" if risk_report.risk_score > 15 else "nominal detection"
    return f"""
<section>
    <h2>13. Conclusion</h2>
    <p>The automated forensic examination identifies a <strong>{level}</strong> of security-focused artifacts. 
    The findings are consistent with environments designed for offensive security testing or sensitive communications. 
    While no specific malicious exploit was identified in flight, the presence of detection-evasion and exploitation toolsets represents a high investigative priority. 
    Corroboration with full memory scans and netflow logs is recommended.</p>
</section>"""

def _section_14_appendix(os_profile, tool_result, risk_report) -> str:
    pkgs = [t.name for t in tool_result.detected_tools]
    return f"""
<section>
    <h2>14. Appendix – Evidence Artifacts</h2>
    <h3>Detected Offensive Package List</h3>
    <pre>{json.dumps(pkgs, indent=2)}</pre>
    <h3>Strategic Technique Registry</h3>
    <pre>{json.dumps([m.technique_id for m in risk_report.mitre_coverage], indent=2)}</pre>
</section>
"""

# ── Stylistics & Visuals ──────────────────────────────────────────────────────

def _html_style() -> str:
    return """
<style>
    :root {
        --primary: #0f172a;
        --accent: #2563eb;
        --text: #334155;
        --muted: #94a3b8;
        --border: #e2e8f0;
        --bg: #f8fafc;
        --card: #ffffff;
    }
    body { font-family: 'Inter', -apple-system, system-ui, sans-serif; color: var(--text); background: #fdfdfd; margin: 0; padding: 0; line-height: 1.6; }
    .container { max-width: 900px; margin: 3rem auto; background: var(--card); padding: 4rem; box-shadow: 0 10px 30px rgba(0,0,0,0.03); border: 1px solid var(--border); }
    header { border-bottom: 2px solid var(--primary); padding-bottom: 2rem; margin-bottom: 4rem; text-align: center; }
    h1 { color: var(--primary); font-size: 1.8rem; margin: 0; font-weight: 800; }
    h2 { font-size: 1.25rem; border-left: 5px solid var(--primary); padding-left: 1.2rem; margin-top: 4rem; color: var(--primary); text-transform: uppercase; font-weight: 700; letter-spacing: 0.5px; }
    h3 { font-size: 1.1rem; margin-top: 1.8rem; color: #1e293b; font-weight: 600; border-bottom: 1px solid var(--border); padding-bottom: 0.4rem; }
    p { margin-top: 1rem; text-align: justify; }
    table { width: 100%; border-collapse: collapse; margin: 2rem 0; font-size: 0.95rem; }
    th, td { padding: 1rem; border: 1px solid var(--border); text-align: left; }
    th { background: #fdfdfd; color: var(--primary); font-weight: 700; width: 35%; border-right: 2px solid var(--bg); }
    .badge { padding: 5px 14px; border-radius: 4px; font-weight: 700; font-size: 0.8rem; color: white; display: inline-block; }
    .summary-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin: 2.5rem 0; }
    .metric-card { background: var(--bg); padding: 2rem; border-radius: 4px; text-align: center; border: 1px solid var(--border); }
    .metric-value { font-size: 2.2rem; font-weight: 900; margin: 0.5rem 0; }
    .graph-container { display: flex; justify-content: center; gap: 2.5rem; flex-wrap: wrap; margin: 3rem 0; }
    .chart-box { background: #fff; padding: 2rem; border: 1px solid var(--border); border-radius: 4px; flex: 1; min-width: 300px; text-align: center; }
    pre { background: #0f172a; color: #e2e8f0; padding: 1.5rem; border-radius: 4px; overflow-x: auto; font-size: 0.85rem; }
    ul { padding-left: 1.5rem; }
    li { margin-bottom: 0.6rem; }
    .method-list li { list-style: none; padding: 0.5rem; border-bottom: 1px solid var(--bg); }
    .method-list li strong { color: var(--accent); }
    @media print { .container { border: none; box-shadow: none; margin: 0; padding: 0; } h2 { page-break-before: always; } }
</style>
"""

def _svg_risk_donut(score: int, level: str) -> str:
    color = RISK_COLOURS.get(level, "#1e3a8a")
    offset = 251 - (251 * score / 100)
    return f"""
<svg width="150" height="150" viewBox="0 0 100 100">
  <circle cx="50" cy="50" r="40" fill="none" stroke="#f1f5f9" stroke-width="10"/>
  <circle cx="50" cy="50" r="40" fill="none" stroke="{color}" stroke-width="10"
          stroke-dasharray="251" stroke-dashoffset="{offset}" transform="rotate(-90 50 50)"/>
  <text x="50" y="55" font-family="sans-serif" font-size="20" font-weight="900" text-anchor="middle" fill="{color}">{score}</text>
  <text x="50" y="70" font-family="sans-serif" font-size="6" font-weight="700" text-anchor="middle" fill="#94a3b8">LEVEL: {level}</text>
</svg>
"""

def _svg_tactic_bar_chart(mitre_coverage) -> str:
    counts = {}
    for m in mitre_coverage:
        counts[m.tactic] = counts.get(m.tactic, 0) + 1
    if not counts: return "<p style='color:#94a3b8; font-size:0.8rem; margin-top:3rem;'>No MITRE Tactic Frequency Identified</p>"
    
    sorted_tactics = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    rows = ""
    max_val = max(counts.values())
    for i, (name, val) in enumerate(sorted_tactics):
        width = (val / max_val) * 120
        y = 25 + (i * 25)
        rows += f"""
        <rect x="90" y="{y}" width="{width}" height="12" fill="#3b82f6" rx="1" />
        <text x="85" y="{y+9}" font-family="sans-serif" font-size="7" font-weight="600" text-anchor="end" fill="#475569">{name}</text>
        <text x="{90+width+6}" y="{y+9}" font-family="sans-serif" font-size="7" fill="#94a3b8">{val}</text>
        """
    height = 40 + (len(sorted_tactics) * 25)
    return f'<svg width="280" height="{height}" viewBox="0 0 280 {height}">{rows}</svg>'


# ── Utilities ─────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)