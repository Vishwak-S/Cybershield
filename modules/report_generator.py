"""
modules/report_generator.py
Generates structured forensic reports in JSON and HTML formats.
Output is self-contained – no external CSS/JS dependencies for HTML.
"""

import json
import os
from datetime import datetime, timezone
from typing import Optional

from modules.os_profiler import OSProfile
from modules.tool_detector import ToolDetectionResult
from modules.live_analyzer import LiveAnalysisResult
from modules.disk_analyzer import DiskAnalysisResult
from modules.risk_classifier import RiskReport, RISK_COLOURS, RISK_BG


# ── Public entry-points ───────────────────────────────────────────────────────

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
            "indicators":         os_profile.indicators,
            "pkg_db_type":        os_profile.pkg_db_type,
            "pkg_db_path":        os_profile.pkg_db_path,
            "tails_disk_confirmed": getattr(os_profile, "tails_disk_confirmed", False),
            "filesystem_artefacts": [
                {
                    "path":          a.path,
                    "type":          a.artefact_type,
                    "description":   a.description,
                    "risk_level":    a.risk_level,
                    "snippet":       a.snippet,
                }
                for a in os_profile.filesystem_artefacts
            ],
        },
        "risk_assessment": {
            "overall_risk": risk_report.overall_risk,
            "risk_score":   risk_report.risk_score,
            "summary":      risk_report.summary_lines,
            "kill_chains":  risk_report.kill_chains,
        },
        "detected_tools": [
            {
                "name":             t.name,
                "risk_level":       t.risk_level,
                "matched_package":  t.matched_package,
                "description":      t.description,
                "mitre_technique":  t.mitre_technique,
                "category":         t.category,
                "detection_method": t.detection_method,
            }
            for t in tool_result.detected_tools
        ],
        "mitre_coverage": [
            {
                "technique_id":   m.technique_id,
                "technique_name": m.technique_name,
                "tactic":         m.tactic,
                "tools":          m.tools,
            }
            for m in risk_report.mitre_coverage
        ],
        "risk_items": [
            {
                "source":          r.source,
                "risk_level":      r.risk_level,
                "title":           r.title,
                "description":     r.description,
                "mitre_technique": r.mitre_technique,
                "mitre_category":  r.mitre_category,
                "evidence":        r.evidence,
            }
            for r in risk_report.items
        ],
    }

    if live_result:
        doc["live_analysis"] = {
            "is_live_system":          live_result.is_live_system,
            "total_processes_scanned": live_result.total_processes_scanned,
            "suspicious_connections":  len(live_result.suspicious_connections),
            "findings": [
                {
                    "pid":             pf.pid,
                    "comm":            pf.comm,
                    "cmdline":         pf.cmdline,
                    "suspicious_vars": pf.suspicious_vars,
                    "attacker_ips":    pf.attacker_ips,
                    "suspicious_paths":pf.suspicious_paths,
                    "suspicious_maps": pf.suspicious_maps,
                    "cmdline_matches": [
                        {"note": n, "technique": t, "category": c}
                        for n, t, c in pf.cmdline_matches
                    ],
                    "notes":           pf.notes,
                }
                for pf in live_result.process_findings
            ],
            "network_connections": [
                {
                    "protocol":    c.protocol,
                    "local":       f"{c.local_addr}:{c.local_port}",
                    "remote":      f"{c.remote_addr}:{c.remote_port}",
                    "state":       c.state,
                    "suspicious":  c in live_result.suspicious_connections,
                }
                for c in live_result.network_connections[:200]  # cap at 200
            ],
        }

    if disk_result:
        doc["disk_analysis"] = {
            "image_path":   disk_result.image_path,
            "has_gpt":      disk_result.has_gpt,
            "has_mbr":      disk_result.has_mbr,
            "tails_data_found": disk_result.tails_data_found,
            "partitions": [
                {
                    "index":           p.index,
                    "label":           p.label,
                    "size_mb":         p.size_mb,
                    "has_luks_header": p.has_luks_header,
                    "luks_version":    p.luks_version,
                    "risk_label":      p.risk_label,
                    "risk_note":       p.risk_note,
                }
                for p in disk_result.partitions
            ],
            "notes": disk_result.notes,
        }

    json_str = json.dumps(doc, indent=2, ensure_ascii=False)
    if output_path:
        _write(output_path, json_str)
    return json_str


def generate_html_report(
    os_profile:  OSProfile,
    tool_result: ToolDetectionResult,
    risk_report: RiskReport,
    live_result: Optional[LiveAnalysisResult] = None,
    disk_result: Optional[DiskAnalysisResult] = None,
    output_path: Optional[str] = None,
) -> str:
    body = _html_body(os_profile, tool_result, risk_report, live_result, disk_result)
    html = _wrap_html(body)
    if output_path:
        _write(output_path, html)
    return html


# ── HTML builders ─────────────────────────────────────────────────────────────

def _html_body(os_profile, tool_result, risk_report, live_result, disk_result) -> str:
    parts = [
        _section_header(os_profile, risk_report),
        _section_summary(risk_report),
        _section_os(os_profile),
        _section_tools(tool_result),
        _section_mitre(risk_report),
    ]
    if os_profile.filesystem_artefacts:
        parts.append(_section_artefacts(os_profile))
    if live_result and live_result.is_live_system:
        parts.append(_section_live(live_result))
    if disk_result and not disk_result.error_message:
        parts.append(_section_disk(disk_result))
    if risk_report.kill_chains:
        parts.append(_section_kill_chains(risk_report))
    parts.append(_section_risk_items(risk_report))
    return "\n".join(parts)


def _section_header(os_profile, risk_report) -> str:
    colour = RISK_COLOURS.get(risk_report.overall_risk, "#333")
    return f"""
<div class="report-header">
  <h1>🔍 PMGP Forensic Report</h1>
  <p class="subtitle">Passive Metadata-Graph Protocol v2.0 · {_now_iso()}</p>
  <div class="badge" style="background:{colour}">
    {risk_report.overall_risk} RISK — Score: {risk_report.risk_score}/100
  </div>
</div>"""


def _section_summary(risk_report) -> str:
    lines = "".join(f"<li>{l}</li>" for l in risk_report.summary_lines)
    chains = ""
    if risk_report.kill_chains:
        chain_list = "".join(f"<li>⚠ {c}</li>" for c in risk_report.kill_chains)
        chains = f"<h3 style='color:#d32f2f'>Kill Chain Patterns Detected</h3><ul>{chain_list}</ul>"
    return f"""
<section>
  <h2>Executive Summary</h2>
  <ul class="summary-list">{lines}</ul>
  {chains}
</section>"""


def _section_os(os_profile) -> str:
    indicators = "".join(f"<li>{i}</li>" for i in os_profile.indicators)
    conf_pct   = int(os_profile.confidence * 100)
    disk_badge = (
        "<span style='color:#d32f2f;font-weight:bold'> ✔ Confirmed by disk analysis</span>"
        if getattr(os_profile, "tails_disk_confirmed", False) else ""
    )
    return f"""
<section>
  <h2>Operating System Profile</h2>
  <table>
    <tr><th>OS Type</th><td><strong>{os_profile.os_type.value}</strong>{disk_badge}</td></tr>
    <tr><th>Confidence</th><td>
      <div class="progress-bar">
        <div class="progress-fill" style="width:{conf_pct}%"></div>
        <span>{conf_pct}%</span>
      </div>
    </td></tr>
    <tr><th>Package DB</th><td>{os_profile.pkg_db_type} — {os_profile.pkg_db_path or 'N/A'}</td></tr>
    <tr><th>Indicators</th><td><ul>{indicators}</ul></td></tr>
  </table>
</section>"""


def _section_tools(tool_result) -> str:
    by_risk = tool_result.by_risk
    method_icons = {"package_db": "📦", "filesystem": "📂", "config": "⚙"}
    tables = ""
    for risk_key, label, colour in [
        ("high_risk",     "⚠ High-Risk Offensive Tooling",      RISK_COLOURS["CRITICAL"]),
        ("anonymization", "🕵 Anonymization Infrastructure",     RISK_COLOURS["HIGH"]),
        ("dual_use",      "🔧 Dual-Use Cybersecurity Utilities", RISK_COLOURS["MEDIUM"]),
    ]:
        tools = by_risk[risk_key]
        if not tools:
            continue
        rows = "".join(
            f"<tr>"
            f"<td><strong>{t.name}</strong></td>"
            f"<td><code>{t.matched_package}</code></td>"
            f"<td>{t.description}</td>"
            f"<td><span class='tag' style='background:{colour}'>{t.category}</span></td>"
            f"<td style='font-size:0.8em'>{t.mitre_technique}</td>"
            f"<td>{method_icons.get(t.detection_method, '')} {t.detection_method}</td>"
            f"</tr>"
            for t in tools
        )
        tables += f"""
<h3 style="color:{colour}">{label} ({len(tools)})</h3>
<table>
  <tr><th>Tool</th><th>Package / Path</th><th>Description</th><th>Category</th>
      <th>MITRE</th><th>Detected via</th></tr>
  {rows}
</table>"""

    if not tables:
        tables = "<p>No suspicious tools detected.</p>"

    fs_note = ""
    if tool_result.filesystem_hits:
        paths = "".join(f"<li><code>{p}</code></li>" for p in tool_result.filesystem_hits)
        fs_note = f"<h3>📂 Non-packaged binary paths ({len(tool_result.filesystem_hits)})</h3><ul>{paths}</ul>"
    config_note = ""
    if tool_result.config_hits:
        paths = "".join(f"<li><code>{p}</code></li>" for p in tool_result.config_hits)
        config_note = f"<h3>⚙ Configuration traces ({len(tool_result.config_hits)})</h3><ul>{paths}</ul>"

    return f"""
<section>
  <h2>Tool Detection ({len(tool_result.detected_tools)} total)</h2>
  {tables}{fs_note}{config_note}
</section>"""


def _section_mitre(risk_report) -> str:
    if not risk_report.mitre_coverage:
        return ""
    rows = "".join(
        f"<tr>"
        f"<td><a href='https://attack.mitre.org/techniques/{m.technique_id.replace('.', '/')}' "
        f"target='_blank'>{m.technique_id}</a></td>"
        f"<td>{m.technique_name}</td>"
        f"<td>{m.tactic}</td>"
        f"<td>{', '.join(m.tools)}</td>"
        f"</tr>"
        for m in risk_report.mitre_coverage
    )
    return f"""
<section>
  <h2>MITRE ATT&CK Coverage</h2>
  <table>
    <tr><th>Technique ID</th><th>Name</th><th>Tactic</th><th>Tools / Processes</th></tr>
    {rows}
  </table>
</section>"""


def _section_artefacts(os_profile) -> str:
    level_colours = {"HIGH": RISK_COLOURS["HIGH"], "MEDIUM": RISK_COLOURS["MEDIUM"],
                     "CRITICAL": RISK_COLOURS["CRITICAL"], "LOW": RISK_COLOURS["LOW"]}
    fallback = "#888"
    rows = "".join(
        "<tr>"
        f"<td><code>{a.path}</code></td>"
        f"<td>{a.artefact_type}</td>"
        f"<td>{a.description}</td>"
        f"<td><span class='tag' style='background:{level_colours.get(a.risk_level, fallback)}'>"
        f"{a.risk_level}</span></td>"
        f"<td style='font-size:0.8em;color:#555'>{a.snippet[:80] if a.snippet else ''}</td>"
        "</tr>"
        for a in os_profile.filesystem_artefacts
    )
    return f"""
<section>
  <h2>Filesystem Artefacts ({len(os_profile.filesystem_artefacts)})</h2>
  <p style="color:#555;font-size:0.9em">
    Shell histories, SSH keys, cron jobs, /etc/hosts modifications, recently-used registries.
  </p>
  <table>
    <tr><th>Path</th><th>Type</th><th>Description</th><th>Risk</th><th>Snippet</th></tr>
    {rows}
  </table>
</section>"""


def _section_live(live_result) -> str:
    conn_html = ""
    if live_result.suspicious_connections:
        conn_rows = "".join(
            f"<tr>"
            f"<td>{c.protocol.upper()}</td>"
            f"<td>{c.local_addr}:{c.local_port}</td>"
            f"<td>{c.remote_addr}:{c.remote_port}</td>"
            f"<td>{c.state}</td>"
            f"</tr>"
            for c in live_result.suspicious_connections
        )
        conn_html = f"""
<h3 style="color:{RISK_COLOURS['HIGH']}">Suspicious Network Connections
  ({len(live_result.suspicious_connections)})</h3>
<table>
  <tr><th>Proto</th><th>Local</th><th>Remote</th><th>State</th></tr>
  {conn_rows}
</table>"""

    if not live_result.process_findings:
        return f"""
<section>
  <h2>Live Process Analysis</h2>
  <p>✅ {live_result.total_processes_scanned} processes scanned. No suspicious indicators found.</p>
  {conn_html}
</section>"""

    rows = ""
    for pf in live_result.process_findings:
        cmdline_td = f"<br><code style='font-size:0.8em'>{pf.cmdline[:120]}</code>" if pf.cmdline else ""
        notes = "".join(f"<li>{n}</li>" for n in pf.notes)
        rows += (
            f"<tr><td>{pf.pid}</td><td>{pf.comm}{cmdline_td}</td>"
            f"<td><ul>{notes}</ul></td></tr>"
        )
    return f"""
<section>
  <h2>Live Process Analysis ({live_result.total_processes_scanned} scanned)</h2>
  <table>
    <tr><th>PID</th><th>Process / Cmdline</th><th>Findings</th></tr>
    {rows}
  </table>
  {conn_html}
</section>"""


def _section_disk(disk_result) -> str:
    rows = "".join(
        f"<tr>"
        f"<td>{p.index}</td><td>{p.label}</td><td>{p.size_mb} MB</td>"
        f"<td>{'✅ ' + p.luks_version if p.has_luks_header else '—'}</td>"
        f"<td><span class='tag' style='background:{RISK_COLOURS.get(p.risk_label, '#888')}'>"
        f"{p.risk_label}</span></td>"
        f"<td>{p.risk_note}</td>"
        f"</tr>"
        for p in disk_result.partitions
    )
    notes = "".join(f"<li>{n}</li>" for n in disk_result.notes)
    return f"""
<section>
  <h2>Disk / Partition Analysis</h2>
  {"<p>⚠ <strong>TailsData partition detected.</strong></p>" if disk_result.tails_data_found else ""}
  <table>
    <tr><th>#</th><th>Label</th><th>Size</th><th>Encrypted</th><th>Risk</th><th>Note</th></tr>
    {rows or "<tr><td colspan='6'>No partitions found</td></tr>"}
  </table>
  <ul class="summary-list">{notes}</ul>
</section>"""


def _section_kill_chains(risk_report) -> str:
    crit_colour = RISK_COLOURS["CRITICAL"]
    crit_bg = RISK_BG["CRITICAL"]
    items = "".join(
        f"<div style='border-left:4px solid {crit_colour};"
        f"padding:0.6rem 1rem;margin-bottom:0.5rem;background:{crit_bg};"
        f"border-radius:0 4px 4px 0'>"
        f"<strong>⚔ {chain}</strong></div>"
        for chain in risk_report.kill_chains
    )
    return f"""
<section>
  <h2 style="color:{RISK_COLOURS['CRITICAL']}">Kill Chain Patterns
    ({len(risk_report.kill_chains)})</h2>
  <p style="color:#555;font-size:0.9em">
    These patterns indicate combinations of tools that together form multi-stage
    offensive workflows, regardless of whether each tool was used individually.
  </p>
  {items}
</section>"""


def _section_risk_items(risk_report) -> str:
    source_icons = {
        "tool": "🛠", "process": "⚙", "disk": "💾",
        "os": "🖥", "artefact": "📄", "network": "🌐", "killchain": "⚔",
    }
    cards = ""
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        items = risk_report.items_by_level.get(level, [])
        if not items:
            continue
        colour = RISK_COLOURS[level]
        bg     = RISK_BG[level]
        for item in items:
            tech = (
                f"<br><small>MITRE: <a href='https://attack.mitre.org/techniques/"
                f"{item.mitre_technique.replace('.', '/')}' target='_blank'>"
                f"{item.mitre_technique}</a> · {item.mitre_category}</small>"
                if item.mitre_technique else ""
            )
            evidence = f"<br><small>Evidence: {item.evidence}</small>" if item.evidence else ""
            icon = source_icons.get(item.source, "•")
            cards += f"""
<div class="risk-card" style="border-left:4px solid {colour};background:{bg}">
  <span class="badge-small" style="background:{colour}">{level}</span>
  {icon} <strong>{item.title}</strong><br>
  <span>{item.description}</span>
  {tech}{evidence}
</div>"""
    return f"""
<section>
  <h2>All Risk Items ({len(risk_report.items)})</h2>
  {cards}
</section>"""


# ── HTML shell ────────────────────────────────────────────────────────────────

def _wrap_html(body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PMGP Forensic Report</title>
<style>
  body{{font-family:'Segoe UI',Arial,sans-serif;margin:0;background:#f4f6f8;color:#212121}}
  .report-header{{background:#1a237e;color:#fff;padding:2rem;text-align:center}}
  .report-header h1{{margin:0 0 0.5rem}}
  .subtitle{{opacity:0.8;margin:0 0 1rem}}
  .badge{{display:inline-block;padding:0.4rem 1.2rem;border-radius:20px;
           color:#fff;font-weight:bold;font-size:1.1rem}}
  .badge-small{{display:inline-block;padding:0.15rem 0.5rem;border-radius:10px;
                color:#fff;font-size:0.75rem;font-weight:bold;margin-right:0.5rem}}
  section{{background:#fff;margin:1rem auto;max-width:1100px;padding:1.5rem 2rem;
           border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.12)}}
  h2{{color:#1a237e;border-bottom:2px solid #e8eaf6;padding-bottom:0.5rem}}
  h3{{margin-top:1.2rem}}
  table{{width:100%;border-collapse:collapse;margin-top:0.5rem}}
  th{{background:#e8eaf6;text-align:left;padding:0.5rem 0.75rem;font-size:0.85rem}}
  td{{padding:0.45rem 0.75rem;border-bottom:1px solid #f0f0f0;font-size:0.9rem;
      word-break:break-word}}
  tr:hover td{{background:#fafafa}}
  code{{background:#f5f5f5;padding:0.1rem 0.3rem;border-radius:3px;font-size:0.85rem}}
  .summary-list{{padding-left:1.2rem}}
  .summary-list li{{margin-bottom:0.3rem}}
  .tag{{display:inline-block;padding:0.1rem 0.4rem;border-radius:4px;
         color:#fff;font-size:0.78rem;white-space:nowrap}}
  .risk-card{{padding:0.75rem 1rem;margin-bottom:0.6rem;border-radius:4px}}
  .progress-bar{{position:relative;background:#e0e0e0;border-radius:4px;height:18px;
                  min-width:120px;display:inline-block;vertical-align:middle}}
  .progress-fill{{height:100%;background:#1a237e;border-radius:4px}}
  .progress-bar span{{position:absolute;left:50%;top:0;transform:translateX(-50%);
                       font-size:0.8rem;line-height:18px;color:#fff;font-weight:bold}}
  a{{color:#1565c0}}
  @media print{{section{{box-shadow:none}}}}
</style>
</head>
<body>
{body}
<footer style="text-align:center;padding:1rem;color:#888;font-size:0.8rem">
  Generated by PMGP v2.0 · Passive Metadata-Graph Protocol · {_now_iso()}
</footer>
</body>
</html>"""


# ── Utilities ─────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)