"""Report generator.

Generates PDF and CSV reports on demand, plus an incident-style
summary suitable for sharing with a wider team.

PDF output uses ReportLab.  The reports are designed to be
self-contained — they include the executive summary, threat
statistics, source analysis, risk analysis, and concrete
recommendations, mirroring the PRD's "Report Sections" list.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import database as db
from .config import get_settings

log = logging.getLogger("sentinelscan.reports")


def _now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)

# Lazy import — reportlab is heavy and optional.
_reportlab = None


def _rl():
    global _reportlab
    if _reportlab is None:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Table,
            TableStyle,
        )

        _reportlab = {
            "colors": colors,
            "A4": A4,
            "styles": getSampleStyleSheet,
            "ParagraphStyle": ParagraphStyle,
            "cm": cm,
            "SimpleDocTemplate": SimpleDocTemplate,
            "Paragraph": Paragraph,
            "Spacer": Spacer,
            "Table": Table,
            "TableStyle": TableStyle,
        }
    return _reportlab


# ---------------------------------------------------------------------------
# Data assembly
# ---------------------------------------------------------------------------


def _collect_data(since: Optional[datetime] = None) -> Tuple[List[db.Attack], Dict]:
    with db.session_scope() as s:
        from sqlalchemy import select, desc

        stmt = select(db.Attack).order_by(desc(db.Attack.started_at))
        if since is not None:
            stmt = stmt.where(db.Attack.started_at >= since)
        attacks = list(s.scalars(stmt).all())

        # Summary metrics
        by_risk = Counter(a.risk_level for a in attacks)
        by_scan = Counter(a.scan_type for a in attacks)
        by_tool = Counter(a.source_tool_guess for a in attacks if a.source_tool_guess)
        by_country = Counter(a.source_country for a in attacks if a.source_country)
        by_source = Counter(a.source_ip for a in attacks)
        avg_risk = (sum(a.risk_score for a in attacks) / len(attacks)) if attacks else 0.0
        period_start = min((a.started_at for a in attacks), default=None)
        period_end = max((a.ended_at for a in attacks), default=None)

    summary = {
        "total": len(attacks),
        "by_risk": dict(by_risk),
        "by_scan": dict(by_scan),
        "by_tool": dict(by_tool),
        "by_country": dict(by_country),
        "top_sources": by_source.most_common(10),
        "avg_risk": avg_risk,
        "period_start": period_start,
        "period_end": period_end,
    }
    return attacks, summary


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------


def generate_csv(since: Optional[datetime] = None) -> Tuple[Path, int]:
    attacks, _ = _collect_data(since)
    settings = get_settings()
    out_dir = settings.reports_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = _now_naive().strftime("%Y%m%d-%H%M%S")
    path = out_dir / f"sentinelscan-attacks-{stamp}.csv"

    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "id", "started_at", "ended_at", "duration_s",
                "source_ip", "source_country", "source_isp", "source_asn",
                "source_tool_guess", "source_tool_confidence", "source_os_guess",
                "scan_type", "scan_confidence",
                "unique_ports", "unique_targets", "packet_count",
                "risk_score", "risk_level",
            ]
        )
        for a in attacks:
            w.writerow(
                [
                    a.id, a.started_at.isoformat(), a.ended_at.isoformat(), a.duration_seconds,
                    a.source_ip, a.source_country, a.source_isp, a.source_asn,
                    a.source_tool_guess, a.source_tool_confidence, a.source_os_guess,
                    a.scan_type, a.scan_confidence,
                    a.unique_ports, a.unique_targets, a.packet_count,
                    a.risk_score, a.risk_level,
                ]
            )
    return path, len(attacks)


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------


def _rl_styles():
    rl = _rl()
    base = rl["styles"]()
    title = rl["ParagraphStyle"](
        "SentinelTitle", parent=base["Title"], fontSize=22, textColor=rl["colors"].HexColor("#0F172A")
    )
    h2 = rl["ParagraphStyle"](
        "SentinelH2", parent=base["Heading2"], textColor=rl["colors"].HexColor("#1E293B")
    )
    body = rl["ParagraphStyle"](
        "SentinelBody", parent=base["BodyText"], fontSize=10, leading=14
    )
    small = rl["ParagraphStyle"](
        "SentinelSmall", parent=base["BodyText"], fontSize=9, leading=12, textColor=rl["colors"].grey
    )
    return {"title": title, "h2": h2, "body": body, "small": small}


def _risk_color(level: str):
    rl = _rl()
    return {
        "low": rl["colors"].HexColor("#16A34A"),
        "medium": rl["colors"].HexColor("#EAB308"),
        "high": rl["colors"].HexColor("#EA580C"),
        "critical": rl["colors"].HexColor("#DC2626"),
    }.get(level, rl["colors"].grey)


def _recommendations(summary: Dict) -> List[str]:
    recs: List[str] = []
    by_scan = summary.get("by_scan", {})
    if by_scan.get("Xmas Scan", 0) or by_scan.get("FIN Scan", 0) or by_scan.get("NULL Scan", 0):
        recs.append("Block stealth / crafted-flag scans at the perimeter and inspect for non-standard flag combinations.")
    if by_scan.get("Ping Sweep", 0):
        recs.append("Restrict ICMP echo replies to known management hosts to slow reconnaissance.")
    if by_scan.get("Mass Scan", 0):
        recs.append("Rate-limit incoming SYN packets per source and alert on sustained bursts (>1000 pps).")
    if summary.get("by_risk", {}).get("critical", 0) >= 3:
        recs.append("Quarantine repeat offenders — block top source IPs at the firewall for 24 hours.")
    if summary.get("by_country"):
        recs.append("Review geographic distribution of scans; correlate with known threat-intel feeds.")
    if summary.get("by_tool", {}).get("Nmap", 0):
        recs.append("Deploy an IDS/IPS signature set tuned for Nmap (S1..S7) and NSE scripts.")
    if summary.get("by_tool", {}).get("Masscan", 0):
        recs.append("Consider deploying fail2ban or equivalent with an aggressive SYN-scan rule.")
    if not recs:
        recs.append("Continue passive monitoring; review baselines weekly.")
    return recs


def generate_pdf(since: Optional[datetime] = None) -> Tuple[Path, int]:
    rl = _rl()
    attacks, summary = _collect_data(since)
    styles = _rl_styles()
    settings = get_settings()
    out_dir = settings.reports_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = _now_naive().strftime("%Y%m%d-%H%M%S")
    path = out_dir / f"sentinelscan-report-{stamp}.pdf"

    doc = rl["SimpleDocTemplate"](
        str(path),
        pagesize=rl["A4"],
        leftMargin=1.6 * rl["cm"],
        rightMargin=1.6 * rl["cm"],
        topMargin=1.4 * rl["cm"],
        bottomMargin=1.4 * rl["cm"],
        title="SentinelScan AI — Incident Report",
    )

    story = []
    # ---- Title block ----
    story.append(rl["Paragraph"]("SentinelScan AI — Incident Report", styles["title"]))
    story.append(rl["Paragraph"](
        f"Generated {_now_naive().strftime('%Y-%m-%d %H:%M UTC')}", styles["small"]
    ))
    if summary["period_start"]:
        story.append(rl["Paragraph"](
            f"Reporting window: {summary['period_start'].strftime('%Y-%m-%d %H:%M')} "
            f"→ {summary['period_end'].strftime('%Y-%m-%d %H:%M')} UTC",
            styles["small"],
        ))
    story.append(rl["Spacer"](1, 8))

    # ---- Executive summary ----
    story.append(rl["Paragraph"]("1. Executive Summary", styles["h2"]))
    total = summary["total"]
    avg = summary["avg_risk"]
    top = ", ".join(f"{ip} ({n})" for ip, n in summary["top_sources"][:3]) or "—"
    story.append(rl["Paragraph"](
        f"During the reporting window, SentinelScan AI detected <b>{total}</b> reconnaissance "
        f"events with an average risk score of <b>{avg:.1f}/10</b>.  The most active sources "
        f"were: {top}.",
        styles["body"],
    ))
    story.append(rl["Spacer"](1, 8))

    # ---- Threat statistics ----
    story.append(rl["Paragraph"]("2. Threat Statistics", styles["h2"]))
    risk_data = [["Risk Level", "Count"]]
    for level in ("critical", "high", "medium", "low"):
        risk_data.append([level.capitalize(), str(summary["by_risk"].get(level, 0))])
    risk_table = rl["Table"](risk_data, colWidths=[4 * rl["cm"], 4 * rl["cm"]])
    risk_table.setStyle(rl["TableStyle"]([
        ("BACKGROUND", (0, 0), (-1, 0), rl["colors"].HexColor("#1E293B")),
        ("TEXTCOLOR", (0, 0), (-1, 0), rl["colors"].white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, rl["colors"].HexColor("#CBD5E1")),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
    ]))
    story.append(risk_table)
    story.append(rl["Spacer"](1, 8))

    if summary["by_scan"]:
        scan_data = [["Scan Type", "Count"]]
        for k, v in sorted(summary["by_scan"].items(), key=lambda x: -x[1]):
            scan_data.append([k, str(v)])
        scan_table = rl["Table"](scan_data, colWidths=[8 * rl["cm"], 2 * rl["cm"]])
        scan_table.setStyle(rl["TableStyle"]([
            ("BACKGROUND", (0, 0), (-1, 0), rl["colors"].HexColor("#1E293B")),
            ("TEXTCOLOR", (0, 0), (-1, 0), rl["colors"].white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, rl["colors"].HexColor("#CBD5E1")),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
        ]))
        story.append(rl["Paragraph"]("Scan Type Distribution", styles["h2"]))
        story.append(scan_table)
        story.append(rl["Spacer"](1, 8))

    # ---- Source analysis ----
    story.append(rl["Paragraph"]("3. Source Analysis", styles["h2"]))
    src_data = [["Source IP", "Hits"]]
    for ip, n in summary["top_sources"]:
        src_data.append([ip, str(n)])
    if len(src_data) == 1:
        src_data.append(["(no data)", "—"])
    src_table = rl["Table"](src_data, colWidths=[8 * rl["cm"], 2 * rl["cm"]])
    src_table.setStyle(rl["TableStyle"]([
        ("BACKGROUND", (0, 0), (-1, 0), rl["colors"].HexColor("#1E293B")),
        ("TEXTCOLOR", (0, 0), (-1, 0), rl["colors"].white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, rl["colors"].HexColor("#CBD5E1")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    story.append(src_table)
    story.append(rl["Spacer"](1, 8))

    if summary["by_country"]:
        country_data = [["Country", "Events"]]
        for c, n in sorted(summary["by_country"].items(), key=lambda x: -x[1]):
            country_data.append([c, str(n)])
        country_table = rl["Table"](country_data, colWidths=[8 * rl["cm"], 2 * rl["cm"]])
        country_table.setStyle(rl["TableStyle"]([
            ("BACKGROUND", (0, 0), (-1, 0), rl["colors"].HexColor("#1E293B")),
            ("TEXTCOLOR", (0, 0), (-1, 0), rl["colors"].white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, rl["colors"].HexColor("#CBD5E1")),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
        ]))
        story.append(rl["Paragraph"]("Geographic Distribution", styles["h2"]))
        story.append(country_table)
        story.append(rl["Spacer"](1, 8))

    # ---- Detailed event listing ----
    story.append(rl["Paragraph"]("4. Detected Events", styles["h2"]))
    detail = [["Time", "Source", "Scan", "Risk", "Score"]]
    for a in attacks[:30]:
        detail.append([
            a.started_at.strftime("%m-%d %H:%M:%S"),
            a.source_ip,
            a.scan_type,
            a.risk_level.upper(),
            f"{a.risk_score:.1f}",
        ])
    detail_table = rl["Table"](detail, colWidths=[3.2 * rl["cm"], 4.2 * rl["cm"], 4.5 * rl["cm"], 2.5 * rl["cm"], 1.4 * rl["cm"]])
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), rl["colors"].HexColor("#1E293B")),
        ("TEXTCOLOR", (0, 0), (-1, 0), rl["colors"].white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.4, rl["colors"].HexColor("#CBD5E1")),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
    ]
    for i, a in enumerate(attacks[:30], start=1):
        style_cmds.append(("TEXTCOLOR", (3, i), (3, i), _risk_color(a.risk_level)))
    detail_table.setStyle(rl["TableStyle"](style_cmds))
    story.append(detail_table)
    if len(attacks) > 30:
        story.append(rl["Paragraph"](
            f"(+{len(attacks) - 30} more events — see CSV export for full list)", styles["small"]
        ))
    story.append(rl["Spacer"](1, 8))

    # ---- Recommendations ----
    story.append(rl["Paragraph"]("5. Recommendations", styles["h2"]))
    for rec in _recommendations(summary):
        story.append(rl["Paragraph"](f"• {rec}", styles["body"]))

    doc.build(story)
    return path, len(attacks)
