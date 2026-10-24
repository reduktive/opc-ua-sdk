#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Generate a self-contained HTML report from OPC UA fuzzer output.

Reads JSON/CSV output from a findings directory and produces a single HTML file
with embedded matplotlib plots (base64 PNGs) and inline CSS.
"""

import argparse
import base64
import csv
import json
import io
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator


# -- Colour palette (dark theme friendly) ------------------------------------

COLORS = [
    "#4fc3f7", "#81c784", "#ffb74d", "#e57373", "#ba68c8",
    "#4dd0e1", "#aed581", "#ffd54f", "#ff8a65", "#f06292",
]
BG_COLOR = "#1e1e2e"
CARD_BG = "#2a2a3d"
TEXT_COLOR = "#cdd6f4"
GRID_COLOR = "#45475a"
ACCENT = "#89b4fa"

SEVERITY_COLOR = {
    "critical": "#f38ba8",
    "high": "#fab387",
    "medium": "#f9e2af",
    "low": "#a6e3a1",
}


def _apply_style(ax, title=""):
    """Apply dark-theme styling to a matplotlib axes."""
    ax.set_facecolor(BG_COLOR)
    ax.figure.set_facecolor(BG_COLOR)
    ax.tick_params(colors=TEXT_COLOR, labelsize=9)
    ax.xaxis.label.set_color(TEXT_COLOR)
    ax.yaxis.label.set_color(TEXT_COLOR)
    ax.title.set_color(TEXT_COLOR)
    for spine in ax.spines.values():
        spine.set_color(GRID_COLOR)
    ax.grid(True, color=GRID_COLOR, alpha=0.3, linewidth=0.5)
    if title:
        ax.set_title(title, fontsize=12, fontweight="bold", pad=10)


# -- Data loading ------------------------------------------------------------

def load_json(path):
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def load_csv_rows(path):
    if not path.exists():
        return None
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        return list(reader)


def load_findings_meta(findings_dir):
    """Load all finding_*.meta.json files from findings/findings/."""
    meta_dir = findings_dir / "findings"
    if not meta_dir.is_dir():
        return []
    metas = []
    for p in sorted(meta_dir.glob("finding_*.meta.json")):
        with open(p) as f:
            metas.append(json.load(f))
    return metas


# -- Plot utilities ----------------------------------------------------------

def fig_to_base64(fig, dpi=120):
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=dpi, bbox_inches="tight",
                facecolor=fig.get_facecolor(), edgecolor="none")
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("ascii")


def _horizontal_bar(counts, title, xlabel="Count"):
    """Generic horizontal bar chart from a {label: count} dict."""
    if not counts:
        return None
    labels = list(counts.keys())
    values = list(counts.values())
    fig, ax = plt.subplots(figsize=(7, max(2.5, len(labels) * 0.45)))
    colors = [COLORS[i % len(COLORS)] for i in range(len(labels))]
    bars = ax.barh(labels, values, color=colors, edgecolor="none", height=0.6)
    ax.set_xlabel(xlabel)
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.invert_yaxis()
    _apply_style(ax, title)
    for bar, val in zip(bars, values):
        ax.text(bar.get_width() + max(values) * 0.02, bar.get_y() + bar.get_height() / 2,
                str(val), va="center", ha="left", color=TEXT_COLOR, fontsize=9)
    return fig_to_base64(fig)


# -- Findings plots ----------------------------------------------------------

def plot_findings_by_class(metas):
    counts = Counter(m["class"] for m in metas)
    return _horizontal_bar(dict(counts.most_common()), "Findings by Class")


def plot_findings_by_layer(metas):
    counts = Counter(m["layer"] for m in metas)
    return _horizontal_bar(dict(counts.most_common()), "Findings by Layer")


def plot_findings_by_strategy(metas):
    counts = Counter(m["strategy"] for m in metas)
    return _horizontal_bar(dict(counts.most_common()), "Findings by Mutation Strategy")


def plot_findings_by_service(metas):
    counts = Counter(m["service"] for m in metas)
    return _horizontal_bar(dict(counts.most_common()), "Findings by Service")


def plot_finding_latencies(metas):
    latencies = [m["latency_us"] for m in metas if "latency_us" in m]
    if not latencies:
        return None
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.hist(latencies, bins=min(30, max(5, len(latencies) // 3)),
            color=ACCENT, edgecolor=BG_COLOR, linewidth=0.5)
    ax.set_xlabel("Latency (\u00b5s)")
    ax.set_ylabel("Count")
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    _apply_style(ax, "Finding Latency Distribution")
    return fig_to_base64(fig)


# -- Performance plots -------------------------------------------------------

def _normalize_throughput(perf):
    """Return throughput data as a list of per-concurrency-level dicts.

    Handles both the new array format and the legacy single-object format.
    """
    tp = perf.get("throughput")
    if not tp:
        return []
    if isinstance(tp, list):
        return tp
    # Legacy: single object with {baseline_rps, saturation_rps, curve}
    if tp.get("curve"):
        return [{"concurrency": 1, **tp}]
    return []


def plot_throughput_curves(perf):
    """Actual RPS vs Target RPS, one line per concurrency level."""
    levels = _normalize_throughput(perf)
    if not levels:
        return None

    fig, ax = plt.subplots(figsize=(8, 5))

    # Ideal line from global min/max target.
    all_targets = [p["target_rps"] for lv in levels for p in lv.get("curve", [])]
    if all_targets:
        lo, hi = min(all_targets), max(all_targets)
        ax.plot([lo, hi], [lo, hi], "--", color=GRID_COLOR, alpha=0.5, label="Ideal", linewidth=1)

    for i, lv in enumerate(levels):
        curve = lv.get("curve", [])
        if not curve:
            continue
        c = lv.get("concurrency", "?")
        target = [p["target_rps"] for p in curve]
        actual = [p["actual_rps"] for p in curve]
        color = COLORS[i % len(COLORS)]
        ax.plot(target, actual, "o-", color=color, label=f"{c} sessions", markersize=3, linewidth=1.2)

    ax.set_xlabel("Target RPS")
    ax.set_ylabel("Actual RPS")
    ax.legend(fontsize=7, facecolor=CARD_BG, edgecolor=GRID_COLOR, labelcolor=TEXT_COLOR,
              loc="upper left", ncol=2)
    _apply_style(ax, "Throughput - Actual vs Target RPS")
    return fig_to_base64(fig)


def plot_throughput_p99(perf):
    """P99 latency vs Target RPS, one line per concurrency level."""
    levels = _normalize_throughput(perf)
    if not levels:
        return None

    fig, ax = plt.subplots(figsize=(8, 5))

    for i, lv in enumerate(levels):
        curve = lv.get("curve", [])
        if not curve:
            continue
        c = lv.get("concurrency", "?")
        target = [p["target_rps"] for p in curve]
        p99 = [p["p99_us"] for p in curve]
        color = COLORS[i % len(COLORS)]
        ax.plot(target, p99, "s-", color=color, label=f"{c} sessions", markersize=3, linewidth=1.2)

    ax.set_xlabel("Target RPS")
    ax.set_ylabel("P99 Latency (\u00b5s)")
    ax.legend(fontsize=7, facecolor=CARD_BG, edgecolor=GRID_COLOR, labelcolor=TEXT_COLOR,
              loc="upper left", ncol=2)
    _apply_style(ax, "Throughput - P99 Latency vs Load")
    return fig_to_base64(fig)


def plot_scaling_vs_concurrency(perf):
    """Baseline and peak actual RPS vs concurrency level."""
    levels = _normalize_throughput(perf)
    if len(levels) < 2:
        return None

    concurrency = [lv.get("concurrency", 0) for lv in levels]
    baseline = [lv.get("baseline_rps", 0) for lv in levels]
    peak_actual = [
        max((p["actual_rps"] for p in lv.get("curve", [])), default=0)
        for lv in levels
    ]

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(concurrency, baseline, "o-", color=COLORS[0], label="Baseline RPS", markersize=4)
    ax.plot(concurrency, peak_actual, "s-", color=COLORS[1], label="Peak Actual RPS", markersize=4)
    ax.set_xlabel("Concurrent Sessions")
    ax.set_ylabel("Requests / sec")
    ax.legend(fontsize=8, facecolor=CARD_BG, edgecolor=GRID_COLOR, labelcolor=TEXT_COLOR)
    _apply_style(ax, "Throughput Scaling by Concurrency")
    return fig_to_base64(fig)


def plot_latency_profile(perf):
    lp = perf.get("latency_profile")
    if not lp:
        return None
    services = sorted(lp.keys())
    percentiles = ["p50_us", "p95_us", "p99_us", "p99_9_us"]
    labels = ["P50", "P95", "P99", "P99.9"]

    import numpy as np
    x = np.arange(len(services))
    width = 0.18
    fig, ax = plt.subplots(figsize=(8, 4.5))
    for i, (pct, label) in enumerate(zip(percentiles, labels)):
        vals = [lp[s].get(pct, 0) for s in services]
        ax.bar(x + i * width, vals, width, label=label, color=COLORS[i], edgecolor="none")

    ax.set_ylabel("Latency (\u00b5s)")
    ax.set_xticks(x + width * 1.5)
    ax.set_xticklabels(services)
    ax.legend(fontsize=8, facecolor=CARD_BG, edgecolor=GRID_COLOR, labelcolor=TEXT_COLOR)
    _apply_style(ax, "Latency Profile by Service")
    return fig_to_base64(fig)


def plot_soak_latency(input_dir):
    rows = load_csv_rows(input_dir / "latency_over_time.csv")
    if not rows:
        return None
    elapsed = [float(r["elapsed_s"]) for r in rows]
    p50 = [float(r["p50_us"]) for r in rows]
    p95 = [float(r["p95_us"]) for r in rows]
    p99 = [float(r["p99_us"]) for r in rows]

    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.plot(elapsed, p50, "-", color=COLORS[0], label="P50", linewidth=1.5)
    ax.plot(elapsed, p95, "-", color=COLORS[2], label="P95", linewidth=1.5)
    ax.plot(elapsed, p99, "-", color=COLORS[3], label="P99", linewidth=1.5)
    ax.set_xlabel("Elapsed Time (s)")
    ax.set_ylabel("Latency (\u00b5s)")
    ax.legend(fontsize=8, facecolor=CARD_BG, edgecolor=GRID_COLOR, labelcolor=TEXT_COLOR)
    _apply_style(ax, "Soak Test - Latency Over Time")
    return fig_to_base64(fig)


# -- Baseline plots ----------------------------------------------------------

def plot_baseline_services(baseline):
    services = baseline.get("services")
    if not services:
        return None
    names = sorted(services.keys())
    percentiles = ["mean", "p95", "p99"]
    labels = ["Mean", "P95", "P99"]

    import numpy as np
    x = np.arange(len(names))
    width = 0.22
    fig, ax = plt.subplots(figsize=(8, 4.5))
    for i, (pct, label) in enumerate(zip(percentiles, labels)):
        vals = [services[s]["latency_us"].get(pct, 0) for s in names]
        ax.bar(x + i * width, vals, width, label=label, color=COLORS[i], edgecolor="none")

    # threshold lines
    for j, name in enumerate(names):
        svc = services[name]
        warn = svc.get("warn_threshold_us")
        alert = svc.get("alert_threshold_us")
        if warn:
            ax.plot([j - 0.15, j + 0.8], [warn, warn], "--", color=SEVERITY_COLOR["medium"],
                    linewidth=0.8, alpha=0.7)
        if alert:
            ax.plot([j - 0.15, j + 0.8], [alert, alert], "--", color=SEVERITY_COLOR["critical"],
                    linewidth=0.8, alpha=0.7)

    ax.set_ylabel("Latency (\u00b5s)")
    ax.set_xticks(x + width)
    ax.set_xticklabels(names)
    ax.legend(fontsize=8, facecolor=CARD_BG, edgecolor=GRID_COLOR, labelcolor=TEXT_COLOR)
    _apply_style(ax, "Baseline - Service Latency")
    return fig_to_base64(fig)


# -- HTML rendering ----------------------------------------------------------

def _img_tag(b64):
    """Wrap a base64 PNG in an <img> tag."""
    return f'<img src="data:image/png;base64,{b64}" style="max-width:100%;border-radius:8px;" />'


def _card(label, value, color=ACCENT):
    return f'''<div class="card">
      <div class="card-value" style="color:{color}">{value}</div>
      <div class="card-label">{label}</div>
    </div>'''


def _table(headers, rows, row_class_fn=None):
    """Render an HTML table."""
    parts = ['<table><thead><tr>']
    for h in headers:
        parts.append(f'<th>{h}</th>')
    parts.append('</tr></thead><tbody>')
    for row in rows:
        cls = f' class="{row_class_fn(row)}"' if row_class_fn else ""
        parts.append(f'<tr{cls}>')
        for cell in row:
            parts.append(f'<td>{cell}</td>')
        parts.append('</tr>')
    parts.append('</tbody></table>')
    return '\n'.join(parts)


def render_html(input_dir, summary, metas, perf, baseline):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    sections = []

    # -- Summary cards -------------------------------------------------------
    cards = []
    if summary:
        total = summary.get("total_cases", 0)
        elapsed = summary.get("elapsed_seconds", 0)
        rate = summary.get("cases_per_second", 0)
        findings_count = len(summary.get("findings", []))
        cards.append(_card("Total Cases", f"{total:,}"))
        cards.append(_card("Findings", str(findings_count),
                          SEVERITY_COLOR["critical"] if findings_count > 0 else "#a6e3a1"))
        cards.append(_card("Rate", f"{rate:.1f} cases/s"))
        cards.append(_card("Duration", f"{elapsed:.1f}s"))
    elif perf:
        cards.append(_card("Mode", "Performance"))
    elif baseline:
        cards.append(_card("Mode", "Baseline"))

    cards_html = '<div class="cards">' + ''.join(cards) + '</div>' if cards else ""

    # -- Findings section ----------------------------------------------------
    if metas:
        plots = []
        for fn in [plot_findings_by_class, plot_findings_by_layer,
                    plot_findings_by_strategy, plot_findings_by_service]:
            b64 = fn(metas)
            if b64:
                plots.append(_img_tag(b64))
        lat_b64 = plot_finding_latencies(metas)
        if lat_b64:
            plots.append(_img_tag(lat_b64))

        plots_html = '<div class="plot-grid">' + ''.join(
            f'<div class="plot-cell">{p}</div>' for p in plots
        ) + '</div>'

        # Findings detail table
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_metas = sorted(metas, key=lambda m: severity_order.get(m.get("severity", "low"), 9))
        rows = []
        for m in sorted_metas:
            sev = m.get("severity", "?")
            sev_html = f'<span class="severity-{sev}">{sev.upper()}</span>'
            rows.append([
                m.get("id", ""),
                sev_html,
                m.get("class", ""),
                m.get("layer", ""),
                m.get("service", ""),
                m.get("strategy", ""),
                f'{m.get("latency_us", 0):,}',
                m.get("description", "")[:120],
            ])
        table_html = _table(
            ["ID", "Severity", "Class", "Layer", "Service", "Strategy", "Latency (\u00b5s)", "Description"],
            rows
        )
        sections.append(f'''
        <section>
          <h2>Findings ({len(metas)})</h2>
          {plots_html}
          <div class="table-wrap">{table_html}</div>
        </section>''')

    # -- Performance section -------------------------------------------------
    if perf:
        perf_plots = []
        for plot_fn in [plot_throughput_curves, plot_throughput_p99, plot_scaling_vs_concurrency]:
            b64 = plot_fn(perf)
            if b64:
                perf_plots.append(_img_tag(b64))
        lp_b64 = plot_latency_profile(perf)
        if lp_b64:
            perf_plots.append(_img_tag(lp_b64))
        soak_b64 = plot_soak_latency(input_dir)
        if soak_b64:
            perf_plots.append(_img_tag(soak_b64))

        perf_plots_html = '<div class="plot-grid">' + ''.join(
            f'<div class="plot-cell">{p}</div>' for p in perf_plots
        ) + '</div>' if perf_plots else ""

        # Soak summary table
        soak_table = ""
        soak = perf.get("soak")
        if soak:
            soak_rows = [
                ["Duration", f'{soak.get("duration_s", 0)}s'],
                ["Total Requests", f'{soak.get("total_requests", 0):,}'],
                ["Avg RPS", f'{soak.get("avg_rps", 0):.1f}'],
                ["Start P50", f'{soak.get("start_p50_us", 0):.0f} \u00b5s'],
                ["End P50", f'{soak.get("end_p50_us", 0):.0f} \u00b5s'],
                ["Latency Drift", f'{soak.get("latency_drift_us_per_hour", 0):.1f} \u00b5s/hr'],
            ]
            soak_table = '<h3>Soak Summary</h3>' + _table(["Metric", "Value"], soak_rows)

        # Throughput summary - per concurrency level
        tp_table = ""
        levels = _normalize_throughput(perf)
        if levels:
            tp_rows = []
            for lv in levels:
                tp_rows.append([
                    str(lv.get("concurrency", "?")),
                    f'{lv.get("baseline_rps", 0):.1f}',
                    f'{lv.get("saturation_rps", 0):.1f}',
                    str(len(lv.get("curve", []))),
                ])
            tp_table = '<h3>Throughput Summary</h3>' + _table(
                ["Concurrency", "Baseline RPS", "Saturation RPS", "Load Steps"], tp_rows)

        sections.append(f'''
        <section>
          <h2>Performance</h2>
          {perf_plots_html}
          <div class="table-wrap">{tp_table}{soak_table}</div>
        </section>''')

    # -- Baseline section ----------------------------------------------------
    if baseline:
        bl_plots = []
        bl_b64 = plot_baseline_services(baseline)
        if bl_b64:
            bl_plots.append(_img_tag(bl_b64))

        bl_plots_html = '<div class="plot-grid">' + ''.join(
            f'<div class="plot-cell">{p}</div>' for p in bl_plots
        ) + '</div>' if bl_plots else ""

        # Baseline stats table
        services = baseline.get("services", {})
        bl_rows = []
        for name in sorted(services):
            s = services[name]
            lat = s.get("latency_us", {})
            bl_rows.append([
                name,
                f'{lat.get("mean", 0):.0f}',
                f'{lat.get("p95", 0):.0f}',
                f'{lat.get("p99", 0):.0f}',
                f'{lat.get("stddev", 0):.1f}',
                f'{s.get("warn_threshold_us", 0):.0f}',
                f'{s.get("alert_threshold_us", 0):.0f}',
            ])
        bl_table = _table(
            ["Service", "Mean (\u00b5s)", "P95 (\u00b5s)", "P99 (\u00b5s)", "Stddev", "Warn", "Alert"],
            bl_rows
        )

        # Connection timing
        conn = baseline.get("connection", {})
        conn_table = ""
        if conn:
            conn_rows = [
                ["Handshake Mean", f'{conn.get("handshake_mean_us", 0):.0f} \u00b5s'],
                ["Handshake P99", f'{conn.get("handshake_p99_us", 0):.0f} \u00b5s'],
            ]
            conn_table = '<h3>Connection Timing</h3>' + _table(["Metric", "Value"], conn_rows)

        recorded = baseline.get("recorded_at", "")
        rec_html = f'<p class="subtle">Recorded: {recorded}</p>' if recorded else ""

        sections.append(f'''
        <section>
          <h2>Baseline</h2>
          {rec_html}
          {bl_plots_html}
          <div class="table-wrap">{bl_table}{conn_table}</div>
        </section>''')

    # -- No data fallback ----------------------------------------------------
    if not sections and not cards:
        sections.append('<section><h2>No Data</h2><p>No fuzzer output found in the input directory.</p></section>')

    body = cards_html + '\n'.join(sections)

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>OPC UA Fuzzer Report</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
    background: {BG_COLOR};
    color: {TEXT_COLOR};
    padding: 24px;
    line-height: 1.5;
  }}
  h1 {{
    font-size: 1.8rem;
    margin-bottom: 4px;
    color: {ACCENT};
  }}
  .subtitle {{
    color: #7f849c;
    font-size: 0.85rem;
    margin-bottom: 24px;
  }}
  h2 {{
    font-size: 1.3rem;
    margin-bottom: 16px;
    padding-bottom: 6px;
    border-bottom: 1px solid {GRID_COLOR};
  }}
  h3 {{
    font-size: 1rem;
    margin: 16px 0 8px;
  }}
  section {{
    background: {CARD_BG};
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 20px;
  }}
  .cards {{
    display: flex;
    gap: 16px;
    margin-bottom: 20px;
    flex-wrap: wrap;
  }}
  .card {{
    background: {CARD_BG};
    border-radius: 10px;
    padding: 16px 24px;
    min-width: 140px;
    text-align: center;
    border: 1px solid {GRID_COLOR};
  }}
  .card-value {{
    font-size: 1.6rem;
    font-weight: 700;
  }}
  .card-label {{
    font-size: 0.8rem;
    color: #7f849c;
    margin-top: 4px;
  }}
  .plot-grid {{
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
    margin-bottom: 16px;
  }}
  .plot-cell {{
    flex: 1 1 45%;
    min-width: 340px;
  }}
  .plot-cell img {{
    width: 100%;
    height: auto;
  }}
  .table-wrap {{
    overflow-x: auto;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
    margin-bottom: 12px;
  }}
  th, td {{
    padding: 8px 12px;
    text-align: left;
    border-bottom: 1px solid {GRID_COLOR};
  }}
  th {{
    color: {ACCENT};
    font-weight: 600;
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }}
  tr:hover {{
    background: rgba(137, 180, 250, 0.05);
  }}
  .severity-critical {{ color: {SEVERITY_COLOR["critical"]}; font-weight: 700; }}
  .severity-high {{ color: {SEVERITY_COLOR["high"]}; font-weight: 600; }}
  .severity-medium {{ color: {SEVERITY_COLOR["medium"]}; }}
  .severity-low {{ color: {SEVERITY_COLOR["low"]}; }}
  .subtle {{ color: #7f849c; font-size: 0.8rem; margin-bottom: 12px; }}
</style>
</head>
<body>
  <h1>OPC UA Fuzzer Report</h1>
  <p class="subtitle">Generated {timestamp}</p>
  {body}
</body>
</html>'''


# -- Main -------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Generate HTML report from fuzzer output")
    parser.add_argument("--input-dir", default="./findings",
                        help="Directory containing fuzzer output (default: ./findings)")
    parser.add_argument("--output", default=None,
                        help="Output HTML file (default: <input-dir>/report.html)")
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    if not input_dir.is_dir():
        print(f"Error: input directory '{input_dir}' does not exist", file=sys.stderr)
        sys.exit(1)

    output_path = Path(args.output) if args.output else input_dir / "report.html"

    summary = load_json(input_dir / "run_summary.json")
    metas = load_findings_meta(input_dir)
    perf = load_json(input_dir / "perf_summary.json")
    baseline = load_json(input_dir / "baseline.json")

    html = render_html(input_dir, summary, metas, perf, baseline)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        f.write(html)

    print(f"Report written to {output_path}")
    print(f"  Summary:  {'yes' if summary else 'no'}")
    print(f"  Findings: {len(metas)}")
    print(f"  Perf:     {'yes' if perf else 'no'}")
    print(f"  Baseline: {'yes' if baseline else 'no'}")


if __name__ == "__main__":
    main()
