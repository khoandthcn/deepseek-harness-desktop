#!/usr/bin/env python3
"""Check a monthly report's data and render it into the fixed A4 template.

    build_report.py init   data.json --customer NAME --tenant ID --year Y --month M [--template NAME]
    build_report.py period data.json
    build_report.py check  data.json
    build_report.py render data.json --out report.html [--brand DIR] [--pdf] [--allow-draft]

    build_report.py templates                      list the templates that can be named
    build_report.py new-template NAME [--like T]   start one in ./report-templates/NAME
    build_report.py check-template NAME            validate one before collecting data

With no ``--template`` the report is the built-in monthly one. A template is a
directory holding a ``template.json``, kept in ``report-templates/`` of the
working directory; see ``references/template-format.md``.

The division of labour is the point of this script. The agent collects figures
into ``data.json`` and writes a handful of narrative sentences; everything
else — every derived number, every boilerplate sentence, every chart, the page
layout and the table of contents — is produced here, the same way every time.
``check`` refuses a data file whose figures do not add up or whose origin is
not recorded, so a number that was estimated or carried over from a sample
cannot reach the report unnoticed.

Standard library only: it has to run wherever the agent's shell runs.
"""

from __future__ import annotations

import argparse
import base64
import calendar
import html
import json
import math
import mimetypes
import os
import re
import shutil
import subprocess
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent

# ── data contract ────────────────────────────────────────────────────────────

#: Every figure a person or a tool supplies, as a dotted path. Each must carry
#: an entry in ``sources`` saying where it came from. Figures this script
#: derives (KPIs achieved, percentages from counts) are deliberately absent:
#: they are computed, never typed.
SOURCED = (
    'overview.apt_count',
    'incident_response.incident_count',
    'tier1.alert_total',
    'tier1.sla.previous',
    'tier1.sla.current',
    'tier1.by_solution',
    'tier1.by_category',
    'tier1.by_level',
    'tier1.top_rules',
    'tier1.top_objects',
    'tier2.tickets_total',
    'tier2.tickets_on_time',
    'tier2.sla.previous',
    'tier3.cases_total',
    'tier3.cases_excluded',
    'tier3.sla.previous',
    'tier3.sla.current',
    'coverage.nsm',
    'coverage.siem',
    'coverage.edr',
    'content.ticket_count',
    'content.sla.previous',
    'content.sla.current',
    'optimization',
    'appendix_siem_offline',
    'appendix_edr_offline',
)

#: Who may have supplied a figure.
SOURCE_KINDS = ('tool', 'user')

#: Figures the platform's tools can answer. Everything else in the contract is
#: known only to the people running the service — SLA results, cases, what was
#: optimised — and is asked of the user rather than looked for.
FROM_TOOLS = (
    'tier1.alert_total', 'tier1.by_solution', 'tier1.by_category', 'tier1.by_level',
    'tier1.top_rules', 'tier1.top_objects', 'tier2.tickets_total', 'tier3.cases_total',
    'coverage.nsm', 'coverage.siem', 'coverage.edr',
    'appendix_siem_offline', 'appendix_edr_offline',
)

#: Default SLA targets, in percent, when the data file names none.
DEFAULT_TARGETS = {'tier1': 90.0, 'tier2': 90.0, 'tier3': 90.0, 'content': 95.0}

MISSING = object()


def get(data: dict, path: str, default=MISSING):
    """Read a dotted path out of nested dicts.

    :param data: the report data.
    :param path: e.g. ``tier1.sla.current``.
    :param default: returned when any segment is absent.
    :returns: the value, or ``default``.
    """
    node = data
    for key in path.split('.'):
        if not isinstance(node, dict) or key not in node:
            return default
        node = node[key]
    return node


def is_number(value) -> bool:
    """Whether a value is a real number (a bool is not)."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


class Findings:
    """What ``check`` found: errors block a final render, warnings do not."""

    def __init__(self) -> None:
        self.errors: list[str] = []
        self.needs_input: list[str] = []
        self.warnings: list[str] = []

    def error(self, message: str) -> None:
        self.errors.append(message)

    def need(self, path: str, why: str) -> None:
        self.needs_input.append((path, why))

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    @property
    def blocking(self) -> bool:
        return bool(self.errors or self.needs_input)


def month_bounds(year: int, month: int) -> tuple[date, date]:
    """First day of a month and first day of the next.

    :returns: the half-open period the report covers.
    """
    nxt = (year + (month == 12), month % 12 + 1)
    return date(year, month, 1), date(nxt[0], nxt[1], 1)


def previous_month(year: int, month: int) -> tuple[int, int]:
    """The month before the given one."""
    return (year - 1, 12) if month == 1 else (year, month - 1)


def month_label(year: int, month: int) -> str:
    """E.g. ``August 2024``."""
    return f'{calendar.month_name[month]} {year}'


def check(data: dict) -> Findings:
    """Validate the data file against the contract.

    :param data: the parsed ``data.json``.
    :returns: errors, missing inputs and warnings.
    """
    f = Findings()

    # -- identity and period
    for path in ('meta.customer_name', 'meta.tenant'):
        value = get(data, path, None)
        if not isinstance(value, str) or not value.strip():
            f.need(path, 'ask the user; a report is for exactly one tenant')
    year, month = get(data, 'meta.period.year', None), get(data, 'meta.period.month', None)
    if not (isinstance(year, int) and isinstance(month, int) and 1 <= month <= 12):
        f.error('meta.period.year / meta.period.month must be integers (month 1-12)')
        return f

    def number(path: str, *, integer: bool = True, low: float = 0, high: float | None = None):
        value = get(data, path, None)
        if value is None:
            f.need(path, 'no value yet')
            return None
        if not is_number(value) or (integer and int(value) != value):
            f.error(f'{path} must be {"an integer" if integer else "a number"}, got {value!r}')
            return None
        if value < low or (high is not None and value > high):
            f.error(f'{path} = {value} is outside {low}..{high if high is not None else "∞"}')
            return None
        return value

    def rows(path: str, keys: tuple[str, ...], count_key: str | None = 'count'):
        value = get(data, path, None)
        if value is None:
            f.need(path, 'no value yet')
            return None
        if not isinstance(value, list):
            f.error(f'{path} must be a list')
            return None
        for index, row in enumerate(value):
            if not isinstance(row, dict):
                f.error(f'{path}[{index}] must be an object')
                return None
            for key in keys:
                if row.get(key) in (None, ''):
                    f.error(f'{path}[{index}].{key} is empty')
            if count_key and not (is_number(row.get(count_key)) and row[count_key] >= 0
                                  and int(row[count_key]) == row[count_key]):
                f.error(f'{path}[{index}].{count_key} must be a non-negative integer')
                return None
        return value

    # -- tier 1
    total = number('tier1.alert_total')
    for path, label in (('tier1.by_solution', 'solutions'), ('tier1.by_category', 'attack categories'),
                        ('tier1.by_level', 'levels')):
        breakdown = rows(path, ('name',))
        if breakdown is not None and total is not None:
            summed = sum(row['count'] for row in breakdown)
            if summed != total:
                f.error(f'{path} sums to {summed} but tier1.alert_total is {total}: the {label} must '
                        'account for every alert (add the missing bucket, or re-run the count queries '
                        'over the same period and tenant)')
    for path, limit, keys in (('tier1.top_rules', 5, ('rule_id', 'description')),
                              ('tier1.top_objects', 10, ('object',))):
        top = rows(path, keys)
        if top is None:
            continue
        counts = [row['count'] for row in top]
        if counts != sorted(counts, reverse=True):
            f.error(f'{path} must be ordered from most alerts to fewest')
        if len(top) > limit:
            f.error(f'{path} has {len(top)} rows; the template lists at most {limit}')
        if total is not None and any(count > total for count in counts):
            f.error(f'{path} has a row with more alerts than tier1.alert_total ({total})')
        if len(top) < limit and total:
            f.warn(f'{path} has {len(top)} rows, fewer than the {limit} the template lists — fine only '
                   'if there really are no more')

    # -- SLA figures
    for tier in ('tier1', 'tier3', 'content'):
        number(f'{tier}.sla.previous', integer=False, high=100)
        number(f'{tier}.sla.current', integer=False, high=100)
    number('tier2.sla.previous', integer=False, high=100)
    tickets, on_time = number('tier2.tickets_total'), number('tier2.tickets_on_time')
    if tickets is not None and on_time is not None and on_time > tickets:
        f.error(f'tier2.tickets_on_time ({on_time}) exceeds tier2.tickets_total ({tickets})')
    stated = get(data, 'tier2.sla.current', None)
    if stated is not None and tickets and on_time is not None:
        derived = round(on_time / tickets * 100, 2)
        if not is_number(stated) or abs(stated - derived) > 0.01:
            f.error(f'tier2.sla.current is {stated} but {on_time}/{tickets} tickets on time is {derived}%: '
                    'leave it out and let it be computed, or correct the counts')
    cases, excluded = number('tier3.cases_total'), number('tier3.cases_excluded')
    if cases is not None and excluded is not None and excluded > cases:
        f.error(f'tier3.cases_excluded ({excluded}) exceeds tier3.cases_total ({cases})')
    if excluded and not str(get(data, 'tier3.exclusion_reason', '') or '').strip():
        f.need('tier3.exclusion_reason', 'cases were deducted from the SLA; the report must say why')
    number('overview.apt_count')
    incidents = number('incident_response.incident_count')
    listed = get(data, 'incident_response.incidents', []) or []
    if incidents is not None and incidents != len(listed):
        f.error(f'incident_response.incident_count is {incidents} but {len(listed)} incidents are described')
    number('content.ticket_count')

    # -- coverage and appendices
    nsm = get(data, 'coverage.nsm', None)
    if nsm is None:
        f.need('coverage.nsm', 'no value yet')
    else:
        sensors, healthy = nsm.get('sensors_total'), nsm.get('sensors_ok')
        if not (is_number(sensors) and is_number(healthy) and 0 <= healthy <= sensors):
            f.error('coverage.nsm needs sensors_total and sensors_ok, with sensors_ok ≤ sensors_total')
    for key, appendix in (('siem', 'appendix_siem_offline'), ('edr', 'appendix_edr_offline')):
        agents = get(data, f'coverage.{key}', None)
        if agents is None:
            f.need(f'coverage.{key}', 'no value yet')
            continue
        installed, online, offline = (agents.get(name) for name in ('installed', 'online', 'offline'))
        if not all(is_number(v) and v >= 0 for v in (installed, online, offline)):
            f.error(f'coverage.{key} needs installed, online and offline as non-negative integers')
            continue
        if online + offline != installed:
            f.error(f'coverage.{key}: online ({online}) + offline ({offline}) is not installed ({installed})')
        listed = rows(appendix, ('hostname',), count_key=None)
        if listed is not None and len(listed) != offline:
            f.error(f'{appendix} lists {len(listed)} machines but coverage.{key}.offline is {offline}: '
                    'the appendix must name every offline agent, no more and no fewer')
    rows('optimization', ('rule', 'optimization'), count_key=None)
    problems = rows('problems', ('problem', 'recommendation'), count_key=None)

    # -- provenance: where each supplied figure came from
    sources = data.get('sources') or {}
    for path in SOURCED:
        if get(data, path, None) is None:
            continue
        entry = sources.get(path)
        if not isinstance(entry, dict) or entry.get('by') not in SOURCE_KINDS:
            f.error(f'sources["{path}"] is missing: record {{"by": "tool"|"user", "ref": "..."}} for every '
                    'figure, so nothing estimated or remembered reaches the report')
        elif not str(entry.get('ref') or '').strip():
            f.error(f'sources["{path}"].ref is empty: name the tool call and its filters, or what the user said')

    # -- things a person should look at
    if problems is not None:
        text = ' '.join(f'{row.get("problem", "")}' for row in problems).lower()
        for key, word in (('siem', 'agent'), ('edr', 'edr')):
            offline = get(data, f'coverage.{key}.offline', 0) or 0
            if offline and word not in text:
                f.warn(f'coverage.{key}.offline is {offline} but no row in problems mentions it')
    if not str(get(data, 'tier1.commentary', '') or '').strip():
        f.warn('tier1.commentary is empty: the template explains the month-on-month change in alerts '
               'here. Leave it empty only if the user has nothing to say.')
    else:
        f.warn('tier1.commentary is free text: show it to the user and have them confirm it before the '
               'final render.')
    return f


# ── derived values and wording ───────────────────────────────────────────────

def pad2(value) -> str:
    """Counts in prose are written with two digits, as the template does."""
    return f'{int(value):02d}'


def pct(value: float) -> str:
    """A percentage as the template prints it: ``100%`` or ``96.25%``."""
    text = f'{value:.2f}'.rstrip('0').rstrip('.')
    return f'{text}%'


def derive(data: dict) -> dict:
    """Everything the report states that is computed rather than supplied.

    :param data: checked report data.
    :returns: labels, SLA series and the KPI tally.
    """
    year, month = data['meta']['period']['year'], data['meta']['period']['month']
    start, end = month_bounds(year, month)
    prev = previous_month(year, month)
    targets = {**DEFAULT_TARGETS, **(data.get('sla_targets') or {})}

    def series(tier: str, current):
        previous = get(data, f'{tier}.sla.previous', None)
        return {'previous': previous, 'current': current, 'target': float(targets[tier]),
                'achieved': current is not None and current >= targets[tier]}

    tickets, on_time = get(data, 'tier2.tickets_total', None), get(data, 'tier2.tickets_on_time', None)
    tier2_current = None
    if is_number(tickets) and is_number(on_time):
        # No tickets means nothing was late: the commitment was met.
        tier2_current = 100.0 if tickets == 0 else round(on_time / tickets * 100, 2)
    sla = {
        'tier1': series('tier1', get(data, 'tier1.sla.current', None)),
        'tier2': series('tier2', tier2_current),
        'tier3': series('tier3', get(data, 'tier3.sla.current', None)),
        'content': series('content', get(data, 'content.sla.current', None)),
    }
    return {
        'month': month_label(year, month),
        'previous_month': month_label(*prev),
        'mm_yyyy': f'{month:02d}/{year}',
        'from': start.strftime('%d/%m/%Y'),
        'to': end.strftime('%d/%m/%Y'),
        'year': year,
        'sla': sla,
        'kpis_total': len(sla),
        'kpis_achieved': sum(1 for entry in sla.values() if entry['achieved']),
    }


# ── charts ───────────────────────────────────────────────────────────────────

PIE_COLORS = ('#c00000', '#767171', '#4472c4', '#ed7d31', '#a5a5a5', '#ffc000', '#5b9bd5', '#70ad47')
RED = '#e70033'
CHART_W = 451.0


def esc(value) -> str:
    """HTML-escape anything that came from data."""
    return html.escape(str(value), quote=True)


def na(value, formatter=str) -> str:
    """A value, or a visible marker when it is still missing (draft renders)."""
    return '<span class="na">N/A</span>' if value is None else esc(formatter(value))


def kpi_chart(previous, current, target: float, labels: tuple[str, str], legend: str) -> str:
    """Two bars, last month and this month, against the SLA target line.

    :returns: an inline SVG the width of the text column.
    """
    height = 158.0
    # The plot stops well short of the frame: the legend beside it has to hold
    # a label as long as "Tier 2 Ticket KPI".
    left, right, top, bottom = 49.0, 326.0, 22.0, 130.0
    values = [v for v in (previous, current) if v is not None]
    low = 50.0
    if values and min(values + [target]) < 55:
        low = max(0.0, math.floor((min(values + [target]) - 5) / 10) * 10)
    step = 5 if (100 - low) <= 50 else 10
    span = bottom - top

    def y(value: float) -> float:
        return bottom - (max(low, min(100.0, value)) - low) / (100 - low) * span

    parts = [f'<svg class="chart" viewBox="0 0 {CHART_W} {height}" xmlns="http://www.w3.org/2000/svg">',
             f'<rect x="0.4" y="0.4" width="{CHART_W - 0.8}" height="{height - 0.8}" fill="#fff" stroke="#afabab" stroke-width="0.75"/>']
    tick = low
    while tick <= 100.0001:
        ty = y(tick)
        parts.append(f'<line x1="{left}" y1="{ty:.2f}" x2="{right}" y2="{ty:.2f}" stroke="#d9d9d9" stroke-width="0.75"/>')
        parts.append(f'<text x="{left - 5}" y="{ty + 3.3:.2f}" font-size="10" text-anchor="end">{int(tick)}%</text>')
        tick += step
    centers = (left + (right - left) * 0.25, left + (right - left) * 0.75)
    for center, value, label in zip(centers, (previous, current), labels):
        if value is not None:
            by = y(value)
            parts.append(f'<rect x="{center - 30.5:.2f}" y="{by:.2f}" width="61" height="{bottom - by:.2f}" fill="{RED}"/>')
            parts.append(f'<text x="{center:.2f}" y="{by - 3:.2f}" font-size="10" text-anchor="middle">{esc(pct(value))}</text>')
        else:
            parts.append(f'<text x="{center:.2f}" y="{bottom - 6:.2f}" font-size="10" text-anchor="middle" fill="#c00000">N/A</text>')
        parts.append(f'<text x="{center:.2f}" y="{bottom + 14:.2f}" font-size="10" text-anchor="middle">{esc(label)}</text>')
    ty = y(target)
    parts.append(f'<line x1="{centers[0]:.2f}" y1="{ty:.2f}" x2="{centers[1]:.2f}" y2="{ty:.2f}" stroke="#7f7f7f" stroke-width="2.25" stroke-linecap="round"/>')
    lx = right + 18
    parts.append(f'<rect x="{lx}" y="66" width="19" height="5" fill="{RED}"/><text x="{lx + 22}" y="72" font-size="10">{esc(legend)}</text>')
    parts.append(f'<line x1="{lx}" y1="87" x2="{lx + 19}" y2="87" stroke="#7f7f7f" stroke-width="2.25" stroke-linecap="round"/>'
                 f'<text x="{lx + 22}" y="90.5" font-size="10">SLA Target</text>')
    parts.append('</svg>')
    return ''.join(parts)


def pie_chart(rows: list[dict] | None) -> str:
    """A pie with its legend, slices clockwise from twelve o'clock.

    :param rows: ``{name, count}`` in the order to draw.
    :returns: an inline SVG.
    """
    height = 170.0
    parts = [f'<svg class="chart" viewBox="0 0 {CHART_W} {height}" xmlns="http://www.w3.org/2000/svg">',
             f'<rect x="0.4" y="0.4" width="{CHART_W - 0.8}" height="{height - 0.8}" fill="#fff" stroke="#d0cece" stroke-width="0.75"/>']
    cx, cy, radius = 150.0, height / 2, 62.0
    if rows is None:
        # Not collected is not the same as none: say which, so a draft cannot
        # be read as a quiet month.
        parts.append(f'<text x="{CHART_W / 2}" y="{cy}" font-size="11" font-weight="700" text-anchor="middle" fill="#c00000">N/A — not collected yet</text></svg>')
        return ''.join(parts)
    rows = [row for row in rows if row.get('count')]
    total = sum(row['count'] for row in rows)
    if not total:
        parts.append(f'<text x="{CHART_W / 2}" y="{cy}" font-size="11" text-anchor="middle" fill="#7f7f7f">No alerts in this period</text></svg>')
        return ''.join(parts)
    angle = -math.pi / 2
    for index, row in enumerate(rows):
        color = PIE_COLORS[index % len(PIE_COLORS)]
        sweep = row['count'] / total * 2 * math.pi
        mid = angle + sweep / 2
        if len(rows) == 1:
            parts.append(f'<circle cx="{cx}" cy="{cy}" r="{radius}" fill="{color}"/>')
        else:
            x1, y1 = cx + radius * math.cos(angle), cy + radius * math.sin(angle)
            x2, y2 = cx + radius * math.cos(angle + sweep), cy + radius * math.sin(angle + sweep)
            parts.append(f'<path d="M{cx} {cy} L{x1:.2f} {y1:.2f} A{radius} {radius} 0 {1 if sweep > math.pi else 0} 1 {x2:.2f} {y2:.2f} Z" '
                         f'fill="{color}" stroke="#fff" stroke-width="1.5"/>')
        # A thin slice cannot hold its own label; put it just outside instead.
        inside = sweep > 0.45
        distance = radius * 0.62 if inside else radius + 11
        lx, ly = cx + distance * math.cos(mid), cy + distance * math.sin(mid) + 3
        parts.append(f'<text x="{lx:.2f}" y="{ly:.2f}" font-size="9" text-anchor="middle">{row["count"]}</text>')
        angle += sweep
    ly = cy - (len(rows) - 1) * 8.5
    for index, row in enumerate(rows):
        color = PIE_COLORS[index % len(PIE_COLORS)]
        parts.append(f'<rect x="258" y="{ly - 5:.2f}" width="4" height="4" fill="{color}"/>'
                     f'<text x="266" y="{ly:.2f}" font-size="9">{esc(row["name"])}</text>'
                     f'<text x="436" y="{ly:.2f}" font-size="9" text-anchor="end">{row["count"]}</text>')
        ly += 17
    parts.append('</svg>')
    return ''.join(parts)


def nice_step(maximum: float) -> float:
    """An axis step that gives at most eight gridlines."""
    if maximum <= 0:
        return 1
    raw = maximum / 8
    magnitude = 10 ** math.floor(math.log10(raw)) if raw > 0 else 1
    for factor in (1, 2, 2.5, 5, 10):
        if factor * magnitude >= raw:
            return factor * magnitude
    return 10 * magnitude


def level_chart(rows: list[dict] | None, legend: str = 'Number of alerts') -> str:
    """One bar per category, by default per alert level.

    :returns: an inline SVG.
    """
    height = 182.0
    left, right, top, bottom = 45.0, 354.0, 16.0, 152.0
    rows = rows or []
    maximum = max([row['count'] for row in rows] or [0])
    step = nice_step(maximum)
    ceiling = max(step, math.ceil(maximum / step) * step)
    parts = [f'<svg class="chart" viewBox="0 0 {CHART_W} {height}" xmlns="http://www.w3.org/2000/svg">',
             f'<rect x="0.4" y="0.4" width="{CHART_W - 0.8}" height="{height - 0.8}" fill="#fff" stroke="#a6a6a6" stroke-width="0.75"/>']
    tick = 0.0
    while tick <= ceiling + 1e-9:
        ty = bottom - tick / ceiling * (bottom - top)
        parts.append(f'<line x1="{left}" y1="{ty:.2f}" x2="{right}" y2="{ty:.2f}" stroke="#d9d9d9" stroke-width="0.75"/>')
        label = int(tick) if float(tick).is_integer() else tick
        parts.append(f'<text x="{left - 6}" y="{ty + 3.3:.2f}" font-size="10" text-anchor="end">{label}</text>')
        tick += step
    slot = (right - left) / max(1, len(rows))
    for index, row in enumerate(rows):
        center = left + slot * (index + 0.5)
        width = min(40.0, slot * 0.4)
        by = bottom - row['count'] / ceiling * (bottom - top)
        parts.append(f'<rect x="{center - width / 2:.2f}" y="{by:.2f}" width="{width:.2f}" height="{bottom - by:.2f}" fill="{RED}"/>')
        parts.append(f'<text x="{center:.2f}" y="{by - 4:.2f}" font-size="10" text-anchor="middle">{row["count"]}</text>')
        parts.append(f'<text x="{center:.2f}" y="{bottom + 14:.2f}" font-size="10" text-anchor="middle">{esc(row["name"])}</text>')
    parts.append(f'<rect x="{right + 12}" y="84" width="5" height="5" fill="{RED}"/>'
                 f'<text x="{right + 20}" y="89.5" font-size="10">{esc(legend)}</text></svg>')
    return ''.join(parts)


# ── brand ────────────────────────────────────────────────────────────────────

#: What a report looks like when no brand pack is found: neutral names and no
#: images. It is a complete brand, so a report always renders — a missing pack
#: shows as "Your Company" on the cover, which nobody mistakes for finished.
DEFAULT_BRAND = {
    'provider_name': 'YOUR COMPANY',
    'provider_legal': 'Your Company',
    'provider_short': 'the provider',
    'service_header': 'Managed Security Service',
    'report_title': 'MANAGED SECURITY SERVICE',
    'accent': '#ee0033',
    'ownership_notice': 'Documents are owned by Your Company, all forms of unauthorized copying and sharing are strictly prohibited.',
    'header_on_every_page': False,
    'solutions': {'siem': 'SIEM', 'edr': 'Endpoint Detection & Response (EDR)',
                  'nsm': 'Network Security Monitoring (NSM)'},
    'footer': {'company': 'Your Company', 'address': '', 'phone': '', 'email': '', 'website': ''},
    'images': {},
}


def brand_candidates(explicit: Path | None) -> list[Path]:
    """Where a brand pack is looked for, most specific first.

    The skill ships inside the application, which replaces it on every update,
    so a company's own pack cannot live there. It belongs with the user: in the
    workspace for one project, or in the Harness home for every report this
    person makes.

    :param explicit: the ``--brand`` argument, if given.
    :returns: the directories to try, in order.
    """
    home = Path(os.environ.get('DSH_HOME', '').strip() or Path.home() / '.dsh')
    named = os.environ.get('MSS_REPORT_BRAND', '').strip()
    return [path for path in (
        explicit,
        Path(named) if named else None,
        Path.cwd() / '.dsh' / 'report-brand',
        home / 'report-brand',
        SKILL_DIR / 'brand',
    ) if path is not None]


def find_brand(explicit: Path | None) -> tuple[dict, Path | None]:
    """Load the first brand pack found, or the neutral default.

    :param explicit: the ``--brand`` argument, if given.
    :returns: the brand and the directory it came from (``None`` for the default).
    """
    if explicit is not None and not (explicit / 'brand.json').exists():
        sys.exit(f'build_report: no brand.json in {explicit}.')
    for directory in brand_candidates(explicit):
        if (directory / 'brand.json').exists():
            return load_brand(directory), directory
    return {**DEFAULT_BRAND, '_images': {}}, None


def load_brand(directory: Path) -> dict:
    """Read a brand pack: names, footer lines and images of the issuing company.

    Kept outside the skill's own files because it is the one part that differs
    between the organisations that use this template.

    :param directory: the folder holding ``brand.json`` and its images.
    :returns: the brand, with each image inlined as a data URI.
    """
    path = directory / 'brand.json'
    brand = {**DEFAULT_BRAND, **json.loads(path.read_text(encoding='utf8'))}
    images = {}
    for key, name in (brand.get('images') or {}).items():
        file = directory / name
        if not name or not file.exists():
            continue
        kind = mimetypes.guess_type(file.name)[0] or 'image/png'
        images[key] = f'data:{kind};base64,{base64.b64encode(file.read_bytes()).decode()}'
    brand['_images'] = images
    return brand


def footer_svg(brand: dict) -> str:
    """The contact block and the two accent strokes at the foot of each page."""
    foot = brand.get('footer') or {}
    accent = esc(brand.get('accent', '#ee0033'))
    contacts, x = [], 45.5
    for tag, key in (('T:', 'phone'), ('E:', 'email'), ('W:', 'website')):
        value = foot.get(key)
        if not value:
            continue
        if contacts:
            contacts.append(f'<text x="{x:.1f}" y="58" font-size="8.4">|</text>')
            x += 8.4
        contacts.append(f'<text x="{x:.1f}" y="58" font-size="8.4" font-weight="500">'
                        f'<tspan font-weight="700" fill="{accent}">{tag}</tspan> {esc(value)}</text>')
        x += 12 + len(str(value)) * 4.25
    return (
        '<svg class="footer-art" viewBox="0 0 530 85" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg">'
        '<g font-family="\'Avenir Next\', Avenir, \'Segoe UI\', \'Helvetica Neue\', Arial, sans-serif" fill="#6d6e71">'
        f'<text x="45.9" y="32" font-size="9.9" font-weight="600" fill="{accent}">{esc(foot.get("company", ""))}</text>'
        f'<text x="45.8" y="46" font-size="8.4" font-weight="500">{esc(foot.get("address", ""))}</text>'
        + ''.join(contacts) + '</g>'
        f'<g fill="none" stroke="{accent}" stroke-width="1.1" stroke-linecap="round">'
        '<path d="M373.2 85 C395.7 54.6 434.2 45.5 470 45.5 C490 45.5 511.6 48.5 530 40.3"/>'
        '<path d="M373 85 C398.2 58 434.8 56 470 56 C494.4 56 521 47.9 530 23.2"/></g></svg>'
    )


# ── document ─────────────────────────────────────────────────────────────────

def table(head: list[str], body_rows: list[list[str]], widths: list[str], *, css: str = '',
          center: tuple[int, ...] = (0,)) -> str:
    """A table whose rows may continue on the next page under a repeated header."""
    cols = ''.join(f'<col style="width:{width}">' for width in widths)
    thead = '<thead><tr>' + ''.join(f'<th>{esc(cell)}</th>' for cell in head) + '</tr></thead>'
    rows_html = []
    for row in body_rows:
        cells = ''.join(f'<td class="{"c" if index in center else ""}">{cell}</td>' for index, cell in enumerate(row))
        rows_html.append(f'<tr>{cells}</tr>')
    return f'<table class="blk split {css}"><colgroup>{cols}</colgroup>{thead}<tbody>{"".join(rows_html)}</tbody></table>'


def lines(text: str) -> str:
    """Escape free text, keeping its line breaks."""
    return '<br>'.join(esc(part) for part in str(text).split('\n'))


def sla_sentence(entry: dict, met: str, missed: str) -> str:
    """The SLA clause for a tier: the template's wording when met, a plain one when not."""
    if entry['current'] is None:
        return '<span class="na">N/A — the SLA figure has not been provided.</span>'
    return met if entry['achieved'] else missed.format(actual=pct(entry['current']), target=pct(entry['target']))


def build_flow(data: dict, d: dict, brand: dict) -> str:
    """The body of the report as a sequence of blocks the page script lays out.

    :param data: checked report data.
    :param d: derived values from :func:`derive`.
    :param brand: the brand pack.
    :returns: the HTML of every block, in reading order.
    """
    customer = esc(get(data, 'meta.customer_name', None) or '<CUSTOMER NAME>')
    # Prose names the company as it is written in a sentence; the cover has its
    # own, usually capitalised, form.
    provider = esc(brand.get('provider_legal') or brand.get('provider_name', 'the provider'))
    short = esc(brand.get('provider_short') or brand.get('provider_legal') or brand.get('provider_name', 'the provider'))
    solutions = {'siem': 'SIEM', 'edr': 'Endpoint Detection & Response (EDR)',
                 'nsm': 'Network Security Monitoring (NSM)', **(brand.get('solutions') or {})}
    month, prev = esc(d['month']), esc(d['previous_month'])
    sla = d['sla']
    out: list[str] = []
    add = out.append

    # PART I
    status = get(data, 'overview.system_status', None) or {}
    level = status.get('level', 'ok')
    add(f'<h1 class="blk" data-break="1" data-bg="overview" data-toc="part1">PART I. OVERVIEW</h1>')
    add(f'<p class="blk lead">Alerts Monitoring &amp; Response System (Customer {customer} - SOC) in {month} recorded:</p>')
    add('<div class="blk stats">'
        f'<div><b>{na(get(data, "tier1.alert_total", None))}</b><span>Alerts</span></div>'
        f'<div><b>{na(get(data, "overview.apt_count", None))}</b><span>APT</span></div>'
        f'<div><b>{d["kpis_achieved"]}/{d["kpis_total"]}</b><span>Achieved KPIs per<br>total KPIs</span></div></div>')
    add(f'<div class="blk banner {esc(level)}">{esc(status.get("label", "Secured System"))}</div>')

    # PART II
    add('<h1 class="blk" data-break="1" data-toc="part2">PART II. DETAIL INFORMATION</h1>')
    add('<h2 class="blk" data-keep="1" data-toc="s1"><span>1.</span>Incident Response Service</h2>')
    incidents = get(data, 'incident_response.incidents', []) or []
    count = get(data, 'incident_response.incident_count', None)
    if count == 0:
        add(f'<p class="blk ind">In {month},  there is no incident on {customer}’s information security (IS) System.</p>')
    else:
        add(f'<p class="blk ind">In {month}, {na(count, pad2)} incident(s) were recorded on {customer}’s information security (IS) System:</p>')
        for incident in incidents:
            add(f'<p class="blk bullet"><span>-</span>{esc(incident.get("title", ""))}'
                f'{": " + lines(incident.get("summary", "")) if incident.get("summary") else ""}</p>')

    add('<h2 class="blk" data-keep="1" data-toc="s2"><span>2.</span>24/7 Security Monitoring Service</h2>')
    add('<h3 class="blk" data-keep="1"><span>a.</span>Alerts Report (Tier 1)</h3>')
    add(f'<p class="blk bullet"><span>-</span>Number of alerts recorded in {month}: {na(get(data, "tier1.alert_total", None))} alerts.</p>')
    add('<p class="blk bullet"><span>-</span>Tier 1 – ' + provider + f' ({short}) ' + sla_sentence(
        sla['tier1'],
        f'has completed alert processing within the commited time, achieving SLA targets above {pct(sla["tier1"]["target"])}.',
        'completed alert processing at {actual}, below the SLA target of {target}.') + '</p>')
    add('<div class="blk">' + kpi_chart(sla['tier1']['previous'], sla['tier1']['current'], sla['tier1']['target'],
                                         (d['previous_month'], d['month']), 'KPI') + '</div>')
    commentary = str(get(data, 'tier1.commentary', '') or '').strip()
    if commentary:
        add(f'<p class="blk arrow"><span>➔</span>{lines(commentary)}</p>')
    add('<p class="blk bullet" data-keep="1"><span>-</span>Alert statistics by IS solutions:</p>')
    add('<div class="blk">' + pie_chart(get(data, 'tier1.by_solution', None)) + '</div>')
    add('<p class="blk bullet" data-keep="1"><span>-</span>Alert statistics by attack category:</p>')
    add('<div class="blk">' + pie_chart(get(data, 'tier1.by_category', None)) + '</div>')
    add('<p class="blk bullet" data-keep="1"><span>-</span>Alert statistics by level:</p>')
    add('<div class="blk">' + level_chart(get(data, 'tier1.by_level', None)) + '</div>')
    rules = get(data, 'tier1.top_rules', None) or []
    add(f'<p class="blk bullet" data-keep="1"><span>-</span>List of {pad2(max(5, len(rules)) if not rules else len(rules))} rules that generating the most alerts:</p>')
    add(table(['No.', 'Rule ID', 'Description', 'Alerts Number'],
              [[str(i), f'<span class="brk">{esc(r["rule_id"])}</span>', esc(r['description']), str(r['count'])]
               for i, r in enumerate(rules, 1)],
              ['7%', '41%', '38.5%', '13.5%'], center=(0, 3)))
    objects = get(data, 'tier1.top_objects', None) or []
    add(f'<p class="blk bullet" data-keep="1"><span>-</span>List of {pad2(len(objects) or 10)} objects generating the most alerts:</p>')
    add(table(['No.', 'Object', 'Alerts Number'],
              [[str(i), esc(o['object']), str(o['count'])] for i, o in enumerate(objects, 1)],
              ['14%', '50%', '36%'], css='narrow', center=(0, 1, 2)))

    add('<h3 class="blk" data-keep="1"><span>b.</span>Ticket Report (Tier 2)</h3>')
    tickets, on_time = get(data, 'tier2.tickets_total', None), get(data, 'tier2.tickets_on_time', None)
    add(f'<p class="blk bullet"><span>-</span>Statistics for {month} has {na(tickets)} tickets created on the monitoring system, '
        f'Tier 2 – {customer} processed {na(on_time)}/{na(tickets)} tickets on time, ' + sla_sentence(
            sla['tier2'], f'achieving SLA above {pct(sla["tier2"]["target"])} as committed.',
            'reaching {actual}, below the committed SLA of {target}.') + '</p>')
    add('<div class="blk">' + kpi_chart(sla['tier2']['previous'], sla['tier2']['current'], sla['tier2']['target'],
                                         (d['previous_month'], d['month']), 'Tier 2 Ticket KPI') + '</div>')

    add('<h3 class="blk" data-keep="1"><span>c.</span>Case Report (Tier 3)</h3>')
    cases, excluded = get(data, 'tier3.cases_total', None), get(data, 'tier3.cases_excluded', None) or 0
    add(f'<p class="blk bullet"><span>-</span>Number of cases recorded on the monitoring system: {na(cases, pad2)} cases.</p>')
    deduction = ''
    if excluded:
        deduction = (f' after deducting {pad2(excluded)} case{"s" if excluded != 1 else ""} '
                     f'{esc(str(get(data, "tier3.exclusion_reason", "")).strip())}')
    add(f'<p class="blk bullet"><span>-</span>Tier 3 - {short} ' + sla_sentence(
        sla['tier3'],
        f'completed cases processing within the prescribed time, achieving SLA target above {pct(sla["tier3"]["target"])}{deduction}.',
        'completed cases processing at {actual}, below the SLA target of {target}' + deduction + '.') + '</p>')
    add('<div class="blk">' + kpi_chart(sla['tier3']['previous'], sla['tier3']['current'], sla['tier3']['target'],
                                         (d['previous_month'], d['month']), 'Tier 3 Case KPI') + '</div>')

    add('<h3 class="blk" data-keep="1"><span>d.</span>The Coverage of Security Solutions Report</h3>')
    add(f'<p class="blk bullet" data-keep="1"><span>-</span>Below is operational information of {short}\'s security monitoring solutions being deployed for {customer}:</p>')
    nsm, siem, edr = (get(data, f'coverage.{key}', None) or {} for key in ('nsm', 'siem', 'edr'))
    siem_name = esc(solutions['siem'])
    sensors_ok = nsm.get('sensors_ok') == nsm.get('sensors_total')
    condition = esc(nsm.get('condition') or ('The sensors are monitoring normally' if sensors_ok else
                                             f'{(nsm.get("sensors_total") or 0) - (nsm.get("sensors_ok") or 0)} sensor(s) are not monitoring'))

    def agents(block: dict) -> str:
        return (f'- Number of online agents: {na(block.get("online"), pad2)} agents<br>'
                f'- Number of offline agents: {na(block.get("offline"), pad2)} agents')
    add(table(['No.', 'Solution', 'Coverage', 'Condition'], [
        ['1', esc(solutions['nsm']),
         f'{na(nsm.get("sensors_ok"))}/{na(nsm.get("sensors_total"))} sensor'
         + (f'<br>Detail: {esc(nsm["detail"])}' if nsm.get('detail') else ''), condition],
        ['2', f'{siem_name} Agent', f'{na(siem.get("installed"))} installed {siem_name} agents', agents(siem)],
        ['3', esc(solutions['edr']), f'{na(edr.get("installed"))} installed EDR agents', agents(edr)],
    ], ['7%', '29%', '30%', '34%'], center=(0,)))
    add(f'<p class="blk note">(For details of {siem_name} disconnected servers, see Appendix 01<br>'
        'For details of EDR disconnected servers, see Appendix 02)</p>')

    add('<h2 class="blk" data-keep="1" data-toc="s3"><span>3.</span>Content Security Service</h2>')
    add('<h3 class="blk plain" data-keep="1">Content KPI Report</h3>')
    content_tickets = get(data, 'content.ticket_count', None)
    if content_tickets == 0:
        add(f'<p class="blk ind">In {month}, during operation and supervision process there is no content ticket from Content Analyst Team.</p>')
    else:
        add(f'<p class="blk ind">In {month}, during operation and supervision process there are {na(content_tickets, pad2)} content ticket(s) from Content Analyst Team.</p>')
    add('<div class="blk">' + kpi_chart(sla['content']['previous'], sla['content']['current'], sla['content']['target'],
                                         (d['previous_month'], d['month']), 'KPI Content') + '</div>')

    add('<h2 class="blk" data-keep="1" data-toc="s4"><span>4.</span>Alerts Optimization</h2>')
    optimization = get(data, 'optimization', None) or []
    if optimization:
        add(f'<p class="blk ind" data-keep="1">In {month}, optimization team has updated knowledge and optimized warning set of rules to enhance the quality of detecting security risks as follows:</p>')
        add(table(['No.', 'Rule', 'Optimization'],
                  [[str(i), f'<span class="brk">{esc(row["rule"])}</span>', f'<span class="brk">{lines(row["optimization"])}</span>']
                   for i, row in enumerate(optimization, 1)], ['8%', '46%', '46%'], center=(0,)))
    else:
        add(f'<p class="blk ind">In {month}, no rule optimization was required.</p>')

    add('<h2 class="blk" data-keep="1" data-toc="s5"><span>5.</span>Existing Problems and Recommendations</h2>')
    problems = get(data, 'problems', None) or []
    if problems:
        add(table(['No.', 'Existing Problems', 'Recommendations'],
                  [[str(i), lines(row['problem']), lines(row['recommendation'])] for i, row in enumerate(problems, 1)],
                  ['8%', '46%', '46%'], center=(0,)))
    else:
        add(f'<p class="blk ind">In {month}, there is no existing problem to report.</p>')

    # Appendices
    for number, key, title, head, fields, widths in (
        ('01', 'appendix_siem_offline', f'LIST OF {esc(solutions["siem"]).upper()} DISCONNECTED COMPUTERS/SERVERS',
         ['STT', 'Hostname', 'IP DCN', 'OS platform', 'Last ping', 'Status'],
         ('hostname', 'ip', 'os', 'last_ping', 'status'), ['7%', '20%', '20%', '25%', '16%', '12%']),
        ('02', 'appendix_edr_offline', 'LIST OF EDR DISCONNECTED COMPUTERS/SERVERS',
         ['STT', 'computerName', 'os', 'last_ping', 'ip_dcn', 'status'],
         ('hostname', 'os', 'last_ping', 'ip', 'status'), ['7%', '25%', '12%', '24%', '20%', '12%']),
    ):
        listed = get(data, key, None) or []
        add(f'<div class="blk apx" data-break="1" data-keep="1"><b>APPENDIX {number}</b><b>{title}</b></div>')
        if listed:
            add(table(head, [[str(i)] + [f'<span class="brk">{esc(row.get(field, ""))}</span>' for field in fields]
                             for i, row in enumerate(listed, 1)], widths, css='apxt', center=(0,)))
        else:
            add('<p class="blk ind">No disconnected computers or servers in this period.</p>')
    return '\n'.join(out)


STYLE = """
@page { size: 595.25pt 842pt; margin: 0; }
* { box-sizing: border-box; }
html { background: #e8e8e8; }
body { margin: 0; padding: 24px 0; font-family: "Times New Roman", Times, serif; font-size: 14pt; line-height: 21pt;
       color: #000; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
.page { position: relative; width: 595.25pt; height: 842pt; margin: 0 auto 24px; background: #fff center/cover no-repeat;
        overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.25), 0 4px 14px rgba(0,0,0,.08); }
.content { position: absolute; left: 72pt; top: 74pt; width: 451pt; height: 640pt; }
.hdr-logo { position: absolute; left: 66.25pt; top: 19pt; width: 90.66pt; }
.hdr-text { position: absolute; right: 72pt; top: 19pt; font-size: 14pt; line-height: 16pt; color: #7f7f7f; }
.footer-art { position: absolute; left: 40pt; top: 727pt; width: 425.75pt; height: 65pt; }
.pageno { position: absolute; left: 493.4pt; top: 765pt; font: 700 9pt/1 Arial, Helvetica, sans-serif; white-space: pre; }
.owner { position: absolute; left: 0; right: 0; top: 806pt; text-align: center; font-size: 8pt; line-height: 10pt; }
.draft { position: absolute; left: 0; right: 0; top: 380pt; text-align: center; font: 700 90pt/1 Arial, sans-serif;
         color: rgba(200,0,0,.12); transform: rotate(-30deg); pointer-events: none; }
#flow { position: absolute; left: -9999pt; top: 0; width: 451pt; }
h1 { margin: 0 0 22pt; padding-bottom: 5pt; border-bottom: 1pt solid #4f81bd; font-size: 20pt; line-height: 23pt; color: #e70033; }
h2 { margin: 0; font-size: 14pt; line-height: 21pt; color: #ee0033; }
h2 > span:first-child, h3 > span:first-child { display: inline-block; width: 18pt; }
h3 { margin: 0; padding-left: 9pt; font-size: 14pt; line-height: 21pt; }
h3.plain { padding-left: 18pt; }
p { margin: 0; text-align: justify; }
.ind { text-indent: 18pt; }
.lead { font-weight: 700; margin-bottom: 30pt; text-align: left; }
.bullet { text-indent: 13.5pt; }
.bullet > span:first-child { display: inline-block; width: 22pt; text-indent: 0; }
.arrow { padding-left: 4.5pt; text-indent: 9pt; margin-top: 6pt; }
.arrow > span:first-child { display: inline-block; width: 18pt; text-indent: 0; }
.note { font-style: italic; text-align: center; margin: 4pt 0 6pt; }
.na { color: #c00000; font-weight: 700; }
.stats { display: flex; justify-content: space-between; margin-bottom: 96pt; }
.stats div { width: 108pt; border-top: 1.5pt solid #e71340; padding-top: 6pt; text-align: center; }
.stats b { display: block; color: #e70033; }
.stats span { display: block; font-size: 10pt; line-height: 14.5pt; }
.banner { margin: 0 -2pt 0 6pt; height: 51pt; line-height: 51pt; text-align: center; color: #fff; font-size: 18pt; background: #00b050; }
.banner.warning { background: #ed7d31; } .banner.critical { background: #c00000; }
.chart { display: block; width: 451pt; margin: 2pt 0 8pt; overflow: visible; font-family: "Times New Roman", Times, serif; }
table { width: 100%; border-collapse: collapse; margin: 4pt 0 8pt; table-layout: fixed; }
table.narrow { width: 60%; margin-left: 20%; }
th { background: #ee0033; color: #fff; font-weight: 400; border: .75pt solid #fff; padding: 1pt 4pt; text-align: center; }
td { border: .75pt solid #000; padding: 1pt 5pt; vertical-align: middle; text-align: justify; }
td.c { text-align: center; }
.brk { overflow-wrap: anywhere; word-break: break-word; text-align: left; display: block; }
table.apxt { font-size: 12pt; line-height: 14pt; } table.apxt th { background: #c00000; font-size: 14pt; line-height: 21pt; }
table.apxt td { padding: 0 6pt; }
.apx { text-align: center; margin-bottom: 8pt; } .apx b { display: block; }
.cover { background-size: cover; }
.cover .logo { position: absolute; left: 61.2pt; top: 82.9pt; width: 147.7pt; }
.cover div { position: absolute; left: 61.5pt; line-height: 1; white-space: nowrap; }
/* A long customer name wraps inside the page instead of running off its edge. */
.cover div.who { width: 472pt; white-space: normal; line-height: 1.15; }
.info h4 { margin: 40pt 0 28pt; text-align: center; font-size: 16pt; }
.info p { text-indent: 36pt; line-height: 20.7pt; font-size: 12pt; }
.info .copy { text-indent: 0; text-align: center; margin-top: 60pt; }
.toc h4 { margin: 0 0 12pt; font-size: 14pt; color: #ee0033; }
.toc div { display: flex; align-items: baseline; font-size: 12pt; line-height: 19.8pt; font-weight: 700; }
.toc div.sub { font-weight: 400; font-style: italic; padding-left: 10pt; line-height: 13.8pt; }
.toc div.sub span:first-child { width: 20pt; flex: none; }
.toc i { flex: 1; border-bottom: 1pt dotted #000; margin: 0 3pt; transform: translateY(-3pt); }
@media print {
  html, body { background: none; padding: 0; }
  .page { margin: 0; box-shadow: none; break-after: page; }
  .page:last-child { break-after: auto; }
}
"""

# Lays the blocks out over fixed A4 pages by measuring them as rendered, so the
# page breaks and the table of contents are those of the real fonts rather than
# an estimate. A table continues on the next page under a repeated header; a
# heading is never left alone at the foot of a page.
SCRIPT = """
(function () {
  var flow = document.getElementById('flow');
  var tpl = document.getElementById('page-tpl');
  var host = flow.parentNode;
  var pages = [], tocPage = {}, first = document.querySelectorAll('.page.fixed').length;
  function newPage() {
    var node = tpl.content.firstElementChild.cloneNode(true);
    host.insertBefore(node, flow);
    var page = { node: node, box: node.querySelector('.content') };
    pages.push(page);
    node.querySelector('.pageno').textContent = 'P a g e  | ' + (first + pages.length);
    return page;
  }
  function overflows(page) { return page.box.scrollHeight > page.box.clientHeight + 0.5; }
  var page = newPage(), kept = [];
  function place(block) {
    page.box.appendChild(block);
    if (overflows(page) && page.box.children.length > kept.length + 1) {
      // Take the headings that introduce this block along, so none is orphaned.
      page = newPage();
      kept.forEach(function (k) { page.box.appendChild(k); });
      page.box.appendChild(block);
    }
  }
  function mark(block) {
    if (block.dataset.toc) tocPage[block.dataset.toc] = first + pages.length;
    if (block.dataset.bg) page.node.style.backgroundImage = 'url(' + window.__bg[block.dataset.bg] + ')';
  }
  Array.prototype.slice.call(flow.children).forEach(function (block) {
    if (block.dataset.break && page.box.children.length) { page = newPage(); kept = []; }
    if (block.tagName === 'TABLE' && block.classList.contains('split')) {
      var rows = Array.prototype.slice.call(block.tBodies[0].rows);
      var shell = function () { var t = block.cloneNode(true); t.tBodies[0].innerHTML = ''; return t; };
      var part = shell();
      place(part);
      rows.forEach(function (row, index) {
        part.tBodies[0].appendChild(row);
        if (overflows(page)) {
          part.tBodies[0].removeChild(row);
          if (!part.tBodies[0].rows.length) part.remove();
          page = newPage();
          if (index === 0) kept.forEach(function (k) { page.box.appendChild(k); });
          part = shell();
          page.box.appendChild(part);
          part.tBodies[0].appendChild(row);
        }
      });
      kept = [];
    } else {
      place(block);
      mark(block);
      kept = block.dataset.keep ? kept.concat([block]) : [];
    }
  });
  flow.remove();
  Object.keys(tocPage).forEach(function (id) {
    var slot = document.querySelector('[data-toc-ref="' + id + '"]');
    if (slot) slot.textContent = tocPage[id];
  });
  document.documentElement.dataset.pages = first + pages.length;
})();
"""


#: The contents page of the built-in monthly report: ``(label, ref, number)``.
MONTHLY_TOC = (
    ('PART I. OVERVIEW', 'part1', ''), ('PART II. DETAIL INFORMATION', 'part2', ''),
    ('Incident Response Service', 's1', '1.'), ('24/7 Security Monitoring Service', 's2', '2.'),
    ('Content Security Service', 's3', '3.'), ('Alerts Optimization', 's4', '4.'),
    ('Existing Problems and Recommendations', 's5', '5.'),
)


def render(data: dict, brand: dict, *, draft: bool, template: dict | None = None) -> str:
    """Build the whole document.

    :param data: report data.
    :param brand: the brand pack.
    :param draft: stamp every page as a draft (missing or unchecked data).
    :param template: a loaded template, or ``None`` for the built-in monthly report.
    :returns: one self-contained HTML file.
    """
    if template is None:
        d = derive(data)
        flow, contents = build_flow(data, d, brand), MONTHLY_TOC
        period_line = f'(from {d["from"]} to {d["to"]})'
    else:
        document = template_document(data, template, brand)
        d, flow, contents = document['d'], document['flow'], document['toc']
        period_line = f'(from {d["from"]} to {d["to"]})'
        if template.get('title'):
            brand = {**brand, 'report_title': template['title']}
    images = brand['_images']
    customer = esc(get(data, 'meta.customer_name', None) or '<CUSTOMER NAME>')
    provider = esc(brand.get('provider_name', ''))
    accent = esc(brand.get('accent', '#ee0033'))
    stamp = '<div class="draft">DRAFT</div>' if draft else ''
    header = ''
    if images.get('header_logo'):
        header += f'<img class="hdr-logo" alt="" src="{images["header_logo"]}">'
    header += f'<div class="hdr-text">{esc(brand.get("service_header", ""))}</div>'
    owner = f'<div class="owner">{esc(brand.get("ownership_notice", ""))}</div>'
    foot = footer_svg(brand) + owner

    def fixed(number: int, css: str, body: str, *, chrome: bool = True) -> str:
        page_no = f'<div class="pageno">P a g e  | {number}</div>' if chrome else ''
        return (f'<section class="page fixed">{header if chrome else ""}<div class="content {css}">{body}</div>'
                f'{foot if chrome else ""}{page_no}{stamp}</section>')

    cover_bg = f' style="background-image:url({images["cover_background"]})"' if images.get('cover_background') else ''
    cover = (
        f'<section class="page fixed cover"{cover_bg}>'
        + (f'<img class="logo" alt="" src="{images["cover_logo"]}">' if images.get('cover_logo') else '')
        + '<div style="top:252pt;font-size:20pt">REPORT</div>'
        f'<div style="top:285pt;font-size:22pt;font-weight:700;color:{accent}">{esc(brand.get("report_title", "MANAGED SECURITY SERVICE"))}</div>'
        f'<div style="top:318pt;font-size:16pt">{d["mm_yyyy"]}</div>'
        f'<div style="top:345pt;font-size:16pt">{period_line}</div>'
        f'<div class="who" style="top:471pt;font-size:24pt;font-weight:700;color:#404040">{customer}</div>'
        f'<div style="top:581pt;left:265.9pt;font-size:20pt;font-weight:700;color:{accent}">{provider}</div>'
        f'{stamp}</section>'
    )
    info = fixed(2, 'info', (
        '<h4>INFORMATION SECURITY</h4>'
        '<p>This document is considered TRADE SECRET and accurate only in PDF electronic format and is password '
        f'protected. Distribution to third parties outside {customer} is strictly prohibited without the prior '
        f'written consent of {esc(brand.get("provider_legal", brand.get("provider_name", "")))}.</p>'
        '<p>In addition to the summary report, this document is intended for technical professionals to contain '
        f'information about {customer} and its supporting systems and related technology. The information recorded '
        'in this report is considered sensitive and redistribution is restricted. This information would be a '
        'valuable tool for any attacker.</p>'
        f'<p class="copy">©{esc(brand.get("provider_legal", brand.get("provider_name", "")))} | {d["year"]}</p>'))

    def entry(label: str, ref: str, sub: str = '') -> str:
        number = f'<span>{sub}</span>' if sub else ''
        return (f'<div class="{"sub" if sub else ""}">{number}<span>{label}</span><i></i>'
                f'<span data-toc-ref="{ref}">{"2" if ref == "info" else ""}</span></div>')
    toc = fixed(3, 'toc', '<h4>CONTENT</h4>' + entry('INFORMATION SECURITY', 'info')
                + ''.join(entry(label, ref, number) for label, ref, number in contents))

    detail_header = header if brand.get('header_on_every_page') else ''
    page_template = (f'<template id="page-tpl"><section class="page">{detail_header}<div class="content"></div>'
                     f'{foot}<div class="pageno"></div>{stamp}</section></template>')
    backgrounds = json.dumps({'overview': images.get('overview_background', '')})
    title = f'{brand.get("report_title", "Managed Security Service")} — {get(data, "meta.customer_name", "")} — {d["mm_yyyy"] or d["month"]}'
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<title>{esc(title)}</title><style>{STYLE}</style></head><body>'
        f'{cover}{info}{toc}{page_template}<div id="flow">{flow}</div>'
        f'<script>window.__bg = {backgrounds};</script><script>{SCRIPT}</script></body></html>'
    )


# ── templates ────────────────────────────────────────────────────────────────
#
# The monthly report above is built in. Any other report — another customer's
# layout, a weekly or quarterly cycle — is a *template*: a directory holding a
# ``template.json`` that names the figures the report needs and lists its
# blocks in reading order. Templates live with the user, in the directory they
# are working in, so adding one never means changing this script.

#: Directories, relative to the working directory, that hold templates.
TEMPLATE_DIRS = ('report-templates', '.dsh/report-templates')

FIELD_TYPES = ('integer', 'number', 'percent', 'text', 'rows')
BLOCK_TYPES = ('part', 'section', 'subsection', 'paragraph', 'bullet', 'bullets', 'stats', 'banner',
               'kpi_chart', 'pie_chart', 'bar_chart', 'table', 'appendix', 'page_break')
#: Names every template may use in text without declaring them.
BUILTINS = ('customer', 'tenant', 'provider', 'provider_short', 'period.label', 'period.previous',
            'period.from', 'period.to', 'period.year')
PLACEHOLDER = re.compile(r'\{([A-Za-z_][\w.]*)(?:\|(\w+))?\}')
CONDITION = re.compile(r'^\s*([A-Za-z_][\w.]*)\s*(?:(>=|<=|==|!=|>|<)\s*(.+?))?\s*$')
FILTERS = ('pad2', 'pct', 'upper')


def template_roots() -> list[Path]:
    """Where templates are looked for: the working directory first."""
    home = Path(os.environ.get('DSH_HOME', '').strip() or Path.home() / '.dsh')
    return [Path.cwd() / name for name in TEMPLATE_DIRS] + [home / 'report-templates',
                                                            SKILL_DIR / 'assets' / 'templates']


def find_template(name: str) -> Path | None:
    """The directory of a template given by name or by path.

    :param name: a template name, a template directory, or its ``template.json``.
    :returns: the directory, or ``None`` when nothing matches.
    """
    direct = Path(name)
    if direct.name == 'template.json' and direct.exists():
        return direct.parent
    if (direct / 'template.json').exists():
        return direct
    for root in template_roots():
        if (root / name / 'template.json').exists():
            return root / name
    return None


def list_templates() -> list[tuple[str, Path, str]]:
    """Every template that can be named, nearest first: ``(name, directory, title)``."""
    found, seen = [], set()
    for root in template_roots():
        if not root.is_dir():
            continue
        for directory in sorted(root.iterdir()):
            if directory.name in seen or not (directory / 'template.json').exists():
                continue
            seen.add(directory.name)
            try:
                title = json.loads((directory / 'template.json').read_text(encoding='utf8')).get('title', '')
            except (OSError, json.JSONDecodeError):
                title = '(unreadable template.json)'
            found.append((directory.name, directory, str(title)))
    return found


def placeholders(text) -> list[tuple[str, str | None]]:
    """The ``{path|filter}`` references in a piece of template text."""
    return [(m.group(1), m.group(2)) for m in PLACEHOLDER.finditer(str(text or ''))]


def validate_template(template: dict) -> list[str]:
    """What is wrong with a template, in words its author can act on.

    Run before any data is collected: a block that reads a figure nobody
    declared would otherwise surface as an N/A in a finished-looking report.

    :returns: the problems; empty when the template is usable.
    """
    problems: list[str] = []
    fields = template.get('fields')
    blocks = template.get('blocks')
    if not isinstance(fields, dict) or not fields:
        problems.append('`fields` must be an object naming every figure the report needs')
        fields = {}
    if not isinstance(blocks, list) or not blocks:
        problems.append('`blocks` must be a non-empty list')
        blocks = []
    if template.get('cycle', 'month') not in ('month', 'quarter', 'range'):
        problems.append('`cycle` must be "month", "quarter" or "range" (any from–to span, e.g. a week)')
    computed = template.get('computed') or {}
    for path, spec in fields.items():
        if not isinstance(spec, dict) or spec.get('type') not in FIELD_TYPES:
            problems.append(f'fields["{path}"].type must be one of {", ".join(FIELD_TYPES)}')
            continue
        if spec.get('from', 'user') not in SOURCE_KINDS:
            problems.append(f'fields["{path}"].from must be "tool" or "user"')
        if spec['type'] == 'rows' and not (isinstance(spec.get('columns'), list) and spec['columns']):
            problems.append(f'fields["{path}"] is rows, so it needs `columns`: the keys each row carries')
        for key in ('sum_equals', 'rows_equal'):
            if spec.get(key) and spec[key] not in fields:
                problems.append(f'fields["{path}"].{key} names "{spec[key]}", which is not a field')
    known = set(fields) | set(computed) | set(BUILTINS)

    def columns_of(path) -> set[str]:
        return set((fields.get(path) or {}).get('columns') or [])

    def text_ok(where: str, text, row_columns: set[str] = frozenset()) -> None:
        for path, flt in placeholders(text):
            if path not in known and path not in row_columns:
                problems.append(f'{where}: {{{path}}} is not a field, a computed value, a row column or a built-in name')
            if flt and flt not in FILTERS:
                problems.append(f'{where}: unknown filter "{flt}" (use {", ".join(FILTERS)})')

    def path_ok(where: str, path, *, rows: bool = False) -> None:
        if not isinstance(path, str) or path not in known:
            problems.append(f'{where}: "{path}" is not a declared field')
        elif rows and (fields.get(path) or {}).get('type') != 'rows':
            problems.append(f'{where}: "{path}" must be a field of type rows')

    for path, spec in computed.items():
        if path in fields:
            problems.append(f'computed["{path}"] is also a field: a figure is either supplied or computed')
        if 'percent_of' in spec:
            pair = spec['percent_of']
            if not (isinstance(pair, list) and len(pair) == 2):
                problems.append(f'computed["{path}"].percent_of must be [part, whole]')
            else:
                for item in pair:
                    path_ok(f'computed["{path}"]', item)
        elif 'count_true' in spec:
            if not isinstance(spec['count_true'], list):
                problems.append(f'computed["{path}"].count_true must be a list of conditions')
        else:
            problems.append(f'computed["{path}"] needs `percent_of` or `count_true`')

    for index, block in enumerate(blocks):
        where = f'blocks[{index}]'
        if not isinstance(block, dict) or block.get('type') not in BLOCK_TYPES:
            problems.append(f'{where}.type must be one of {", ".join(BLOCK_TYPES)}')
            continue
        kind = block['type']
        where = f'{where} ({kind})'
        row_columns = columns_of(block.get('rows')) if block.get('rows') else set()
        if kind in ('bullets', 'pie_chart', 'bar_chart', 'table'):
            path_ok(where, block.get('rows'), rows=True)
        if kind in ('part', 'section', 'subsection', 'paragraph', 'bullet', 'bullets', 'banner'):
            if not block.get('text'):
                problems.append(f'{where} needs `text`')
            text_ok(where, block.get('text'), row_columns)
        if kind == 'appendix':
            if not block.get('title'):
                problems.append(f'{where} needs `title`')
            text_ok(where, block.get('title'))
        if kind == 'stats':
            items = block.get('items')
            if not (isinstance(items, list) and 1 <= len(items) <= 4):
                problems.append(f'{where} needs 1 to 4 `items`, each {{"value": ..., "label": ...}}')
            for item in items if isinstance(items, list) else []:
                text_ok(where, item.get('value'))
                text_ok(where, item.get('label'))
        if kind == 'kpi_chart':
            path_ok(where, block.get('previous'))
            path_ok(where, block.get('current'))
            if not is_number(block.get('target')):
                problems.append(f'{where} needs a numeric `target`, in percent')
        if kind in ('pie_chart', 'bar_chart'):
            for key in (block.get('name', 'name'), block.get('count', 'count')):
                if row_columns and key not in row_columns:
                    problems.append(f'{where}: rows of "{block.get("rows")}" have no column "{key}"')
        if kind == 'table':
            columns = block.get('columns')
            if not (isinstance(columns, list) and columns):
                problems.append(f'{where} needs `columns`')
            for column in columns if isinstance(columns, list) else []:
                if not column.get('head'):
                    problems.append(f'{where}: every column needs `head`')
                if column.get('field'):
                    if row_columns and column['field'] not in row_columns:
                        problems.append(f'{where}: rows of "{block.get("rows")}" have no column "{column["field"]}"')
                elif column.get('text'):
                    text_ok(where, column['text'], row_columns)
                else:
                    problems.append(f'{where}: column "{column.get("head")}" needs `field` or `text`')
            text_ok(where, block.get('empty'))
        for key in ('when', 'unless'):
            if block.get(key) is not None:
                match = CONDITION.match(str(block[key]))
                if not match:
                    problems.append(f'{where}.{key}: cannot read "{block[key]}" (use `path`, or `path >= 90`)')
                elif match.group(1) not in known:
                    problems.append(f'{where}.{key}: "{match.group(1)}" is not a declared field')
    return problems


def load_template(name: str) -> tuple[dict, Path]:
    """Find, read and validate a template; exit with the reasons if it is unusable."""
    directory = find_template(name)
    if directory is None:
        looked = ', '.join(str(root) for root in template_roots()[:2])
        sys.exit(f'build_report: no template "{name}". Templates are directories with a template.json, looked for in '
                 f'{looked}. Run `build_report.py templates` to list them.')
    try:
        template = json.loads((directory / 'template.json').read_text(encoding='utf8'))
    except (OSError, json.JSONDecodeError) as error:
        sys.exit(f'build_report: cannot read {directory / "template.json"}: {error}')
    problems = validate_template(template)
    if problems:
        sys.exit(f'build_report: {directory / "template.json"} is not usable:\n' + '\n'.join(f'  - {p}' for p in problems))
    return template, directory


def period_of(data: dict) -> dict:
    """The span a report covers and the equal span before it, from ``meta.period``.

    Three forms: ``{year, month}``, ``{year, quarter}``, or ``{from, to}`` with
    ISO dates, ``to`` being the last day included.

    :raises ValueError: when the period is none of these.
    """
    spec = get(data, 'meta.period', None) or {}
    year, month, quarter = spec.get('year'), spec.get('month'), spec.get('quarter')
    day = timedelta(days=1)
    if isinstance(year, int) and isinstance(month, int) and 1 <= month <= 12:
        start, end = month_bounds(year, month)
        previous = month_bounds(*previous_month(year, month))[0]
        # The monthly template prints the first day of the next month as the end.
        return {'kind': 'month', 'start': start, 'end': end, 'previous_start': previous,
                'label': month_label(year, month), 'previous_label': month_label(*previous_month(year, month)),
                'cover': f'{month:02d}/{year}', 'from': f'{start:%d/%m/%Y}', 'to': f'{end:%d/%m/%Y}', 'year': year}
    if isinstance(year, int) and isinstance(quarter, int) and 1 <= quarter <= 4:
        start, end = date(year, quarter * 3 - 2, 1), month_bounds(year, quarter * 3)[1]
        before = (year - 1, 4) if quarter == 1 else (year, quarter - 1)
        return {'kind': 'quarter', 'start': start, 'end': end, 'previous_start': date(before[0], before[1] * 3 - 2, 1),
                'label': f'Q{quarter} {year}', 'previous_label': f'Q{before[1]} {before[0]}',
                'cover': f'Q{quarter}/{year}', 'from': f'{start:%d/%m/%Y}', 'to': f'{end - day:%d/%m/%Y}', 'year': year}
    try:
        start, last = date.fromisoformat(str(spec.get('from'))), date.fromisoformat(str(spec.get('to')))
    except ValueError:
        raise ValueError('meta.period must be {year, month}, {year, quarter} or {from, to} as YYYY-MM-DD dates') from None
    if last < start:
        raise ValueError('meta.period.to is before meta.period.from')
    end = last + day
    previous = start - (end - start)
    span = lambda a, b: f'{a:%d/%m/%Y} – {b:%d/%m/%Y}'  # noqa: E731
    return {'kind': 'range', 'start': start, 'end': end, 'previous_start': previous,
            'label': span(start, last), 'previous_label': span(previous, start - day),
            'cover': '', 'from': f'{start:%d/%m/%Y}', 'to': f'{last:%d/%m/%Y}', 'year': start.year}


class Values:
    """What a template's text and conditions can name: data, computed values, built-ins."""

    def __init__(self, data: dict, template: dict, brand: dict, period: dict) -> None:
        self.data = data
        self.computed = template.get('computed') or {}
        provider = brand.get('provider_legal') or brand.get('provider_name', 'the provider')
        self.builtins = {
            'customer': get(data, 'meta.customer_name', None) or '<CUSTOMER NAME>',
            'tenant': get(data, 'meta.tenant', None),
            'provider': provider,
            'provider_short': brand.get('provider_short') or provider,
            'period.label': period['label'], 'period.previous': period['previous_label'],
            'period.from': period['from'], 'period.to': period['to'], 'period.year': period['year'],
        }

    def value(self, path: str, row: dict | None = None):
        """A named value, or ``None`` when it has not been supplied."""
        if isinstance(row, dict):
            found = get(row, path, MISSING)
            if found is not MISSING:
                return found
        if path in self.builtins:
            return self.builtins[path]
        if path in self.computed:
            return self.compute(self.computed[path])
        return get(self.data, path, None)

    def compute(self, spec: dict):
        if 'percent_of' in spec:
            part, whole = (self.value(path) for path in spec['percent_of'])
            if not (is_number(part) and is_number(whole)):
                return None
            # Nothing to do means nothing was missed.
            return float(spec.get('when_zero', 100)) if whole == 0 else round(part / whole * 100, 2)
        return sum(1 for condition in spec.get('count_true', []) if self.holds(condition))

    def holds(self, condition, row: dict | None = None) -> bool:
        """Whether a ``when`` condition is true. An unknown value makes it false."""
        match = CONDITION.match(str(condition))
        if not match:
            return False
        left = self.value(match.group(1), row)
        operator, right = match.group(2), match.group(3)
        if operator is None:
            return bool(left) and left != []
        if left is None:
            return False
        try:
            other = float(right)
        except ValueError:
            other = right.strip('"\'') if right[:1] in '"\'' else self.value(right, row)
        if other is None:
            return False
        if is_number(left) != is_number(other):
            left, other = str(left), str(other)
        return {'>=': left >= other, '<=': left <= other, '>': left > other, '<': left < other,
                '==': left == other, '!=': left != other}[operator]

    def fill(self, text, row: dict | None = None) -> str:
        """Template text as HTML: literals escaped, ``{path|filter}`` replaced."""
        out, position, text = [], 0, str(text or '')
        for match in PLACEHOLDER.finditer(text):
            out.append(lines(text[position:match.start()]))
            out.append(show(self.value(match.group(1), row), match.group(2)))
            position = match.end()
        out.append(lines(text[position:]))
        return ''.join(out)


def show(value, flt: str | None = None) -> str:
    """A value as the report prints it; a missing one is a visible N/A."""
    if value is None or value == '':
        return '<span class="na">N/A</span>'
    if flt == 'pct' and is_number(value):
        return esc(pct(value))
    if flt == 'pad2' and is_number(value):
        return esc(pad2(value))
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    text = lines(value)
    return text.upper() if flt == 'upper' else text


def check_template(data: dict, template: dict) -> Findings:
    """Validate a data file against a template's declared fields.

    The same guarantees as the built-in check: every figure present, of its
    type, consistent with the figures it is tied to, and with a recorded source.
    """
    f = Findings()
    for path in ('meta.customer_name', 'meta.tenant'):
        value = get(data, path, None)
        if not isinstance(value, str) or not value.strip():
            f.need(path, 'ask the user; a report is for exactly one tenant')
    try:
        period = period_of(data)
    except ValueError as error:
        f.error(str(error))
        return f
    wanted = template.get('cycle', 'month')
    if period['kind'] != wanted:
        f.error(f'this template is for a {wanted} period, but meta.period describes a {period["kind"]}')
    fields = template['fields']
    sources = data.get('sources') or {}
    for path, spec in fields.items():
        kind, value = spec['type'], get(data, path, None)
        if value is None or (kind == 'text' and not str(value).strip()):
            if not spec.get('optional'):
                f.need(path, spec.get('hint') or 'no value yet')
            continue
        if kind == 'text':
            if spec.get('confirm', True):
                f.warn(f'{path} is free text: show it to the user and have them confirm it before the final render.')
            continue
        if kind in ('integer', 'number', 'percent'):
            if not is_number(value) or (kind == 'integer' and int(value) != value):
                f.error(f'{path} must be {"an integer" if kind == "integer" else "a number"}, got {value!r}')
            elif value < 0 or (kind == 'percent' and value > 100):
                f.error(f'{path} = {value} is outside 0..{"100" if kind == "percent" else "∞"}')
        else:
            check_rows(f, data, path, spec, value)
        entry = sources.get(path)
        if not isinstance(entry, dict) or entry.get('by') not in SOURCE_KINDS:
            f.error(f'sources["{path}"] is missing: record {{"by": "tool"|"user", "ref": "..."}} for every '
                    'figure, so nothing estimated or remembered reaches the report')
        elif not str(entry.get('ref') or '').strip():
            f.error(f'sources["{path}"].ref is empty: name the tool call and its filters, or what the user said')
    return f


def check_rows(f: Findings, data: dict, path: str, spec: dict, value) -> None:
    """The checks on one ``rows`` field: shape, numbers, and its ties to other figures."""
    if not isinstance(value, list) or not all(isinstance(row, dict) for row in value):
        f.error(f'{path} must be a list of objects')
        return
    numeric = spec.get('numeric') or (['count'] if 'count' in spec['columns'] else [])
    loose = set(spec.get('optional_columns') or [])
    for index, row in enumerate(value):
        for column in spec['columns']:
            if column in numeric:
                if not (is_number(row.get(column)) and row[column] >= 0):
                    f.error(f'{path}[{index}].{column} must be a non-negative number')
                    return
            elif column not in loose and row.get(column) in (None, ''):
                f.error(f'{path}[{index}].{column} is empty')
    if spec.get('max_rows') and len(value) > spec['max_rows']:
        f.error(f'{path} has {len(value)} rows; the template lists at most {spec["max_rows"]}')
    column = spec.get('sorted_desc')
    if column:
        order = [row.get(column) for row in value]
        if order != sorted(order, reverse=True):
            f.error(f'{path} must be ordered by {column}, largest first')
    total_path = spec.get('sum_equals')
    total = get(data, total_path, None) if total_path else None
    if is_number(total):
        column = spec.get('sum_column', 'count')
        summed = sum(row.get(column) or 0 for row in value)
        if summed != total:
            f.error(f'{path} sums to {summed} but {total_path} is {total}: the rows must account for every one '
                    '(find the missing bucket with a query, or re-run the counts over the same period and tenant)')
    count_path = spec.get('rows_equal')
    count = get(data, count_path, None) if count_path else None
    if is_number(count) and len(value) != count:
        f.error(f'{path} lists {len(value)} rows but {count_path} is {count}: it must list every one, no more and no fewer')


def template_document(data: dict, template: dict, brand: dict) -> dict:
    """Turn a template's blocks into the flow the page script lays out.

    :returns: ``flow`` (HTML), ``toc`` entries as ``(label, ref, number)``, and
        the ``d`` values the cover and the front pages print.
    """
    period = period_of(data)
    values = Values(data, template, brand, period)
    fill = values.fill
    out: list[str] = []
    toc: list[tuple[str, str, str]] = []
    section = sub = 0

    def keep(block: dict, default: bool = False) -> str:
        return ' data-keep="1"' if block.get('keep', default) else ''

    def rows_of(block: dict):
        value = values.value(block['rows'])
        return value if isinstance(value, list) else None

    def build_table(block: dict, css: str = '') -> str:
        rows = rows_of(block)
        if not rows:
            text = '<span class="na">N/A — not collected yet.</span>' if rows is None else fill(
                block.get('empty') or 'None in this period.')
            return f'<p class="blk ind">{text}</p>'
        columns = block['columns']
        numbered = block.get('numbered', True)
        given = [column.get('width') for column in columns]
        share = (100 - (7 if numbered else 0) - sum(float(w.rstrip('%')) for w in given if w)) / max(1, given.count(None))
        widths = (['7%'] if numbered else []) + [w or f'{share:.2f}%' for w in given]
        center = tuple(i + numbered for i, column in enumerate(columns) if column.get('align') == 'center')
        body = []
        for index, row in enumerate(rows, 1):
            cells = []
            for column in columns:
                cell = show(row.get(column['field']), column.get('filter')) if column.get('field') else fill(column['text'], row)
                cells.append(f'<span class="brk">{cell}</span>' if column.get('wrap') else cell)
            body.append(([str(index)] if numbered else []) + cells)
        head = ([block.get('number_head', 'No.')] if numbered else []) + [column['head'] for column in columns]
        return table(head, body, widths, css=css or block.get('style', ''), center=((0,) if numbered else ()) + center)

    for index, block in enumerate(template['blocks']):
        if block.get('when') is not None and not values.holds(block['when']):
            continue
        if block.get('unless') is not None and values.holds(block['unless']):
            continue
        kind = block['type']
        ref = f't{index}'
        if kind == 'part':
            section = sub = 0
            background = f' data-bg="{esc(block["background"])}"' if block.get('background') else ''
            out.append(f'<h1 class="blk" data-break="1" data-toc="{ref}"{background}>{fill(block["text"])}</h1>')
            toc.append((fill(block['text']), ref, ''))
        elif kind == 'section':
            section, sub = section + 1, 0
            out.append(f'<h2 class="blk" data-keep="1" data-toc="{ref}"><span>{section}.</span>{fill(block["text"])}</h2>')
            toc.append((fill(block['text']), ref, f'{section}.'))
        elif kind == 'subsection':
            if block.get('number', True):
                sub += 1
                letter = chr(ord('a') + (sub - 1) % 26)
                out.append(f'<h3 class="blk" data-keep="1"><span>{letter}.</span>{fill(block["text"])}</h3>')
            else:
                out.append(f'<h3 class="blk plain" data-keep="1">{fill(block["text"])}</h3>')
        elif kind == 'paragraph':
            style = block.get('style', 'ind')
            css = {'lead': 'lead', 'note': 'note', 'arrow': 'arrow'}.get(style, 'ind')
            lead = '<span>➔</span>' if css == 'arrow' else ''
            out.append(f'<p class="blk {css}"{keep(block)}>{lead}{fill(block["text"])}</p>')
        elif kind == 'bullet':
            out.append(f'<p class="blk bullet"{keep(block)}><span>-</span>{fill(block["text"])}</p>')
        elif kind == 'bullets':
            rows = rows_of(block)
            if rows is None:
                out.append('<p class="blk bullet"><span>-</span><span class="na">N/A — not collected yet.</span></p>')
            for row in rows or []:
                out.append(f'<p class="blk bullet"><span>-</span>{fill(block["text"], row)}</p>')
        elif kind == 'stats':
            out.append('<div class="blk stats">' + ''.join(
                f'<div><b>{fill(item.get("value"))}</b><span>{fill(item.get("label"))}</span></div>'
                for item in block['items']) + '</div>')
        elif kind == 'banner':
            level = str(block.get('level', 'ok'))
            level = str(values.value(level[1:-1]) or 'ok') if level.startswith('{') and level.endswith('}') else level
            out.append(f'<div class="blk banner {esc(level)}">{fill(block["text"])}</div>')
        elif kind == 'kpi_chart':
            out.append('<div class="blk">' + kpi_chart(
                values.value(block['previous']), values.value(block['current']), float(block['target']),
                (period['previous_label'], period['label']), str(block.get('legend', 'KPI'))) + '</div>')
        elif kind in ('pie_chart', 'bar_chart'):
            rows = rows_of(block)
            if rows is not None:
                rows = [{'name': row.get(block.get('name', 'name')), 'count': row.get(block.get('count', 'count')) or 0}
                        for row in rows]
            chart = pie_chart(rows) if kind == 'pie_chart' else level_chart(rows, str(block.get('legend', 'Number of alerts')))
            out.append(f'<div class="blk">{chart}</div>')
        elif kind == 'table':
            out.append(build_table(block))
        elif kind == 'appendix':
            title = ''.join(f'<b>{fill(line)}</b>' for line in str(block['title']).split('\n'))
            out.append(f'<div class="blk apx" data-break="1" data-keep="1">{title}</div>')
        elif kind == 'page_break':
            out.append('<div class="blk" data-break="1"></div>')
    return {'flow': '\n'.join(out), 'toc': toc,
            'd': {'month': period['label'], 'mm_yyyy': period['cover'],
                  'from': period['from'], 'to': period['to'], 'year': period['year']}}


def blank_from_template(template: dict, name: str, customer: str, tenant: str, period: dict, utc_offset: float) -> dict:
    """A data file for a template: identity filled in, every declared figure still ``null``."""
    data: dict = {'meta': {'template': name, 'customer_name': customer, 'tenant': tenant,
                           'period': period, 'utc_offset_hours': utc_offset}}
    for path, spec in template['fields'].items():
        node = data
        *parents, leaf = path.split('.')
        for key in parents:
            node = node.setdefault(key, {})
        node[leaf] = '' if spec['type'] == 'text' else None
    data['sources'] = {}
    return data


# ── command line ─────────────────────────────────────────────────────────────

CHROME_CANDIDATES = (
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    'google-chrome', 'chromium', 'chromium-browser', 'microsoft-edge',
    r'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    r'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
)


def find_browser() -> str | None:
    """A Chromium-family browser to print with, if this machine has one."""
    for candidate in CHROME_CANDIDATES:
        if Path(candidate).exists():
            return candidate
        found = shutil.which(candidate)
        if found:
            return found
    return None


def print_pdf(html_path: Path) -> Path | None:
    """Print the report to PDF beside it.

    :returns: the PDF path, or ``None`` when no browser could do it.
    """
    browser = find_browser()
    if browser is None:
        return None
    pdf = html_path.with_suffix('.pdf')
    subprocess.run([browser, '--headless=new', '--disable-gpu', '--no-pdf-header-footer',
                    '--virtual-time-budget=5000', f'--print-to-pdf={pdf}', html_path.resolve().as_uri()],
                   check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
    return pdf if pdf.exists() else None


def blank(customer: str, tenant: str, year: int, month: int, utc_offset: float) -> dict:
    """A data file with the identity filled in and every figure still to find.

    ``null`` is the honest starting value: ``check`` lists each one as needing
    a tool call or an answer from the user, so nothing is left at a default
    that could pass for a real figure.
    """
    sla = {'previous': None, 'current': None}
    return {
        'meta': {'customer_name': customer, 'tenant': tenant,
                 'period': {'year': year, 'month': month}, 'utc_offset_hours': utc_offset},
        'overview': {'apt_count': None, 'system_status': {'label': 'Secured System', 'level': 'ok'}},
        'incident_response': {'incident_count': None, 'incidents': []},
        'tier1': {'alert_total': None, 'sla': dict(sla), 'commentary': '', 'by_solution': None,
                  'by_category': None, 'by_level': None, 'top_rules': None, 'top_objects': None},
        'tier2': {'tickets_total': None, 'tickets_on_time': None, 'sla': {'previous': None}},
        'tier3': {'cases_total': None, 'cases_excluded': None, 'exclusion_reason': '', 'sla': dict(sla)},
        'coverage': {'nsm': None, 'siem': None, 'edr': None},
        'content': {'ticket_count': None, 'sla': dict(sla)},
        'optimization': None,
        'problems': [],
        'appendix_siem_offline': None,
        'appendix_edr_offline': None,
        'sources': {},
    }


def period_bounds(data: dict) -> dict:
    """The report month as the bounds every tool query must use.

    Computed here rather than by the agent: an off-by-one day or a wrong
    time zone silently changes every count in the report.

    :returns: the half-open period in epoch milliseconds and ISO form, for
        this month and for the month before it.
    """
    period = period_of(data)
    zone = timezone(timedelta(hours=float(get(data, 'meta.utc_offset_hours', 7))))

    def bounds(label: str, start: date, end: date) -> dict:
        first = datetime(start.year, start.month, start.day, tzinfo=zone)
        last = datetime(end.year, end.month, end.day, tzinfo=zone)
        return {'label': label,
                'from_ms': int(first.timestamp() * 1000), 'to_ms': int(last.timestamp() * 1000) - 1,
                'from_iso': first.isoformat(), 'to_exclusive_iso': last.isoformat()}
    unit = 'month' if period['kind'] == 'month' else 'period'
    return {'tenant': get(data, 'meta.tenant', None),
            f'this_{unit}': bounds(period['label'], period['start'], period['end']),
            f'previous_{unit}': bounds(period['previous_label'], period['previous_start'], period['start'])}


def report(findings: Findings, tools: tuple[str, ...] = FROM_TOOLS) -> None:
    """Print what ``check`` found, most blocking first.

    :param tools: the figures a tool can answer; the rest are asked of the user.
    """
    from_tools = [(path, why) for path, why in findings.needs_input if path in tools]
    from_user = [(path, why) for path, why in findings.needs_input if path not in tools]
    if from_tools:
        print(f'COLLECT WITH TOOLS ({len(from_tools)}) — query the platform for the report tenant and period:')
        for path, why in from_tools:
            print(f'  - {path} — {why}')
    if from_user:
        print(f'ASK THE USER ({len(from_user)}) — no tool holds these; do not guess or carry over:')
        for path, why in from_user:
            print(f'  - {path} — {why}')
    if findings.errors:
        print(f'ERRORS ({len(findings.errors)}):')
        for item in findings.errors:
            print(f'  - {item}')
    if findings.warnings:
        print(f'WARNINGS ({len(findings.warnings)}):')
        for item in findings.warnings:
            print(f'  - {item}')
    if not findings.blocking:
        print('OK: the figures are consistent and every one has a recorded source.')


def write_sources(data: dict, label: str, path: Path) -> None:
    """Write the audit sheet: where each figure in the report came from."""
    rows = ['# Data sources', '', f'Report: {get(data, "meta.customer_name", "")} — {label} '
            f'(tenant `{get(data, "meta.tenant", "")}`), generated {datetime.now():%Y-%m-%d %H:%M}.', '',
            '| Figure | Supplied by | Reference |', '|---|---|---|']
    for key, entry in sorted((data.get('sources') or {}).items()):
        rows.append(f'| `{key}` | {entry.get("by", "")} | {str(entry.get("ref", "")).replace("|", "/")} |')
    rows += ['', 'Computed by the renderer: percentages from counts, KPIs achieved, period labels.']
    path.write_text('\n'.join(rows) + '\n', encoding='utf8')


#: The smallest useful template, written when there is no example to copy.
STARTER = {
    'title': 'SECURITY MONITORING REPORT',
    'cycle': 'month',
    'fields': {
        'alerts.total': {'type': 'integer', 'from': 'tool', 'hint': 'soar_search_alerts over the period and tenant: the count field'},
        'alerts.by_level': {'type': 'rows', 'columns': ['name', 'count'], 'sum_equals': 'alerts.total', 'from': 'tool',
                            'hint': 'soar_group_alerts field=severity'},
        'commentary': {'type': 'text', 'from': 'user', 'optional': True},
    },
    'computed': {},
    'blocks': [
        {'type': 'part', 'text': 'PART I. OVERVIEW', 'background': 'overview'},
        {'type': 'paragraph', 'style': 'lead', 'text': 'Security monitoring for {customer} in {period.label} recorded:'},
        {'type': 'stats', 'items': [{'value': '{alerts.total}', 'label': 'Alerts'}]},
        {'type': 'part', 'text': 'PART II. DETAIL'},
        {'type': 'section', 'text': 'Alerts'},
        {'type': 'bullet', 'text': 'Alerts by level:', 'keep': True},
        {'type': 'bar_chart', 'rows': 'alerts.by_level'},
        {'type': 'paragraph', 'style': 'arrow', 'text': '{commentary}', 'when': 'commentary'},
    ],
}


def new_template(name: str, like: str) -> int:
    """Start a template in the working directory from an existing one."""
    source = find_template(like)
    target = Path(name) if len(Path(name).parts) > 1 else Path.cwd() / TEMPLATE_DIRS[0] / name
    if target.exists():
        print(f'build_report: {target} already exists; not overwritten.', file=sys.stderr)
        return 2
    if source is None:
        # A copy of this script run from a workspace has no shipped examples
        # beside it; a bare skeleton is still a valid place to start.
        target.mkdir(parents=True)
        (target / 'template.json').write_text(json.dumps(STARTER, indent=2, ensure_ascii=False) + '\n', encoding='utf8')
        print(f'wrote: {target / "template.json"} (a bare skeleton: no template "{like}" was found to copy)\n'
              'Edit its fields and blocks, then run `check-template` on it.')
        return 0
    shutil.copytree(source, target)
    example = target / 'example-data.json'
    if example.exists():
        # The preview data travels with the copy and must name it, not its origin.
        sample = json.loads(example.read_text(encoding='utf8'))
        sample.setdefault('meta', {})['template'] = target.name
        example.write_text(json.dumps(sample, indent=2, ensure_ascii=False) + '\n', encoding='utf8')
    print(f'wrote: {target / "template.json"} (a copy of "{like}")\n'
          'Edit its fields and blocks, then run `check-template` on it.')
    return 0


def main() -> int:
    """Run one command.

    :returns: 0 when clean, 2 when the data blocks a final report.
    """
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=('init', 'period', 'check', 'render',
                                            'templates', 'new-template', 'check-template'))
    parser.add_argument('data', type=Path, nargs='?',
                        help='the data file; for new-template and check-template, the template name or directory')
    parser.add_argument('--customer', help='customer name as it should appear in the report (init)')
    parser.add_argument('--tenant', help='the tenant id every query is scoped to (init)')
    parser.add_argument('--template', help='a template name or directory (init); omit for the built-in monthly report')
    parser.add_argument('--like', default='weekly-summary', help='the template a new one starts as a copy of (new-template)')
    parser.add_argument('--year', type=int, help='report year (init)')
    parser.add_argument('--month', type=int, help='report month, 1-12 (init)')
    parser.add_argument('--quarter', type=int, help='report quarter, 1-4 (init, quarterly templates)')
    parser.add_argument('--from', dest='start', help='first day, YYYY-MM-DD (init, templates over a date range)')
    parser.add_argument('--to', dest='last', help='last day included, YYYY-MM-DD (init, templates over a date range)')
    parser.add_argument('--utc-offset', type=float, default=7.0,
                        help='hours east of UTC that the period boundaries are taken in (init, default 7)')
    parser.add_argument('--out', type=Path, help='the HTML file to write (render)')
    parser.add_argument('--brand', type=Path,
                        help='brand pack directory (default: the template\'s own, then .dsh/report-brand in the '
                             'workspace, then ~/.dsh/report-brand)')
    parser.add_argument('--pdf', action='store_true', help='also print a PDF with a local Chromium-family browser')
    parser.add_argument('--allow-draft', action='store_true',
                        help='render even with missing or inconsistent data, stamped DRAFT on every page')
    args = parser.parse_args()

    if args.command == 'templates':
        print('monthly-mss  (built in)  MANAGED SECURITY SERVICE — monthly; used when init is given no --template')
        for name, directory, title in list_templates():
            print(f'{name}  ({directory})  {title}')
        print(f'\nA new template is a directory with a template.json under ./{TEMPLATE_DIRS[0]}/ of the working directory.')
        return 0
    if args.data is None:
        parser.error(f'{args.command} needs a path')
    if args.command == 'new-template':
        return new_template(str(args.data), args.like)
    if args.command == 'check-template':
        template, directory = load_template(str(args.data))
        tools = sum(1 for spec in template['fields'].values() if spec.get('from') == 'tool')
        print(f'OK: {directory / "template.json"} — {len(template["blocks"])} blocks, {len(template["fields"])} fields '
              f'({tools} from tools, {len(template["fields"]) - tools} from the user), cycle {template.get("cycle", "month")}.')
        return 0

    if args.command == 'init':
        if not (args.customer and args.tenant):
            parser.error('init needs --customer and --tenant')
        if args.data.exists():
            print(f'build_report: {args.data} already exists; not overwritten.', file=sys.stderr)
            return 2
        if args.template:
            template, directory = load_template(args.template)
            if args.start and args.last:
                period = {'from': args.start, 'to': args.last}
            elif args.year and args.quarter:
                period = {'year': args.year, 'quarter': args.quarter}
            else:
                period = {'year': args.year, 'month': args.month}
            try:
                kind = period_of({'meta': {'period': period}})['kind']
            except ValueError as error:
                parser.error(f'init: {error}. Give --year --month, --year --quarter, or --from --to.')
            if kind != template.get('cycle', 'month'):
                parser.error(f'template "{directory.name}" is for a {template.get("cycle", "month")} period; '
                             f'the options given describe a {kind}')
            # Recorded as a path when the template is not in a place it would be found by name.
            named = directory.name if find_template(directory.name) == directory else str(directory)
            blank_data = blank_from_template(template, named, args.customer, args.tenant, period, args.utc_offset)
        else:
            if not (args.year and args.month and 1 <= args.month <= 12):
                parser.error('init needs --year and --month (1-12), or --template for another kind of report')
            blank_data = blank(args.customer, args.tenant, args.year, args.month, args.utc_offset)
        args.data.parent.mkdir(parents=True, exist_ok=True)
        args.data.write_text(json.dumps(blank_data, indent=2, ensure_ascii=False) + '\n', encoding='utf8')
        print(f'wrote: {args.data}')
        return 0
    try:
        data = json.loads(args.data.read_text(encoding='utf8'))
    except (OSError, json.JSONDecodeError) as error:
        print(f'build_report: cannot read {args.data}: {error}', file=sys.stderr)
        return 2
    if args.command == 'period':
        try:
            print(json.dumps(period_bounds(data), indent=2))
        except ValueError as error:
            print(f'build_report: {error}', file=sys.stderr)
            return 2
        return 0
    template, template_dir = None, None
    if get(data, 'meta.template', None):
        template, template_dir = load_template(str(data['meta']['template']))
        findings = check_template(data, template)
        report(findings, tuple(path for path, spec in template['fields'].items() if spec.get('from') == 'tool'))
    else:
        findings = check(data)
        report(findings)
    if args.command == 'check':
        return 2 if findings.blocking else 0
    if findings.blocking and not args.allow_draft:
        print('\nNot rendered. Resolve the items above, or pass --allow-draft for a stamped draft.')
        return 2
    if args.out is None:
        parser.error('render needs --out')
    try:
        label = period_of(data)['label']
    except ValueError as error:
        print(f'build_report: {error}', file=sys.stderr)
        return 2
    # A template made for one customer may carry that customer's own brand pack.
    own_brand = template_dir if template_dir is not None and (template_dir / 'brand.json').exists() else None
    brand, brand_dir = find_brand(args.brand or own_brand)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(render(data, brand, draft=findings.blocking, template=template), encoding='utf8')
    print(f'\nwrote: {args.out}{" (DRAFT)" if findings.blocking else ""}')
    if template_dir is not None:
        print(f'template: {template_dir}')
    if brand_dir is None:
        print('brand: none found, so the report carries placeholder names and no logo. Put a brand pack '
              f'(brand.json and its images) in {Path.home() / ".dsh" / "report-brand"} or in '
              '.dsh/report-brand of the workspace; see brand.example beside this skill.')
    else:
        print(f'brand: {brand_dir}')
    sources = args.out.with_suffix('.sources.md')
    write_sources(data, label, sources)
    print(f'wrote: {sources}')
    if args.pdf:
        pdf = print_pdf(args.out)
        print(f'wrote: {pdf}' if pdf else 'No Chromium-family browser found: open the HTML and print it to PDF (A4, no margins, background graphics on).')
    return 0


if __name__ == '__main__':
    sys.exit(main())
