---
name: monthly-mss-report
description: Produce the monthly Managed Security Service report for one customer tenant in the fixed A4 template (cover, overview, SLA charts for Tier 1/2/3 and Content, alert statistics, agent coverage, optimization, problems, offline-agent appendices), as HTML ready to print to PDF. Also produces weekly, quarterly or customer-specific reports from templates kept in the working directory, and turns a sample report the user provides into a new template.
whenToUse: The user asks for a monthly SOC / MSS / managed security service report, a "báo cáo tháng" (or tuần / quý) for a customer or tenant, to fill in a report template, or to add, change or list report templates ("thêm template báo cáo").
---

# Monthly Managed Security Service report

You collect figures into one `data.json`. A script checks them and renders the report. You never write
the report's HTML, draw a chart, compute a percentage, or count rows yourself.

Everything lives beside this file; call it `$SKILL` (the directory the `skill` tool reported):

- `scripts/build_report.py` — `init`, `period`, `check`, `render`
- `references/data-collection.md` — which tool answers which figure, and how to record it
- `references/data-contract.md` — the shape of `data.json` for the built-in monthly report
- `references/template-format.md` — how a template is written; read it before creating or editing one

Speak to the user in their language. The report itself is in English, as the template is.

**If the shell cannot run the script where it is** (the skill ships inside the application, and a
sandboxed shell may not reach it): read `scripts/build_report.py` with the file-read tool, write a copy
to `reports/.tools/build_report.py` in the workspace, and run that copy instead. It needs nothing beside
itself and Python 3.

**The company's names and logo** come from a brand pack — a `brand.json` and its images. The script
looks in `.dsh/report-brand` of the workspace, then in `report-brand` under the Harness home
(`~/.dsh`), and says which it used. With none, the report renders with placeholder names and no logo:
tell the user, and point them at `brand.example` beside this file.

## Which report

Run `python3 "$SKILL/scripts/build_report.py" templates` first. It lists the built-in monthly report
and every template in `report-templates/` of the working directory.

- The user wants the standard monthly report and no template in the workspace is for that customer:
  use the built-in one (no `--template`).
- A template in the workspace matches the customer or the cycle the user asked for: use it, and say
  which. If more than one could match, ask.
- The user wants a layout none of them gives: make a template first (see "Adding a template").

With a template the procedure below is the same, with three differences: `init` takes
`--template <name>` and the period its cycle needs (`--year --month`, `--year --quarter`, or
`--from --to`); the figures to collect are the template's `fields`, which `check` lists with the hint
the template gives for each; and `references/data-collection.md` is a guide to which tool answers what,
not a list to work down.

## Rules that are not negotiable

1. **One tenant, one period.** Every query carries the tenant and the exact period bounds printed by
   `period` — a calendar month for the built-in report. A figure for another tenant, or for "the last
   30 days", is a wrong figure.
2. **A number is a count the platform returned, or an answer the user gave.** Never estimate, never
   extrapolate from a page of results, never reuse a figure from an earlier report or conversation.
   A page of 50 results tells you about 50 results; the total is the `count` field of the response.
3. **Record where each figure came from** in `sources`, as you write the figure — the tool and its
   filters, or the user's own words. `check` rejects a figure with no source.
4. **What no tool can answer, ask.** SLA results, APT count, incidents, content tickets and the
   optimization list are known to the service team, not to the tools. Ask the user; do not look for a
   stand-in.
5. **If a figure cannot be obtained, leave it `null`** and say so. A stamped draft with a visible gap
   is a correct outcome. A complete-looking report with an invented number is not.
6. **`check` decides, not you.** If totals do not add up, the data is wrong: re-query, do not adjust a
   number to make the sum work.

## Procedure

1. **Scope.** Ask the user, in one question set: customer name as it should be printed, tenant id, and
   the month. Confirm the tenant exists with the tenant-listing tools before going on.
2. **Start the data file** in the workspace, never inside the skill directory:

   ```bash
   python3 "$SKILL/scripts/build_report.py" init reports/<tenant>-<yyyy>-<mm>/data.json \
     --customer "<name>" --tenant <tenant> --year <yyyy> --month <m>
   python3 "$SKILL/scripts/build_report.py" period reports/<tenant>-<yyyy>-<mm>/data.json
   ```

   `period` prints the bounds in epoch milliseconds for this month and the previous one. Use those
   exact values in every time filter.
3. **Collect what tools can answer.** Read `references/data-collection.md` and work down its table.
   Write each figure and its source into `data.json` as soon as you have it.
4. **Check.**

   ```bash
   python3 "$SKILL/scripts/build_report.py" check reports/<tenant>-<yyyy>-<mm>/data.json
   ```

   It prints three lists: figures still to collect with tools, figures to ask the user for, and
   errors. Fix errors by re-querying.
5. **Ask the user for the rest**, in one question set built from the "ASK THE USER" list: SLA results
   for this month and last month per tier, tickets processed on time, Tier 3 cases deducted from the
   SLA with the reason, APT count, incidents, content tickets, rules optimized this month.
   Record each answer with `"by": "user"` and what they said.
6. **Narrative.** The only free text is `tier1.commentary` (why the alert volume changed against last
   month), incident summaries, and `problems`. Draft them from the collected figures only, show them to
   the user, and keep the wording they confirm. Offline agents belong in `problems`, one row per
   solution, with the count taken from `coverage`.
7. **Render** once `check` prints OK:

   ```bash
   python3 "$SKILL/scripts/build_report.py" render reports/<tenant>-<yyyy>-<mm>/data.json \
     --out reports/<tenant>-<yyyy>-<mm>/report.html --pdf
   ```

   It writes `report.html`, `report.pdf` when a Chromium-family browser is installed, and
   `report.sources.md`, the audit sheet. If the user wants to see progress before everything is in,
   add `--allow-draft`: every page is stamped DRAFT and missing figures show as N/A.
8. **Hand over.** Give the paths, list anything still `null` and why, and repeat the warnings `check`
   printed. Present the files with the file-presenting tool when it is available.

## When something does not fit

- A breakdown does not sum to the total: a bucket is missing, or the queries used different bounds.
  Find the missing bucket with a query that excludes the known ones. Do not add an "Other" row to
  close the gap unless a query returned it.
- A top-5 or top-10 list, or a breakdown, comes from `soar_group_alerts`, which counts every alert of
  the month. A ranking built from the rows of a search is not a ranking: a page is a sample. If the
  grouping reports `truncated`, the month is too large to read in one go — split the period and add
  the counts, or leave the figure `null` and say so.
- A tool fails or a system is unreachable: leave its figures `null`, say which system, and offer a
  draft. Do not substitute another system's data.
- The user wants different wording in a standard sentence: those sentences come from the renderer so
  that they always agree with the figures. Change the figures or the narrative fields, not the HTML.

## Adding a template

The user can add a report layout in conversation: they give a sample (an HTML, PDF or DOCX of a past
report, or a description), and you turn it into a template in **their working directory**. Never write
into the skill directory; the application replaces it on every update.

1. Read the sample. List for the user what you found: the sections in order, each chart and table,
   the period it covers, and every figure it states. Ask what you cannot tell from one sample — which
   sentences are fixed and which change, the SLA targets, whether a section can be absent.
2. Start from the shipped example and read the format reference:

   ```bash
   python3 "$SKILL/scripts/build_report.py" new-template <customer>-<cycle>
   ```

   That writes `report-templates/<customer>-<cycle>/template.json` and an `example-data.json` beside it.
3. Rewrite `template.json` for the sample: declare every figure under `fields` (its type, whether a
   tool or the user supplies it, and a `hint` naming the tool and filter), then list the `blocks` in
   reading order. Figures that follow from others go under `computed`, never under `fields`.
4. Validate, and fix what it reports, until it prints OK:

   ```bash
   python3 "$SKILL/scripts/build_report.py" check-template <customer>-<cycle>
   ```

5. Rewrite `example-data.json` with the sample's own figures (mark each source `"by": "user"`,
   `"ref": "sample report"`), render it, and show the user the result beside their sample:

   ```bash
   python3 "$SKILL/scripts/build_report.py" render report-templates/<name>/example-data.json \
     --out report-templates/<name>/preview.html --pdf
   ```

6. Change the template as the user asks, re-render, repeat. The example data is for the preview only:
   a real report starts from `init`, with every figure `null`.

A template can only use the blocks the renderer has (headings, paragraphs, bullets, figures in a row,
a status banner, KPI / pie / bar charts, tables, appendices). If the sample needs something else — a
different page design, a chart type that is not there — say so plainly and offer the closest block;
do not write HTML by hand to imitate it. The cover, the confidentiality page, the contents page, the
page header and footer are the same for every template and take their names and logo from the brand
pack; a template made for one customer may carry its own `brand.json` and images in its directory.
