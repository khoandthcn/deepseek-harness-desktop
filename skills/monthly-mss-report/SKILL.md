---
name: monthly-mss-report
description: Produce the monthly Managed Security Service report for one customer tenant in the fixed A4 template (cover, overview, SLA charts for Tier 1/2/3 and Content, alert statistics, agent coverage, optimization, problems, offline-agent appendices), as HTML ready to print to PDF.
whenToUse: The user asks for a monthly SOC / MSS / managed security service report, a "báo cáo tháng" for a customer or tenant, or to fill in the monthly report template.
---

# Monthly Managed Security Service report

You collect figures into one `data.json`. A script checks them and renders the report. You never write
the report's HTML, draw a chart, compute a percentage, or count rows yourself.

Everything lives beside this file; call it `$SKILL` (the directory the `skill` tool reported):

- `scripts/build_report.py` — `init`, `period`, `check`, `render`
- `references/data-collection.md` — which tool answers which figure, and how to record it
- `references/data-contract.md` — the shape of `data.json`, field by field

Speak to the user in their language. The report itself is in English, as the template is.

## Rules that are not negotiable

1. **One tenant, one calendar month.** Every query carries the tenant and the exact period bounds
   printed by `period`. A figure for another tenant, or for "the last 30 days", is a wrong figure.
2. **A number is a count the platform returned, or an answer the user gave.** Never estimate, never
   extrapolate from a page of results, never reuse a figure from an earlier report or conversation.
   A page of 50 results tells you about 50 results; the total is the `count` field of the response.
3. **Record where each figure came from** in `sources`, as you write the figure — the tool and its
   filters, or the user's own words. `check` rejects a figure with no source.
4. **What no tool can answer, ask.** SLA results, APT count, incidents, Tier 3 cases, content tickets
   and the optimization list are known to the service team, not to the tools. Ask the user; do not
   look for a stand-in.
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
   for this month and last month per tier, tickets processed on time, Tier 3 cases and any deducted
   from the SLA with the reason, APT count, incidents, content tickets, rules optimized this month.
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
- A top-5 or top-10 list needs grouping. If no tool can group alerts by a field for the whole month,
  ask the user for the list (an export from the platform) and record it as theirs. A ranking built
  from the first pages of results is not a ranking.
- A tool fails or a system is unreachable: leave its figures `null`, say which system, and offer a
  draft. Do not substitute another system's data.
- The user wants different wording in a standard sentence: those sentences come from the renderer so
  that they always agree with the figures. Change the figures or the narrative fields, not the HTML.
