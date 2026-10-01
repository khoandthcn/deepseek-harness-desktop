# `template.json`

A template is a directory under `report-templates/` of the working directory:

```
report-templates/<name>/
  template.json        the report: its figures and its blocks
  example-data.json    figures for previewing the layout (optional)
  brand.json + images  this customer's own brand pack (optional; see brand.example)
```

`build_report.py templates` lists what is found; `check-template <name>` validates one. A template is
looked up by name in `./report-templates/`, then `./.dsh/report-templates/`, then
`~/.dsh/report-templates/`, then the examples shipped with the skill — so a template in the working
directory replaces a shipped one of the same name.

```jsonc
{
  "title": "WEEKLY SECURITY MONITORING SUMMARY",   // printed on the cover
  "cycle": "range",                                 // "month" | "quarter" | "range" (any from–to span)
  "fields":   { ... },                              // every figure somebody supplies
  "computed": { ... },                              // figures that follow from others
  "blocks":   [ ... ]                               // the body, in reading order
}
```

## `fields` — what has to be collected

The key is the dotted path of the figure in `data.json`. `init --template` writes a data file with
each one `null`; `check` lists the missing ones, split by who supplies them.

| key | meaning |
|---|---|
| `type` | `integer`, `number`, `percent` (0–100), `text` (free text), `rows` (a list of objects) |
| `from` | `tool` — a platform query answers it; `user` — ask (default) |
| `hint` | shown by `check` beside a missing figure: the tool and filter, or what to ask |
| `optional` | `true`: may stay empty without blocking the report |
| `confirm` | `text` only; `false` silences the "have the user confirm this wording" warning |

For `rows`:

| key | meaning |
|---|---|
| `columns` | the keys each row carries, e.g. `["name", "count"]` |
| `numeric` | which columns are numbers (default: `count`, when present) |
| `optional_columns` | columns that may be empty |
| `sum_equals` | path of a total the `count` column must add up to (`sum_column` names another column) |
| `rows_equal` | path of a number the row count must equal (a list that must name every offline agent) |
| `max_rows`, `sorted_desc` | a top-N list: at most N rows, ordered by that column, largest first |

Use the ties. `sum_equals` is what catches a breakdown taken from one page of results.

Every field that has a value needs an entry in `sources` of the data file, except `text`.

## `computed`

```jsonc
"computed": {
  "sla.current": { "percent_of": ["tickets.on_time", "tickets.total"] },   // 100 when the whole is 0; "when_zero" changes that
  "kpis.met":    { "count_true": ["sla.current >= 90", "sla.t1 >= 95"] }   // how many conditions hold
}
```

A percentage that follows from two counts is computed, never asked for.

## Text, placeholders, conditions

Any `text` may contain `{path}`: a field, a computed value, a column of the current row (in `bullets`
and table columns), or one of the built-ins `{customer}`, `{tenant}`, `{provider}`,
`{provider_short}`, `{period.label}`, `{period.previous}`, `{period.from}`, `{period.to}`,
`{period.year}`. A figure still missing prints as a red N/A. Filters: `{n|pad2}` → `03`,
`{x|pct}` → `96.25%`, `{s|upper}`.

Every block may carry `"when": "<condition>"` or `"unless": "<condition>"`. A condition is a path
(true when it has a non-empty, non-zero value) or a comparison: `sla.current >= 90`,
`incidents.count == 0`, `status.level == "warning"`. Wording that depends on a figure is two blocks,
one `when` and one `unless` the same condition.

## `blocks`

| `type` | keys | renders |
|---|---|---|
| `part` | `text`, `background: "overview"` (optional) | a part title on a new page; listed in the contents |
| `section` | `text` | a numbered heading (1., 2., … restarting in each part); listed in the contents |
| `subsection` | `text`, `number: false` | a lettered heading (a., b., …), or unlettered |
| `paragraph` | `text`, `style`: `ind` (default), `lead`, `note`, `arrow` | a paragraph |
| `bullet` | `text` | one dash item |
| `bullets` | `rows`, `text` | one dash item per row; `{column}` reads the row |
| `stats` | `items: [{value, label}]`, 1–4 | the large figures of an overview page |
| `banner` | `text`, `level`: `ok`, `warning`, `critical`, or `"{path}"` | the coloured status bar |
| `kpi_chart` | `previous`, `current` (paths), `target` (percent), `legend` | last period and this one against the target |
| `pie_chart` | `rows`, `name`, `count` (column names; default `name`, `count`) | a pie with its legend |
| `bar_chart` | `rows`, `name`, `count`, `legend` | one bar per row |
| `table` | `rows`, `columns`, `numbered` (default true), `empty`, `style`: `narrow`, `apxt` | a table that continues over pages under a repeated header |
| `appendix` | `title` (`\n` separates lines) | a centred appendix title on a new page; follow it with a `table` |
| `page_break` | | the next block starts a page |

Table columns: `{ "head": "Rule ID", "field": "rule_id" }` or `{ "head": "On time", "text": "{done}/{total}" }`,
with optional `width` (`"18%"`; the rest share what is left), `align: "center"`, `wrap: true` for
identifiers with no spaces, `filter`. `empty` is the sentence shown when the list is empty.

`"keep": true` on a `paragraph` or `bullet` keeps it on the same page as the block that follows — use
it on the line that introduces a chart or table. Headings always stay with what follows.

## What a template cannot change

The cover, the confidentiality page, the contents page, and the header and footer of each page. Their
names, colours and images come from the brand pack. Charts are the three kinds above. If a sample
needs more than this, tell the user what is missing instead of approximating it silently.
