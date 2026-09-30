# Collecting the figures

Run `build_report.py period data.json` first. Below, `FROM` and `TO` are its `this_month.from_ms` and
`this_month.to_ms`; `TENANT` is `meta.tenant`.

Two habits make the difference between an exact report and an approximate one:

- **To count, ask for one row and read `count`.** A search tool returns the number of matches for the
  filter in its `count` field regardless of page size. Use `size: 1`. Never count the rows you see.
- **Confirm a field's name before filtering on it.** Alerts normally carry `tenant`, `source` (the
  solution that raised it), `category`, `severity`, `rule_id`, `hostname`, `created` and `sla_expired`;
  tickets carry `tenant`, `type`, `assigned_group` (the handling tier), `severity`, `status`, `created`
  and `sla_expired`; cases carry `tenant`, `case_id`, `type`, `severity`, `status`, `created`,
  `sla_expired` and `incident_tag`. Deployments differ, so check with the field-listing tool for the system
  (`soar_list_alert_fields`, `edr_list_alert_fields`, `nsm_list_alert_fields`, `siem_list_event_fields`)
  or against one returned row, and put the names you used in the `ref` of each source.

## Figures and their tools

| Figure in `data.json` | How to get it | Record in `sources[...]`.ref |
|---|---|---|
| `tier1.alert_total` | `soar_search_alerts` with `created_from: FROM`, `created_to: TO`, `tenant: TENANT`, `size: 1` → `count` | the tool, the bounds, the tenant |
| `tier1.by_level` | `soar_group_alerts` with `field: "severity"`, same bounds and tenant → `groups`. Rows `{name, count}`, most severe first | the call |
| `tier1.by_solution` | `soar_group_alerts` with `field: "source"` → `groups` | the call and the field |
| `tier1.by_category` | `soar_group_alerts` with `field: "category"` → `groups` | the call and the field |
| `tier1.top_rules` (5) | `soar_group_alerts` with `field: "rule_id"`, `top: 5` → `groups`. The description of each rule comes from one alert of that rule (`soar_search_alerts` with `query: 'rule_id = "..."'`, `size: 1`) or from `siem_search_rules`. `{rule_id, description, count}` | the grouping call, and where each description came from |
| `tier1.top_objects` (10) | `soar_group_alerts` with `field: "hostname"` (or the object field the deployment uses), `top: 10` → `groups`. `{object, count}` | the call and the field |
| `tier2.tickets_total` | `soar_search_tickets` with `created_from: FROM`, `created_to: TO`, `tenant: TENANT`, `size: 1` → `count` | the call |
| `tier3.cases_total` | `soar_search_cases` with `created_from: FROM`, `created_to: TO`, `tenant: TENANT`, `size: 1` → `count`. A case is not a ticket: never count tickets here | the call |
| `coverage.edr` | `edr_search_agents` with a `query` that selects the tenant (find the tenant and status fields in a returned agent first): read `total` for all agents, for online, for offline → `{installed, online, offline}` | the three calls and their queries |
| `appendix_edr_offline` | `edr_search_agents` for the tenant's offline agents, raising `limit` or paging with `since` until the rows listed equal the offline total: `{hostname, os, last_ping, ip, status}` | the call and how many rows came back |
| `coverage.siem` | `siem_search_agents` with `active: "1"` then `active: "0"`, keeping only the report tenant's agents → `{installed, online, offline}` | the calls, and how the tenant was selected |
| `appendix_siem_offline` | `siem_search_agents` with `active: "0"`, paging with `from` until every inactive agent of the tenant is listed: `{hostname, ip, os, last_ping, status}` | the calls and how many rows came back |
| `coverage.nsm` | `nsm_list_sensors`, keeping the sensors whose tenant is the report tenant → `{sensors_total, sensors_ok, detail}`; `detail` is the sensor name(s) | the call |

**Tenant scoping is not optional.** Some tools take no tenant parameter and answer for every tenant
the signed-in account can see. For those, select the report tenant's rows by the tenant field each row
carries, and page until you have seen all rows, not just the first page. If a tool gives you no way to
tell which rows belong to the tenant, stop and tell the user: a figure covering other customers must
not go into this customer's report.

Each breakdown must sum to `tier1.alert_total`, online plus offline must equal installed, and each
appendix must list exactly as many machines as are offline. `check` enforces all three.

**Reading a grouping.** `soar_group_alerts` counts every matching alert, page by page, so its `total`
must equal `tier1.alert_total`. Two things to check before using its `groups`:

- `truncated: true` means it stopped at `scanned` alerts. The groups are then incomplete: do not use
  them. Say so, and leave the figure `null`.
- `missing` is the number of alerts with no value in that field. For a breakdown that has to sum to
  the total, add them as a row named "Unclassified" — that row is real, the tool counted it.

**EDR timestamps are epoch seconds**, unlike every other system. The EDR tools accept the millisecond
bounds `period` prints and convert them.

**Tickets and cases are different things.** The Tier 2 figures count tickets
(`soar_search_tickets`); the Tier 3 figure counts cases (`soar_search_cases`). If the user's
deployment counts only some tickets as "Tier 2" — by `assigned_group` or `type` — ask which, and
record the rule in the source entry.

**SLA results stay the user's to state.** Alerts, tickets and cases each carry `sla_expired`, so you
can count how many met their SLA and show the user that count when you ask — it helps them answer,
and a gap between the two is worth pointing out. The figure that goes in the report is the one the
user confirms.

## Figures only the user has

Ask for these; record `"by": "user"` with what they told you.

| Figure | Question |
|---|---|
| `tier1.sla.previous`, `tier1.sla.current` | Tier 1 alert SLA achieved last month and this month, in percent |
| `tier2.tickets_on_time`, `tier2.sla.previous` | Tickets the customer processed on time this month; Tier 2 SLA last month. This month's Tier 2 SLA is computed from the counts |
| `tier3.cases_excluded`, `tier3.exclusion_reason`, `tier3.sla.*` | Of this month's Tier 3 cases, how many are deducted from the SLA and why; SLA last month and this month |
| `content.ticket_count`, `content.sla.*` | Content tickets this month; Content KPI last month and this month |
| `overview.apt_count` | APT campaigns identified this month |
| `incident_response.incident_count`, `.incidents` | Incidents this month, each with a title and a one-paragraph summary |
| `optimization` | Rules optimized this month: `{rule, optimization}` per rule, or an empty list |

## Writing a source entry

```json
"sources": {
  "tier1.alert_total": {
    "by": "tool",
    "ref": "soar_search_alerts created_from=1788195600000 created_to=1790787599999 query='tenant = \"acme\"' size=1 -> count 1709"
  },
  "tier1.sla.current": { "by": "user", "ref": "user: 'Tier 1 SLA tháng 9 đạt 100%'" }
}
```
