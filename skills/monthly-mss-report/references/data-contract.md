# `data.json`

`build_report.py init` writes this shape with every figure `null`. `null` means "not found yet";
`check` lists each one. Do not replace a `null` with `0` unless a query or the user said zero.

```jsonc
{
  "meta": {
    "customer_name": "Acme Corp",          // printed on the cover and in the text
    "tenant": "acme",                      // scopes every query
    "period": { "year": 2026, "month": 9 },
    "utc_offset_hours": 7                  // month boundaries are taken in this zone
  },
  "sla_targets": { "tier1": 90, "tier2": 90, "tier3": 90, "content": 95 },   // optional; these are the defaults
  "overview": {
    "apt_count": 0,
    "system_status": { "label": "Secured System", "level": "ok" }            // level: ok | warning | critical
  },
  "incident_response": {
    "incident_count": 0,
    "incidents": [ { "title": "...", "summary": "..." } ]                     // one per incident
  },
  "tier1": {
    "alert_total": 1709,
    "sla": { "previous": 100, "current": 100 },                              // percent
    "commentary": "Why the alert volume changed against last month.",        // free text, user-confirmed
    "by_solution": [ { "name": "Endpoint Detection & Response (EDR)", "count": 1095 } ],
    "by_category": [ { "name": "Abnormal behaviour attack", "count": 1633 } ],
    "by_level":    [ { "name": "Critical", "count": 39 } ],
    "top_rules":   [ { "rule_id": "...", "description": "...", "count": 342 } ],   // at most 5, descending
    "top_objects": [ { "object": "10.0.0.5", "count": 642 } ]                      // at most 10, descending
  },
  "tier2": { "tickets_total": 80, "tickets_on_time": 77, "sla": { "previous": 100 } },
  "tier3": {
    "cases_total": 8, "cases_excluded": 1,
    "exclusion_reason": "because more time is needed to verify with the customer",
    "sla": { "previous": 100, "current": 100 }
  },
  "coverage": {
    "nsm":  { "sensors_total": 1, "sensors_ok": 1, "detail": "sensor-01" },
    "siem": { "installed": 55, "online": 46, "offline": 9 },
    "edr":  { "installed": 34, "online": 28, "offline": 6 }
  },
  "content": { "ticket_count": 0, "sla": { "previous": 100, "current": 100 } },
  "optimization": [ { "rule": "...", "optimization": "Whitelist ..." } ],
  "problems": [ { "problem": "...", "recommendation": "..." } ],
  "appendix_siem_offline": [ { "hostname": "...", "ip": "...", "os": "...", "last_ping": "...", "status": "Offline" } ],
  "appendix_edr_offline":  [ { "hostname": "...", "os": "...", "last_ping": "...", "ip": "...", "status": "offline" } ],
  "sources": { "<dotted path>": { "by": "tool" | "user", "ref": "..." } }
}
```

## What the renderer computes

Never put these in `data.json`:

- Tier 2 SLA for the month: `tickets_on_time / tickets_total`.
- KPIs achieved out of total: a tier is achieved when its SLA for the month is at or above its target.
- Month names, the period on the cover, the previous month's label.
- Every standard sentence, every chart, the page breaks and the table of contents.

## What `check` enforces

- each of `by_solution`, `by_category`, `by_level` sums to `alert_total`;
- `top_rules` and `top_objects` are in descending order, within their limits, and no row exceeds the total;
- `tickets_on_time ≤ tickets_total`; `cases_excluded ≤ cases_total`; a deduction has a reason;
- `incident_count` equals the number of incidents described;
- `online + offline = installed` for SIEM and EDR agents, and each appendix lists exactly the offline ones;
- every supplied figure has a `sources` entry naming a tool call or the user.
