# Brand pack

The names, footer lines and images of the company issuing the report. It is the one part of the
template that differs between organisations, so it lives outside the skill's own files.

Copy this directory to one of the places the script looks, and fill in `brand.json`:

1. `.dsh/report-brand` in the workspace — for one project;
2. `report-brand` in the Harness home (`~/.dsh/report-brand`) — for every report this person makes.

Do not put it inside the skill's own directory: the skill ships with the application and is replaced
on every update. Put the image files beside `brand.json` and name them under `images`; an empty name
leaves that image out. Any field left out of `brand.json` falls back to a neutral default.

| Image | Where it appears | Size in the template |
|---|---|---|
| `cover_background` | the whole cover page | A4 portrait |
| `cover_logo` | upper left of the cover | about 148 × 60 pt |
| `header_logo` | upper left of the inner pages | about 91 × 37 pt |
| `overview_background` | the whole "Part I. Overview" page | A4 portrait |

A brand pack names a company, so it is never part of the skill and never tracked in version control.
