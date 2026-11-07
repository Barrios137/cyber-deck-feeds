# cyber-deck-feeds

JSON mirror of the public security advisories published by CISA, the U.S. Cybersecurity and
Infrastructure Security Agency, so that client-side tools (browser widgets, dashboards) can
read them with a plain `fetch`. It is built from CISA's own data repositories on GitHub and
served through `raw.githubusercontent.com`, which sends CORS headers.

- `feeds.json` — the 40 most recent ICS and vulnerability advisories from
  [cisagov/CSAF](https://github.com/cisagov/CSAF), plus one entry per day of additions to the
  Known Exploited Vulnerabilities catalog from [cisagov/kev-data](https://github.com/cisagov/kev-data)
  over the last 45 days (up to 60 items; title, link, date, source and tag only). Regenerated
  every 2 hours by the GitHub Action in `.github/workflows/mirror.yml` with `mirror.py`.
- Read it from: `https://raw.githubusercontent.com/Barrios137/cyber-deck-feeds/main/feeds.json`

## Format

```json
{"v":1,"generated":"2026-11-07T23:38:41Z",
 "sources":{"cisa":{"name":"CISA","lang":"en","home":"https://www.cisa.gov/","license":"Public domain (17 U.S.C. § 105); KEV data CC0 1.0"}},
 "items":[
  {"title":"Subnet Solutions PowerSYSTEM Center","link":"https://www.cisa.gov/news-events/ics-advisories/icsa-26-307-01","date":"2026-11-03T06:00:00Z","source":"cisa","tag":"ics"}
 ]}
```

Dates are UTC, ISO 8601, and items come newest first. `tag` is `ics` (ICS advisory), `medical`
(ICS medical advisory), `advisory` (other CSAF advisories) or `alert` (KEV additions; the link
goes to the catalog). `generated` only changes when the items change. If a source cannot be
read, `feeds.json` keeps its last good version and the Action opens an issue labelled `mirror`.

## Sources and conduct

- [cisagov/CSAF](https://github.com/cisagov/CSAF) (TLP:CLEAR advisories only) and
  [cisagov/kev-data](https://github.com/cisagov/kev-data). CISA content is a work of the U.S.
  Government and is in the public domain (17 U.S.C. § 105); the KEV data is also published
  under CC0 1.0. Only headlines and links are mirrored: follow the link for the full text.
- One GitHub API call and at most 41 file reads every 2 hours, with an identifiable
  User-Agent and a contact address.
- This is a community resource. It is not affiliated with or endorsed by CISA, DHS or the
  U.S. Government, and it does not use the CISA logo or DHS seal.

Maintained by Simple Code · legal@simple-code.cloud
