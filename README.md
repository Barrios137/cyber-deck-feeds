# cyber-deck-feeds

JSON mirror of the public cybersecurity advisories and news published by CISA, the U.S.
Cybersecurity and Infrastructure Security Agency, so that client-side tools (browser widgets,
dashboards) can read them with a plain `fetch`. CISA's RSS feeds send no CORS headers; this
repository serves the same headlines through `raw.githubusercontent.com`, which does.

- `feeds.json` — up to the 60 most recent advisories and the 20 most recent news items
  (title, link, date, source and tag only), regenerated every 2 hours by the GitHub Action in
  `.github/workflows/mirror.yml` with `mirror.py`.
- Read it from: `https://raw.githubusercontent.com/Barrios137/cyber-deck-feeds/main/feeds.json`

## Format

```json
{"v":1,"generated":"2026-11-07T23:38:41Z",
 "sources":{"cisa":{"name":"CISA","lang":"en","home":"https://www.cisa.gov/","license":"Public domain (17 U.S.C. § 105)"}},
 "items":[
  {"title":"CISA Adds One Known Exploited Vulnerability to Catalog","link":"https://www.cisa.gov/news-events/alerts/...","date":"2026-11-06T12:00:00Z","source":"cisa","tag":"alert"}
 ]}
```

Dates are UTC, ISO 8601, and items come newest first. `tag` is one of `alert`, `advisory`,
`ics`, `medical`, `analysis`, `news`, `resource` or `other`. `generated` only changes when the
headlines change. If a feed cannot be read, `feeds.json` keeps its last good version and the
Action opens an issue labelled `mirror`.

## Sources and conduct

- <https://www.cisa.gov/cybersecurity-advisories/all.xml> and <https://www.cisa.gov/news.xml>.
  CISA content is a work of the U.S. Government and is in the public domain
  (17 U.S.C. § 105). Only headlines and links are mirrored: follow the link for the full text.
- One request per feed every 2 hours from a GitHub runner, with an identifiable User-Agent
  and a contact address.
- This is a community resource. It is not affiliated with or endorsed by CISA or the U.S.
  Government.

Maintained by Simple Code · legal@simple-code.cloud
