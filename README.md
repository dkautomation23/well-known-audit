# well-known-audit

[![CI](https://github.com/dkautomation23/well-known-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/dkautomation23/well-known-audit/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/dkautomation23/well-known-audit/badge)](https://scorecard.dev/viewer/?uri=github.com/dkautomation23/well-known-audit)
[![CodeQL](https://github.com/dkautomation23/well-known-audit/actions/workflows/codeql.yml/badge.svg)](https://github.com/dkautomation23/well-known-audit/actions/workflows/codeql.yml)
[![npm](https://img.shields.io/npm/v/well-known-audit)](https://www.npmjs.com/package/well-known-audit)

One run, one report: every file a site publishes at its root and under
`/.well-known/` — what is there, what is broken, what is expired.

```bash
npx well-known-audit yourdomain.com
```

No runtime dependencies, no API key, no account. TypeScript, Node's own test
runner, 117 tests.

Every published version is built and published by the workflow in this
repository, never from a laptop, and carries a provenance statement recorded in
Sigstore's public transparency log. Anyone can check that before trusting it:

```bash
npm audit signatures
```

## Why

Twelve different files, twelve different specs, one shared failure mode:
nothing tells you when they go wrong. `security.txt` has an `Expires` field
that most people set once and forget — [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116)
says an expired one is exactly as invalid as a missing one, and there is no
warning anywhere when the date passes. `apple-app-site-association` breaks
completely, and silently, the moment a static host's SPA-fallback routing
serves it as an HTML shell instead of the real JSON — the file still answers
`200`, so nothing looks wrong until a user taps a link and the app does not
open. This checks all twelve the way the consumer that reads them would, and
says which ones are lying about being fine.

## A real example

`cloudflare.com`, on the day this was written:

```console
$ well-known-audit cloudflare.com

------------------------------------------------------------------------
WELL-KNOWN AUDIT - cloudflare.com
------------------------------------------------------------------------
checked   2026-09-18T15:13:01.468Z   timeout 10000ms

  BLOCK  security.txt                  no Expires field
                                       RFC 9116 requires exactly one Expires field; without it the
                                       file has no defined shelf life.
                                       -> Add `Expires: <RFC 3339 date-time>`, at most a year out.
  ok     robots.txt                    1 sitemap(s)
  ok     llms.txt                      90 link(s)
  warn   change-password               not found
                                       lets password managers jump straight to the change-password page.
  ...

1 blocker(s), 1 warning(s), 8 note(s)
```

A multi-billion-dollar security company's own `security.txt` has no `Expires`
field at all — one of the two fields RFC 9116 requires. And `github.com`, the
same day:

```console
$ well-known-audit github.com

  ok     security.txt                  valid, expires in 30d
  note   robots.txt                    no Sitemap: line
  ok     llms.txt                      117 link(s)
  ok     assetlinks.json               3 statement(s)
  ok     change-password               redirects, then 200
  ...

0 blocker(s), 0 warning(s), 8 note(s)
```

Same tool, same twelve files, two very different answers.

## What it checks

**`security.txt`** ([RFC 9116](https://www.rfc-editor.org/rfc/rfc9116)) — checked at both
`/.well-known/security.txt` (canonical) and `/security.txt` (legacy)

- `Expires` is the one field this tool leads with: missing, unparseable, given
  twice, or in the past are all blockers. An expired file is formally invalid,
  the same as no file at all — RFC 9116 says so explicitly, and it is the most
  common mistake in the wild (see the example above).
- `Contact` is required; present but not a URI (a bare email instead of
  `mailto:...`) is a warning, not a blocker — a human can still read it, a
  parser cannot.
- `Encryption`, `Policy`, `Preferred-Languages` and `Canonical` are read and
  surfaced; more than one `Preferred-Languages` or `Expires` is a blocker
  (RFC 9116 allows at most one of each).
- Published only at the legacy root path, not the canonical one, is a warning.

**`robots.txt`** — has a `Sitemap:` line; does not `Disallow: /` for `User-agent: *`
with no exception (which hides the whole site from every crawler that honours
it, AI crawlers included).

**`llms.txt`** — present, and how many markdown links it contains.

**`ai.txt`**, **`ucp`**, **`dnt-policy.txt`** — presence only. `ucp` is
deliberately not parsed here; that is a full audit in its own right, done by
[`ucp-audit`](https://github.com/dkautomation23/ucp-audit).

**`openid-configuration`** — valid JSON with a string `issuer`; a non-`https`
issuer is a warning.

**`apple-app-site-association`** — valid JSON with an `applinks`,
`webcredentials` or `appclips` key. Served as `text/html` (or a body that
looks like an HTML shell regardless of the declared type) is a blocker: the
classic static-host mistake where a catch-all route answers `200` with the
app shell for any unmatched path, so the file "exists" but is not there.

**`assetlinks.json`** — valid JSON, and specifically a top-level *array*
(Digital Asset Links) with `relation` and `target` on each entry.

**`change-password`** — answers with a redirect or `200`. Anything else
reachable (a `4xx`/`5xx`, or a `3xx` with no `Location`) is a blocker: the URL
is there but does not do the one thing it is for.

**`mta-sts.txt`** ([RFC 8461](https://www.rfc-editor.org/rfc/rfc8461)) — has
`version: STSv1`, a valid `mode`, at least one `mx`, and an integer `max_age`.

**`gpc.json`** — valid JSON with a boolean `gpc` field, per the
[Global Privacy Control](https://globalprivacycontrol.org/) spec.

## Severity

- **blocker** — the file is published but does not do its job: an expired
  `security.txt`, an `apple-app-site-association` served as HTML, invalid JSON
  where JSON is required. Same bucket as "answers with garbage."
- **warning** — either `security.txt`, `robots.txt` or `change-password` is
  missing (these apply to essentially any public site), or a present file has
  a soft defect that degrades but does not break it.
- **note** — a file that only applies to *some* sites (a mobile app, a mail
  server, an OIDC provider) is missing, or a present file has a cosmetic
  issue.

## In CI, or in cron

```yaml
- run: npx well-known-audit yourdomain.com
```

Run it on a schedule, not once. Every one of these files is fine until a date
nobody is watching, and `Expires` is the clearest case: past that date RFC 9116
treats the file as invalid, and nothing on the site says so. `--expires-within`
turns the date into a build failure while there is still time to act:

```yaml
on:
  schedule: [{ cron: "0 7 * * 1" }]
jobs:
  security-txt:
    runs-on: ubuntu-latest
    steps:
      - run: npx well-known-audit yourdomain.com --only security.txt --expires-within 30
```

Without the flag an unexpired file is valid however soon it lapses, which is
what the RFC says and is useless in a weekly run. With it, a file inside the
window is a blocker. On 21 September 2026 that was the difference between
exit 0 and exit 1 on `microsoft.com`, whose file expired two days later.

Exit code is `1` when there is a blocker, `0` when there is not, `2` when the
domain answered nothing at all — DNS failure, connection refused, or every
request timing out. A `404` on an individual file is not a `2`; that is a
normal, common answer and is reported as a missing file instead.

## Fuzzed, because the input is always someone else's

Every parser here is handed a file written by a stranger, on a host nobody
controls, over the network. The test suite covers the cases I thought of;
[`fuzz/parse.fuzz.js`](fuzz/parse.fuzz.js) covers the ones I did not. It asserts
the property that actually matters for a survey of five hundred domains: the
parser **returns** rather than throws, because an exception at domain forty ends
the run.

```bash
npm run build
npx jazzer fuzz/parse.fuzz.js fuzz/corpus --sync -- -max_total_time=150
```

A local run on 21 September 2026: **1,376,673 executions in 151 seconds, no
crash**, corpus grown from the five seed files to 153 inputs at 89 edges of
coverage. ClusterFuzzLite re-runs it on every pull request against the code that
changed, with the config in [`.clusterfuzzlite/`](.clusterfuzzlite/).

Seed files are real: a `security.txt`, a `robots.txt` with a named AI crawler, an
`mta-sts.txt`, an `llms.txt` and an `assetlinks.json`. Starting from valid input
reaches the interesting states far sooner than starting from random bytes.

## Safety

This tool requests paths on a domain someone else typed in, and follows
whatever redirects that domain sends back - so it treats both as untrusted.

- **It refuses any private or loopback address**, for the domain itself and
  for every redirect hop: `localhost`, `127.0.0.0/8`, `10/8`, `172.16/12`,
  `192.168/16`, `169.254/16` (cloud metadata), `::1` and bare hostnames are
  all refused rather than requested. A redirect that lands on one is reported
  as a blocker, not silently followed.
- **Redirects are followed manually, one hop at a time, capped at 5.** Each
  hop is checked before it is requested; a chain that does not resolve within
  5 hops is abandoned rather than followed indefinitely.
- **Every response is capped at 5 MB**, with the read aborted the moment the
  cap is crossed rather than after the whole body has already been buffered.
  None of these twelve files are legitimately anywhere near that size.
- **No more than 4 requests to a domain at once**, in batches with a pause
  between them - this tool visits sites that did not ask to be scanned, and
  it does so politely or not at all.
- **A clear, honest User-Agent** naming this repository, sent on every
  request.
- **Sends no credentials**, ever, to anyone.

The test suite covers each of these against a real (loopback-only) HTTP
server. Nothing in it touches the public network.

## Install

```bash
npx well-known-audit --help          # nothing to install

git clone https://github.com/dkautomation23/well-known-audit.git
cd well-known-audit && npm install && npm test
```

Node 22+.

| Flag | Meaning |
| --- | --- |
| `--only LIST` | comma-separated target names; check only these, e.g. `--only security.txt,robots.txt` |
| `--batch FILE` | audit a list of domains, one per line |
| `--csv FILE` | write the batch result as CSV, one row per domain |
| `--json FILE` | write the findings as JSON |
| `--timeout MS` | per request, default 10000 |
| `--quiet` | write the file, print nothing |

## A list of sites at a time

```console
$ well-known-audit --batch sites.txt --csv survey.csv

5 domain(s)

  answered           5  (100%)
  never answered     0

Of the 5 that answered:
  publish a security.txt        4  (80%)
  at least one blocker          4  (80%)

Of the 4 security.txt files:
  valid today                   1  (25%)
  expired                       0  (0%)
  no Expires field at all       3  (75%)
```

One domain at a time, its own files fetched four at a time with a pause: a site
never sees more than four of our requests at once, and never sees them while we
are busy with the next site. The concurrency cannot be raised past four however
it is asked for.

A site that never answered is counted apart and never as "publishes nothing" —
the difference between a survey and a number someone made up.

Rows are written as they land, and a run that finds its `--csv` already there
picks up where the last one stopped. A thousand-domain survey takes hours; it
should not have to start over because a laptop slept, and the sites should not
be asked twice.

## What the top 500 sites actually publish

Run on 2026-09-18 against the Tranco top 500 — one domain at a time, its files
four requests at a time. 332 of the 500 answered; the other 168 are counted
apart and never as "publishes nothing", because a traffic ranking is full of
content-delivery and API hostnames that serve nothing at their root.

Seventy of those 332 answer `200` to any path at all, including one invented for
the purpose. For those hosts only files whose contents were actually recognised
are counted — a 200 from a server that says 200 to everything is not evidence of
anything.

| of the 332 that answered | sites | |
|---|---|---|
| Publish a `robots.txt` | 233 | 70% |
| Publish a `security.txt` | 158 | 48% |
| Publish `assetlinks.json` (Android app links) | 138 | 42% |
| Publish `apple-app-site-association` (iOS) | 127 | 38% |
| Publish `change-password` | 77 | 23% |
| Publish an `llms.txt` | 70 | 21% |

And then the part worth the run:

| of the 158 `security.txt` files | files | |
|---|---|---|
| Valid today | 60 | 38% |
| **No `Expires` field at all** | **92** | **58%** |
| Expired | 6 | 4% |

**Nearly two thirds of the security.txt files at the top of the web are not
valid under RFC 9116.** The field is mandatory — `Expires` is what tells a
researcher the contact details are still watched — and an expired file is, in
the words of the specification, exactly as good as no file. One of the six
expired ones has been out of date since January 2024.

The domain list, the raw per-domain CSV and the aggregate are in
[`survey/`](survey/), so this can be repeated rather than believed:

```console
$ well-known-audit --batch survey/domains-top500.txt --csv results.csv
```

Spot-checked by hand with `curl` against four of the flagged sites before
publishing, because a number like that is only worth having if it is right.

### "Valid today" hides the date it stops being valid

The table above counts 60 valid files. Valid *on 18 September* — the survey
stored whether an `Expires` field was there, never when it fell due, so it
could not say which of those 60 were days from lapsing. Re-run on
**21 September 2026** with the date recorded, the same 60 domains say this:

| of the 60 valid files | files | |
|---|---|---|
| Lapse within 30 days | 8 | 13% |
| Lapse within 90 days | 10 | 17% |

| Domain | `Expires` | days left |
|---|---|---|
| microsoft.com | 2026-09-23 | **2** |
| amazonaws.com | 2026-09-24 | **3** |
| achmea.nl | 2026-10-01 | 9 |
| ibm.com | 2026-10-21 | 29 |
| facebook.com, github.com, whatsapp.net, whatsapp.com | 2026-10-21 | 30 |

Nothing here says those sites will let the date pass — a file with 30 days on
it is a file being maintained. What it says is that a single audit cannot tell
the difference between a maintained file and one about to lapse, and that the
six already-expired files in the table above were all, at some earlier survey,
"valid today". Raw re-run in
[`survey/2026-09-21-expires-dates.csv`](survey/2026-09-21-expires-dates.csv):

```console
$ well-known-audit --batch survey/domains-expires-top500.txt --only security.txt     --csv survey/2026-09-21-expires-dates.csv
```

## Does a published llms.txt actually work?

How many sites publish an `llms.txt` has been counted several times in 2026 and
the answers agree, so counting it again adds nothing. The next question has not
been asked: of the files that exist, how many have the shape the specification
describes, how many still point at pages that are there, and how many belong to
a site whose `robots.txt` bans the crawler that would read them.

Tranco top 1,500, 19 September 2026. Of 1,500 domains, 765 could be asked at
all — 418 never answered (most are CDN and infrastructure names carrying no
website), 133 refused, and 184 answer 200 to a path that cannot exist, so
nothing they return is evidence. None of those three is inside any rate below.

| | |
|---|---|
| Publish an `llms.txt` | 123 of 765 answered (16.1%) |
| Have the documented shape | 107 (87%) |
| Contain no links at all | 12 |
| Sites with at least one dead link inside | 15 of 111 checked (13.5%) |
| Links followed | 864, of which 36 are dead (4.2%) |
| **Publish one and ban a named AI crawler outright** | **13 of 123 (10.6%)** |

That last row is the finding. One site in ten writes a guide for a reader it is
not letting through the door. Only a `robots.txt` group naming the crawler
explicitly counts here, and only `Disallow: /` counts as a block — the wildcard
group is not evidence about a named bot, and treating it as one is how
published blocking rates get inflated.

The domain list, the row-per-domain CSV, the aggregate and the script are in
[`survey/`](survey/):

```console
$ node survey/llms-conformance.mjs survey/domains-top1500.txt out.csv
$ node survey/llms-aggregate.mjs out.csv aggregate.json
```

At most eight links per site were followed, spaced out, so the dead-link share
is a floor rather than a ceiling.

## Honest limits

- **A survey run from one machine sees what that machine is shown.** A site
  that serves different files by region, or that blocks an unknown user agent,
  is counted as "could not check" rather than guessed at - but a site that
  serves a different `security.txt` to a datacentre IP than to a browser would
  pass unnoticed.

- **It reads the file, not the system behind it.** `change-password` answering
  `200` means the URL resolves, not that the form on it works; `mta-sts.txt`
  parsing cleanly means the fields are well-formed, not that mail actually
  routes the way it says.
- **DNS is out of scope.** MTA-STS also has an `_mta-sts` DNS TXT record this
  tool does not read; SPF, DKIM and DMARC are not read at all. This is a
  `/.well-known/` auditor, not a DNS auditor.
- **`ucp` is presence-only, on purpose.** Whether the profile itself is any
  good is a question for [`ucp-audit`](https://github.com/dkautomation23/ucp-audit).
- **The "served as HTML" check is a heuristic**, not a certainty: it looks at
  the `Content-Type` header and the first bytes of the body. An unusual but
  legitimate file that happens to start with `<html` would be misread; in
  practice this is the same static-host fallback mistake every time.
- **PGP signatures on `security.txt` are not verified.** The fields inside a
  signed block are still read; whether the signature is valid is not checked.
- **Missing-file severity (warning vs. note) is a judgement call**, documented
  in the source (`src/targets.ts`) rather than dictated by any spec:
  `security.txt`, `robots.txt` and `change-password` apply broadly enough to
  warrant a warning when absent; the other nine only apply to sites that do
  that particular thing, so their absence is a note.
- **One connectivity signal decides exit code 2.** If every single request to
  a domain fails at the network level, this is reported as "did not respond."
  A domain that is up but blocks this tool's User-Agent specifically will
  look the same as one that is down - there is no way to tell those apart
  from outside.
- **Not affiliated** with Apple, Google, the IETF, the EFF or the Global
  Privacy Control project. This is an independent reader of public
  specifications.

## Licence

MIT
