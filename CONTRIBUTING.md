# Contributing

## Before you write code

Open an issue first if the change adds a file to the list. Each entry in
`src/targets.ts` carries a judgement — is a missing file a blocker, a warning or
just a note — and that judgement is worth agreeing on before the code exists.

A fix with a failing test attached needs no issue. Send it.

## The rule that is not negotiable

**A new check starts as a failing test.** Write the test against a recorded
response, watch it fail for the right reason, then make it pass. This tool tells
strangers their site is wrong; a check nobody saw fail is a check nobody has
verified.

## Building and testing

Node 22 or newer. No runtime dependencies, and it stays that way.

```console
$ npm ci
$ npm run build          # tsc, strict
$ npm test               # build, then node --test on dist/test
```

The suite is 99 tests and touches no external network: every response comes from
a fixture through a swappable `Fetcher`. The only sockets it opens are loopback
servers in the tests that prove the SSRF guard, the body cap and the redirect
limit actually hold.

CI runs exactly `npm ci && npm test` on Ubuntu with Node 22. If it passes
locally on a clean checkout, it passes there.

## Things this repository cares about

- **No runtime dependencies.** A tool that audits other people's supply chain
  should not have one of its own.
- **Say why, not what, in comments.** The code shows what; a comment earns its
  place by explaining a decision.
- **Honest verdicts.** "Could not check" is a real answer and must never be
  reported as "broken". A site that blocks us is not a site that failed.
- **Politeness to the audited site.** One request per file, four at a time, a
  pause between them, an honest user agent naming the repository, and no attempt
  to get around anything that says no.

## Commit messages

A short sentence saying what changed for the person running the tool, a blank
line, then why — the part a diff cannot show. Look at `git log` and match it.

## Licence

By contributing you agree your work is published under the MIT licence.
