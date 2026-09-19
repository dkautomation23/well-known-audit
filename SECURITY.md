# Security policy

well-known-audit fetches a dozen small files from a domain someone names on the
command line, parses them, and prints what it found. Both halves are the attack
surface: the request, which goes wherever the domain and its redirects lead, and
the parsing, which is done on a file written by a stranger.

## Reporting

Use GitHub's private reporting on this repository: **Security → Report a
vulnerability**. It creates a private thread and nothing is public until there
is a fix.

If that is not available to you, write to **hello@dkautomation.dev** with
`well-known-audit` in the subject.

Include the version, the exact command, and the file or server that triggers it.
A proof of concept is welcome; a scanner's raw output usually is not.

Please do not open a public issue for a vulnerability. A public issue is a
disclosure, and it is unfair to anyone running the tool.

## What to expect

| | |
|---|---|
| First reply | within 2 working days |
| Assessment | within 7 working days of the first reply |
| Fix, or a stated decision not to fix | within 30 days for anything reproducible |

These are one person's commitments, not a company SLA.

## What counts as a vulnerability here

- **A request that leaves the public internet.** The tool refuses private,
  loopback and link-local addresses, and it checks every redirect hop rather
  than only the URL it was given. A domain that gets it to fetch
  `http://169.254.169.254/` or an address inside the operator's network is a
  vulnerability, not a quirk.
- **A response that costs more than it should.** Bodies are read with a 5 MB cap
  enforced as the bytes arrive. A server that makes the tool spend more memory
  or time than that cap implies — a body that never ends, a redirect loop, a
  parser that goes quadratic on a crafted `security.txt` — is a vulnerability.
- **Output that acts rather than describes.** Findings are printed and written
  to JSON. Content from a fetched file that escapes into a terminal escape
  sequence, or into a JSON document that is no longer valid JSON, is a
  vulnerability.
- **A wrong verdict in the direction that matters.** Reporting a valid
  `security.txt` as expired, or an expired one as valid, is worth reporting as a
  bug; if it can be triggered deliberately by the audited site, it is a
  vulnerability, because the whole point is that the audited site does not get
  to decide the verdict.

## What is not a vulnerability

- A file this tool does not know about yet. Open an issue.
- A site that blocks the tool's user agent. That is the site's choice, and the
  report says "could not check" rather than pretending otherwise.
- The tool fetching a domain the operator typed. That is what it is for.
- Disagreeing with whether a missing file is a warning or a note. Those are
  judgement calls, listed in `src/targets.ts`, and arguable in an issue.
- Findings from an automated scanner with no demonstrated impact.

## Supported versions

The latest release and the default branch.

## Credit

If you want it, you are named in the release notes for the fix. If you would
rather not be, say so. There is no bug bounty — one person, and I would rather
promise nothing than promise money I have not set aside.
