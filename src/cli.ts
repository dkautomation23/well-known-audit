/**
 * well-known-audit - what does this domain actually publish at its root and
 * under /.well-known/? `run` holds the whole program so tests can call it
 * without a process.
 */

import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";

import { allFindings, countByLevel, evaluateTarget, type TargetResult } from "./checks.js";
import { httpFetcher, isPublicUrl, runLimited, safeGet, type Fetcher, type FetchOutcome } from "./probe.js";
import { renderConsole, renderJson, type Context } from "./report.js";
import { findTarget, TARGETS, urlsFor, type TargetDef } from "./targets.js";
import {
  auditMany,
  CSV_HEADER,
  domainsIn,
  parseDomainList,
  renderSummary,
  summarise,
  toCsvRow,
  type DomainResult,
} from "./batch.js";

const USAGE = `well-known-audit - what a site publishes at its root and under /.well-known/.

  well-known-audit example.com
  well-known-audit example.com --only security.txt,robots.txt
  well-known-audit example.com --json report.json --quiet
  well-known-audit --batch sites.txt --csv survey.csv

Checks, in one run: security.txt (RFC 9116), robots.txt, llms.txt, ai.txt,
ucp, openid-configuration, apple-app-site-association, assetlinks.json,
change-password, mta-sts.txt, gpc.json and dnt-policy.txt - one line per
file, saying what is missing, broken or expired.

  --only LIST     comma-separated target names; check only these
  --batch FILE    audit a list of domains, one per line, and print the totals
  --csv FILE      write the batch result as CSV, one row per domain
  --json FILE     write the findings as JSON
  --timeout MS    per request, default 10000
  --quiet         write the file, print nothing
  --expires-within N
                  fail while there is still time: a security.txt that expires
                  within N days counts as a blocker. Without it an unexpired
                  file is valid however soon it lapses, which is what RFC 9116
                  says and useless in a scheduled run.

Run it weekly rather than once. Expires lapses on a date, silently, and the
site that publishes the file is the last to find out:

  # .github/workflows/security-txt.yml
  on:
    schedule: [{ cron: "0 7 * * 1" }]
  jobs:
    check:
      runs-on: ubuntu-latest
      steps:
        - run: npx well-known-audit example.com --only security.txt --expires-within 30

Exit codes: 0 no blockers, 1 at least one blocker, 2 the domain answered
nothing at all.
`;

interface Args {
  target?: string;
  flags: Map<string, string>;
  bools: Set<string>;
}

/**
 * Flags that take no value.
 *
 * Without this list, `well-known-audit --quiet example.com` reads "example.com"
 * as the value of --quiet and then complains that no domain was named.
 */
const SWITCHES = new Set(["quiet", "help"]);

function parse(argv: string[]): Args {
  const flags = new Map<string, string>();
  const bools = new Set<string>();
  let target: string | undefined;

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i]!;
    if (token === "-h") {
      bools.add("help");
      continue;
    }
    if (!token.startsWith("--")) {
      target ??= token;
      continue;
    }
    const name = token.slice(2);
    const next = argv[i + 1];
    if (SWITCHES.has(name)) bools.add(name);
    else if (next === undefined || next.startsWith("--")) bools.add(name);
    else {
      flags.set(name, next);
      i += 1;
    }
  }
  return { target, flags, bools };
}

function normalizeOrigin(input: string): string {
  const withScheme = /^https?:\/\//i.test(input) ? input : `https://${input}`;
  return new URL(withScheme).origin;
}

const CONCURRENCY = 4;
const BATCH_PAUSE_MS = 150;

/** Reads back the rows a previous run appended, enough to summarise them. */
function parseCsvResults(csv: string): DomainResult[] {
  const results: DomainResult[] = [];
  for (const line of csv.split(/\r?\n/).slice(1)) {
    if (!line.trim()) continue;
    const [domain, outcome, blockers, warnings, security, expires, expired, days, present, readable, expiresAt] =
      line.split(",");
    if (!domain || outcome !== "checked") {
      if (domain) results.push({ domain, outcome: "unreachable" });
      continue;
    }
    results.push({
      domain,
      outcome: "checked",
      blockers: Number(blockers || 0),
      warnings: Number(warnings || 0),
      present: present ? present.split(" ").filter(Boolean) : [],
      securityTxt:
        security === ""
          ? undefined
          : {
              found: security === "yes",
              // A CSV from before this column existed cannot tell a readable
              // file from an HTML shell, so it keeps its old meaning rather
              // than inventing a stricter one after the fact.
              parsed: readable === undefined || readable === "" ? security === "yes" : readable === "yes",
              hasExpires: expires === "yes",
              expired: expired === "yes",
              daysLeft: days ? Number(days) : undefined,
              expiresAt: expiresAt ? expiresAt : undefined,
            },
    });
  }
  return results;
}

export async function run(
  argv: string[],
  fetcher?: Fetcher,
  out: (text: string) => void = (text) => process.stdout.write(text),
): Promise<number> {
  const args = parse(argv);

  const askedForHelp = args.bools.has("help");
  const batchPath = args.flags.get("batch");
  if (!args.target && !batchPath) {
    out(USAGE);
    return askedForHelp ? 0 : 2;
  }
  if (askedForHelp) {
    out(USAGE);
    return 0;
  }

  let selectedTargets: readonly TargetDef[] = TARGETS;
  const onlyRaw = args.flags.get("only");
  if (onlyRaw) {
    const ids = onlyRaw
      .split(",")
      .map((id) => id.trim())
      .filter((id) => id.length > 0);
    const unknown = ids.filter((id) => !findTarget(id));
    if (unknown.length > 0) {
      out(`unknown target(s) in --only: ${unknown.join(", ")}\n`);
      out(`valid targets: ${TARGETS.map((target) => target.id).join(", ")}\n`);
      return 2;
    }
    selectedTargets = TARGETS.filter((target) => ids.includes(target.id));
  }

  const expiresRaw = args.flags.get("expires-within");
  let expiresWithinDays: number | undefined;
  if (expiresRaw !== undefined) {
    expiresWithinDays = Number(expiresRaw);
    if (!Number.isFinite(expiresWithinDays) || expiresWithinDays < 0) {
      out(`--expires-within must be a number of days, got "${expiresRaw}"\n`);
      return 2;
    }
  } else if (args.bools.has("expires-within")) {
    out("--expires-within needs a number of days, for example --expires-within 30\n");
    return 2;
  }

  const timeoutRaw = args.flags.get("timeout");
  const timeout = timeoutRaw === undefined ? 10_000 : Number(timeoutRaw);
  if (!Number.isFinite(timeout) || timeout <= 0) {
    out(`--timeout must be a positive number of milliseconds, got "${timeoutRaw}"\n`);
    return 2;
  }

  if (batchPath) {
    const domains = parseDomainList(readFileSync(batchPath, "utf8"));
    if (domains.length === 0) {
      out(`${batchPath}: no domains found\n`);
      return 2;
    }

    const http = fetcher ?? httpFetcher(timeout);
    const quiet = args.bools.has("quiet");
    const csvPath = args.flags.get("csv");

    // A long run is worth resuming. Rows are appended as they land, so an
    // interrupted run keeps what it learned and a second run does not walk up
    // to the same sites again.
    let alreadyDone: DomainResult[] = [];
    let pending = domains;
    if (csvPath && existsSync(csvPath)) {
      const existing = readFileSync(csvPath, "utf8");
      const done = domainsIn(existing);
      pending = domains.filter((domain) => !done.has(domain));
      alreadyDone = parseCsvResults(existing);
      if (!quiet && pending.length < domains.length) {
        out(`resuming: ${domains.length - pending.length} domain(s) already in ${csvPath}\n`);
      }
    } else if (csvPath) {
      writeFileSync(csvPath, `${CSV_HEADER}\n`, "utf8");
    }

    if (!quiet) out(`auditing ${pending.length} domain(s), one at a time\n\n`);

    const fresh = await auditMany(http, pending, {
      targets: selectedTargets,
      timeoutMs: timeout,
      expiresWithinDays,
      onResult: (result, done, total) => {
        if (csvPath) appendFileSync(csvPath, `${toCsvRow(result)}\n`, "utf8");
        if (quiet) return;
        const detail =
          result.outcome === "checked"
            ? `${result.present?.length ?? 0} file(s), ${result.blockers} blocker(s)`
            : result.outcome;
        out(`  ${String(done).padStart(4)}/${total}  ${result.domain.padEnd(34)} ${detail}\n`);
      },
    });

    const results = [...alreadyDone, ...fresh];
    if (!quiet) out(`\n${renderSummary(summarise(results))}\n`);
    if (csvPath && !quiet) out(`\n${results.length} row(s) in ${csvPath}\n`);
    const batchJsonPath = args.flags.get("json");
    if (batchJsonPath) {
      writeFileSync(
        batchJsonPath,
        `${JSON.stringify({ checkedAt: new Date().toISOString(), summary: summarise(results), results }, null, 2)}\n`,
        "utf8",
      );
      if (!quiet) out(`findings written to ${batchJsonPath}\n`);
    }

    // A survey is not a gate: a site failing its own audit is not this run
    // failing. Only reaching nothing at all is.
    return results.every((result) => result.outcome === "unreachable") ? 2 : 0;
  }

  let origin: string;
  try {
    origin = normalizeOrigin(args.target!);
  } catch {
    out(`"${args.target}" is not a valid domain or URL\n`);
    return 2;
  }

  if (!isPublicUrl(`${origin}/`)) {
    out(`${origin} is not a public address; well-known-audit only checks public sites\n`);
    return 2;
  }

  const http = fetcher ?? httpFetcher(timeout);
  const requests = urlsFor(origin, selectedTargets);
  const outcomes = await runLimited(requests, CONCURRENCY, BATCH_PAUSE_MS, ({ url }) => safeGet(http, url));

  const outcomesByTarget = new Map<string, FetchOutcome[]>();
  requests.forEach((request, index) => {
    const list = outcomesByTarget.get(request.target.id) ?? [];
    list.push(outcomes[index]!);
    outcomesByTarget.set(request.target.id, list);
  });

  const now = Date.now();
  const results: TargetResult[] = selectedTargets.map((target) =>
    evaluateTarget(target, outcomesByTarget.get(target.id)!, now, { expiresWithinDays }),
  );

  const context: Context = { domain: args.target!, checkedAt: new Date(now).toISOString(), timeoutMs: timeout };
  if (!args.bools.has("quiet")) out(`${renderConsole(results, context)}\n`);

  const jsonPath = args.flags.get("json");
  if (jsonPath) {
    writeFileSync(jsonPath, renderJson(results, context), "utf8");
    if (!args.bools.has("quiet")) out(`\nfindings written to ${jsonPath}\n`);
  }

  // Every single request failing is a different fact from every file being
  // absent: a 404 means the server answered, an unreached request means it
  // never did. Only the second one means there is no report to trust.
  const anyReached = outcomes.some((outcome) => outcome.reached);
  if (!anyReached) return 2;

  return countByLevel(allFindings(results)).blocker > 0 ? 1 : 0;
}
