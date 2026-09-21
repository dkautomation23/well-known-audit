/**
 * Auditing a list of sites instead of one.
 *
 * The single-domain run answers "is my site right". A list answers a question
 * nobody has published: how many sites out there publish a security.txt at all,
 * and how many of those have quietly expired. That second question is only
 * worth asking if the crawler is polite, so the politeness lives here rather
 * than in the caller.
 *
 * The outcome of each domain is a status, not a verdict. "We could not reach
 * this site" and "this site is broken" are different facts, and merging them is
 * how a survey ends up publishing a number that is not true.
 */

import { allFindings, countByLevel, evaluateTarget, type TargetResult } from "./checks.js";
import { runLimited, safeGet, type Fetcher, type FetchOutcome } from "./probe.js";
import { TARGETS, urlsFor, type TargetDef } from "./targets.js";

export type Outcome = "checked" | "unreachable";

export interface DomainResult {
  domain: string;
  outcome: Outcome;
  /** This host answers 200 to a path that cannot exist, so its 200s mean nothing. */
  answersAnything?: boolean;
  /** Present only when the site answered something. */
  blockers?: number;
  warnings?: number;
  /** Per target: did the file exist, and was it usable? */
  present?: string[];
  securityTxt?: {
    found: boolean;
    /**
     * Did the served file read as a security.txt at all? A site that answers
     * its HTML home page at /security.txt has served something, but nothing
     * about it belongs in a rate about security.txt files.
     */
    parsed: boolean;
    hasExpires: boolean;
    expired: boolean;
    /**
     * Days until the Expires date; negative once it has passed. Filled for
     * every file with a date that parses, not only for expired ones - the
     * question a survey cannot answer without it is how many files are about
     * to lapse.
     */
    daysLeft?: number;
    /** The Expires date in ISO form, so a re-run can be compared to this one. */
    expiresAt?: string;
  };
}

export interface BatchOptions {
  targets?: readonly TargetDef[];
  /** Requests in flight per domain. Four is polite and still finishes a list. */
  concurrency?: number;
  pauseMs?: number;
  timeoutMs?: number;
  /** Passed through to the checks: see EvalOptions.expiresWithinDays. */
  expiresWithinDays?: number;
  onResult?: (result: DomainResult, done: number, total: number) => void;
}

const MAX_CONCURRENCY = 4;

/** One domain per line; blanks and `#` comments ignored, scheme and path stripped. */
export function parseDomainList(text: string): string[] {
  const seen = new Set<string>();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.split("#")[0]!.trim();
    if (!line) continue;
    try {
      seen.add(new URL(/^https?:\/\//i.test(line) ? line : `https://${line}`).host.toLowerCase());
    } catch {
      // A line that is not a host is skipped rather than fetched blindly.
    }
  }
  return [...seen];
}

/** A file counts as published when the site answered with it, not with a 404. */
function isPresent(result: TargetResult): boolean {
  return result.summary !== "not found" && result.summary !== "error";
}

/**
 * Every summary a check produces when it did *not* understand the file.
 *
 * A check that recognised something says so in its own words - "9 link(s)",
 * "issuer https://...", "keys: mode, mx". Anything on this list means the bytes
 * arrived and meant nothing, which is exactly what a soft 404 delivers.
 */
const NOT_EVIDENCE = new Set([
  "not found",
  "error",
  "served as HTML",
  "invalid JSON",
  "not a JSON object",
  "not a JSON array",
  "not a valid security.txt",
  "missing issuer",
  "no recognised keys",
  "malformed",
  "present",
]);

/**
 * The stricter test, for hosts that answer 200 to anything: the contents had to
 * be recognised as the file they claim to be, not merely delivered.
 *
 * change-password is excluded on purpose. Its specification asks only that the
 * URL resolve, so on a host that answers everything there is nothing left to
 * verify and counting it would be counting the soft 404 itself.
 */
function isVerified(result: TargetResult): boolean {
  if (!isPresent(result)) return false;
  if (result.id === "change-password") return false;
  if (NOT_EVIDENCE.has(result.summary)) return false;
  return !result.summary.startsWith("present (");
}

/** Reads what the security.txt checks concluded, without re-parsing the file. */
function securityTxtSummary(
  results: TargetResult[],
  answersAnything = false,
): DomainResult["securityTxt"] {
  const target = results.find((result) => result.id === "security.txt");
  if (!target) return undefined;

  const parsed = !NOT_EVIDENCE.has(target.summary) && isPresent(target);
  const found = answersAnything ? isVerified(target) : isPresent(target);
  const has = (id: string) => target.findings.some((finding) => finding.id === id);
  const expired = has("security-txt-expired");
  // "Has an Expires field" needs the file to have parsed in the first place:
  // no finding about Expires on a file nobody could read is not evidence that
  // the field is there.
  const hasExpires =
    found && parsed && !has("security-txt-no-expires") && !has("security-txt-multiple-expires")
    && !has("security-txt-expires-unparseable");

  return {
    found,
    parsed,
    hasExpires,
    expired,
    ...(target.expiry ? { daysLeft: target.expiry.daysLeft, expiresAt: target.expiry.iso } : {}),
  };
}

/**
 * A path no site can legitimately serve.
 *
 * Asking for it once per domain is the control that tells a real 200 from a
 * site that answers 200 to everything with an HTML shell - which is what large
 * single-page sites do, and what silently inflates a survey of which files
 * exist.
 */
export const CONTROL_PATH = "/.well-known/well-known-audit-control-should-not-exist";

export async function auditDomain(
  fetcher: Fetcher,
  domain: string,
  options: BatchOptions = {},
): Promise<DomainResult> {
  const targets = options.targets ?? TARGETS;
  const origin = `https://${domain}`;
  const requests = urlsFor(origin, targets);

  const concurrency = Math.max(1, Math.min(options.concurrency ?? MAX_CONCURRENCY, MAX_CONCURRENCY));
  const outcomes = await runLimited(requests, concurrency, options.pauseMs ?? 250, ({ url }) =>
    safeGet(fetcher, url),
  );

  if (!outcomes.some((outcome) => outcome.reached)) {
    return { domain, outcome: "unreachable" };
  }

  const control = await safeGet(fetcher, `${origin}${CONTROL_PATH}`);
  const answersAnything = control.reached && control.status >= 200 && control.status < 300;

  const byTarget = new Map<string, FetchOutcome[]>();
  requests.forEach((request, index) => {
    const list = byTarget.get(request.target.id) ?? [];
    list.push(outcomes[index]!);
    byTarget.set(request.target.id, list);
  });

  const now = Date.now();
  const results = targets.map((target) =>
    evaluateTarget(target, byTarget.get(target.id)!, now, {
      expiresWithinDays: options.expiresWithinDays,
    }),
  );
  const counts = countByLevel(allFindings(results));

  // When a host answers 200 to anything, only a file whose contents were
  // actually recognised counts: "it returned 200" is not evidence.
  const present = results
    .filter((result) => (answersAnything ? isVerified(result) : isPresent(result)))
    .map((result) => result.id);

  return {
    domain,
    outcome: "checked",
    answersAnything: answersAnything || undefined,
    blockers: counts.blocker,
    warnings: counts.warning,
    present,
    securityTxt: securityTxtSummary(results, answersAnything),
  };
}

export async function auditMany(
  fetcher: Fetcher,
  domains: string[],
  options: BatchOptions = {},
): Promise<DomainResult[]> {
  const results: DomainResult[] = new Array(domains.length);
  let done = 0;

  // One domain at a time, with its own files fetched a few at a time: a site
  // should never see more than four of our requests at once, and never see
  // them while we are also hammering the next site.
  for (let index = 0; index < domains.length; index += 1) {
    results[index] = await auditDomain(fetcher, domains[index]!, options);
    done += 1;
    options.onResult?.(results[index]!, done, domains.length);
  }

  return results;
}

const CSV_COLUMNS = [
  "domain",
  "outcome",
  "blockers",
  "warnings",
  "security_txt",
  "security_txt_expires",
  "security_txt_expired",
  "days_left",
  "files_present",
  // Appended last on purpose: a CSV written before these columns existed
  // still parses, and a reader that does not know them simply ignores them.
  "security_txt_readable",
  "security_txt_expires_at",
] as const;

function csvCell(value: unknown): string {
  const text = value === undefined || value === null ? "" : String(value);
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

/** The header a resumed run recognises, and the one `toCsv` writes. */
export const CSV_HEADER = CSV_COLUMNS.join(",");

/** One CSV row for one domain, so a long run can write as it goes. */
export function toCsvRow(result: DomainResult): string {
  const security = result.securityTxt;
  return [
    result.domain,
    result.outcome,
    result.blockers ?? "",
    result.warnings ?? "",
    security ? (security.found ? "yes" : "no") : "",
    security?.found ? (security.hasExpires ? "yes" : "no") : "",
    security?.found ? (security.expired ? "yes" : "no") : "",
    security?.daysLeft ?? "",
    result.present?.join(" ") ?? "",
    security?.found ? (security.parsed ? "yes" : "no") : "",
    security?.expiresAt ?? "",
  ]
    .map(csvCell)
    .join(",");
}

/** Domains already written to a CSV, so a resumed run does not ask them again. */
export function domainsIn(csv: string): Set<string> {
  const done = new Set<string>();
  for (const line of csv.split(/\r?\n/).slice(1)) {
    const domain = line.split(",")[0]?.trim();
    if (domain) done.add(domain.toLowerCase());
  }
  return done;
}



export function toCsv(results: DomainResult[]): string {
  return `${[CSV_HEADER, ...results.map(toCsvRow)].join("\n")}\n`;
}

export interface Summary {
  total: number;
  checked: number;
  unreachable: number;
  /** Hosts that answer 200 to any path; their bare 200s were not counted. */
  answerAnything: number;
  withBlockers: number;
  securityTxt: {
    published: number;
    withoutExpires: number;
    expired: number;
    valid: number;
    /**
     * Valid today and lapsing inside the next 30 and 90 days. These are the
     * numbers a one-off survey cannot report, and the reason it has to be
     * repeated: every file counted as valid has a date on which it stops
     * being valid.
     */
    expiringIn30: number;
    expiringIn90: number;
    /** Served something at the path, but it does not read as a security.txt. */
    unreadable: number;
  };
  filePresence: Record<string, number>;
}

export function summarise(results: DomainResult[]): Summary {
  const filePresence: Record<string, number> = {};
  let checked = 0;
  let unreachable = 0;
  let withBlockers = 0;
  let answerAnything = 0;
  const securityTxt = {
    published: 0, withoutExpires: 0, expired: 0, valid: 0,
    expiringIn30: 0, expiringIn90: 0, unreadable: 0,
  };

  for (const result of results) {
    if (result.outcome === "unreachable") {
      unreachable += 1;
      continue;
    }
    checked += 1;
    if (result.answersAnything) answerAnything += 1;
    if ((result.blockers ?? 0) > 0) withBlockers += 1;
    for (const file of result.present ?? []) filePresence[file] = (filePresence[file] ?? 0) + 1;

    const security = result.securityTxt;
    if (!security?.found) continue;
    // Served but unreadable is its own outcome. Putting it in `published`
    // would inflate every rate under it, and putting it in `withoutExpires`
    // would report a missing field in a document that is not a security.txt.
    if (!security.parsed) {
      securityTxt.unreadable += 1;
      continue;
    }
    securityTxt.published += 1;
    if (!security.hasExpires) securityTxt.withoutExpires += 1;
    else if (security.expired) securityTxt.expired += 1;
    else {
      securityTxt.valid += 1;
      const left = security.daysLeft;
      if (left !== undefined) {
        if (left <= 30) securityTxt.expiringIn30 += 1;
        if (left <= 90) securityTxt.expiringIn90 += 1;
      }
    }
  }

  return { total: results.length, checked, unreachable, answerAnything, withBlockers, securityTxt, filePresence };
}

export function renderSummary(summary: Summary): string {
  const percent = (part: number, whole: number) => (whole === 0 ? "—" : `${Math.round((part / whole) * 100)}%`);
  const lines: string[] = [];

  lines.push(`${summary.total} domain(s)`);
  lines.push("");
  lines.push(`  answered           ${summary.checked}  (${percent(summary.checked, summary.total)})`);
  lines.push(`  never answered     ${summary.unreachable}`);
  if (summary.answerAnything > 0) {
    lines.push(`  answer 200 to any path  ${summary.answerAnything}  (counted only what parsed)`);
  }
  lines.push("");

  if (summary.checked === 0) return lines.join("\n");

  const s = summary.securityTxt;
  lines.push(`Of the ${summary.checked} that answered:`);
  lines.push(`  publish a security.txt        ${s.published}  (${percent(s.published, summary.checked)})`);
  if (s.unreadable > 0) {
    lines.push(`  served one that is not one    ${s.unreadable}  (not counted in any rate below)`);
  }
  lines.push(`  at least one blocker          ${summary.withBlockers}  (${percent(summary.withBlockers, summary.checked)})`);
  lines.push("");

  if (s.published > 0) {
    lines.push(`Of the ${s.published} security.txt files:`);
    lines.push(`  valid today                   ${s.valid}  (${percent(s.valid, s.published)})`);
    lines.push(`  expired                       ${s.expired}  (${percent(s.expired, s.published)})`);
    lines.push(`  no Expires field at all       ${s.withoutExpires}  (${percent(s.withoutExpires, s.published)})`);
    if (s.valid > 0) {
      lines.push(`  of those valid, lapse in 30d  ${s.expiringIn30}  (${percent(s.expiringIn30, s.valid)})`);
      lines.push(`  of those valid, lapse in 90d  ${s.expiringIn90}  (${percent(s.expiringIn90, s.valid)})`);
    }
    lines.push("");
  }

  const files = Object.entries(summary.filePresence).sort((a, b) => b[1] - a[1]);
  if (files.length > 0) {
    lines.push("Files found, by how many sites publish them:");
    for (const [file, count] of files) {
      lines.push(`  ${file.padEnd(28)} ${count}  (${percent(count, summary.checked)})`);
    }
  }
  return lines.join("\n");
}
