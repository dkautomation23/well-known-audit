/**
 * Does the llms.txt a site publishes actually work?
 *
 * Every published count of llms.txt so far answers one question: is the file
 * there. That question is answered - several independent scans put adoption in
 * the top 1,000 somewhere between 8% and 16% as of June 2026. Nobody has asked
 * the next one, which is the one that decides whether the file does anything:
 * is it the shape the specification describes, and do the links inside it
 * still resolve? A file that lists twelve pages, nine of which 404, is worse
 * than no file at all - it hands an agent a map to nowhere.
 *
 * The second question this answers is a contradiction nobody has counted: how
 * many sites publish a guide for language models while their robots.txt bans
 * the crawlers that would read it.
 *
 * Politeness is not optional here. Four domains at a time, a pause between
 * batches, one request per file, a pause between link checks on the same host,
 * at most eight links checked per site, an honest User-Agent that says who is
 * calling, and no retry on a refusal. A 403 or a 429 is recorded as "could not
 * check" and never counted as a fault of the site.
 *
 *     node survey/llms-conformance.mjs <domains.txt> <out.csv> [--limit N]
 *
 * The CSV is written row by row, so an interrupted run loses nothing and a
 * second run resumes where the first stopped.
 */

import { appendFileSync, existsSync, readFileSync } from "node:fs";

const UA =
  "well-known-audit/0.1.1 (+https://github.com/dkautomation23/well-known-audit; survey of llms.txt conformance)";

const CONCURRENCY = 4;
const PAUSE_BETWEEN_BATCHES_MS = 250;
const PAUSE_BETWEEN_LINKS_MS = 300;
const TIMEOUT_MS = 10_000;
const MAX_LINKS_CHECKED = 8;
/** A path that cannot exist. A site answering 200 here answers 200 to anything. */
const CONTROL_PATH = "/llms-conformance-control-should-not-exist.txt";

/** The crawlers whose names actually appear in robots.txt files in 2026. */
const AI_AGENTS = [
  "GPTBot",
  "ClaudeBot",
  "Google-Extended",
  "CCBot",
  "PerplexityBot",
  "Bytespider",
  "Applebot-Extended",
];

const CSV_HEADER = [
  "domain",
  "outcome",
  "llms_bytes",
  "has_h1",
  "has_summary",
  "section_count",
  "link_count",
  "links_checked",
  "links_ok",
  "links_broken",
  "links_unverified",
  "conformant",
  "robots",
  ...AI_AGENTS.map((a) => `robots_${a}`),
  "blocks_any_ai",
  "contradiction",
].join(",");

// ---------------------------------------------------------------- fetching

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * One request, no retries, no redirect chasing past what fetch does for us.
 * Every failure is a value, never an exception: a survey that throws on the
 * first unreachable host is a survey of the reachable web.
 */
async function get(url, { method = "GET" } = {}) {
  try {
    const response = await fetch(url, {
      method,
      headers: { "user-agent": UA, accept: "*/*" },
      redirect: "follow",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    const type = response.headers.get("content-type") ?? "";
    // Only read a body we might parse; a 20 MB HTML error page helps nobody.
    const body =
      method === "GET" && response.ok && !type.includes("image/")
        ? (await response.text()).slice(0, 512 * 1024)
        : "";
    return { status: response.status, type, body, url: response.url };
  } catch (error) {
    const name = error?.name === "TimeoutError" ? "timeout" : "network";
    return { status: 0, type: "", body: "", url, error: name };
  }
}

// ---------------------------------------------------------------- llms.txt

/**
 * The shape llms.txt is supposed to have: an H1 with the site's name, an
 * optional blockquote summary, then H2 sections of markdown links.
 *
 * "Conformant" here is deliberately generous - an H1 and at least one link
 * under at least one H2. Anything stricter would measure our reading of the
 * specification rather than whether an agent can use the file.
 */
function parseLlms(text) {
  const lines = text.split(/\r?\n/);
  const hasH1 = lines.some((line) => /^#\s+\S/.test(line));
  const hasSummary = lines.some((line) => /^>\s*\S/.test(line));
  const sectionCount = lines.filter((line) => /^##\s+\S/.test(line)).length;

  const links = [];
  const pattern = /\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g;
  let match;
  while ((match = pattern.exec(text)) !== null) links.push(match[1]);

  return { hasH1, hasSummary, sectionCount, links };
}

/**
 * Tells a real llms.txt from the HTML a single-page app serves for every path.
 * Both checks are needed: the control request catches a site that answers 200
 * everywhere, and the HTML sniff catches one that serves its index page with a
 * text/plain header.
 */
function looksLikeMarkdown(response) {
  if (response.status !== 200) return false;
  const head = response.body.slice(0, 400).toLowerCase();
  if (head.includes("<!doctype html") || head.includes("<html")) return false;
  if (response.type.includes("text/html")) return false;
  return response.body.trim().length > 0;
}

// ---------------------------------------------------------------- robots.txt

/**
 * What robots.txt says about one named crawler.
 *
 * Only groups naming the agent exactly are read - the wildcard group is not
 * evidence about a specific bot, and treating it as such is how published
 * blocking rates get inflated. Returns "blocked" only for a rule that closes
 * the whole site (`Disallow: /`), "partial" for narrower rules, "allowed" when
 * the group exists but bans nothing, and "absent" when the name never appears.
 */
function robotsVerdict(text, agent) {
  const lines = text.split(/\r?\n/).map((line) => line.replace(/#.*$/, "").trim());
  const wanted = agent.toLowerCase();

  let inGroup = false;
  let sawGroup = false;
  let blanket = false;
  let narrow = false;
  let previousWasAgent = false;

  for (const line of lines) {
    const agentMatch = /^user-agent\s*:\s*(.+)$/i.exec(line);
    if (agentMatch) {
      const name = agentMatch[1].trim().toLowerCase();
      // Consecutive User-agent lines share one group of rules.
      if (!previousWasAgent) inGroup = false;
      if (name === wanted) {
        inGroup = true;
        sawGroup = true;
      }
      previousWasAgent = true;
      continue;
    }
    previousWasAgent = false;
    if (!inGroup) continue;

    const disallow = /^disallow\s*:\s*(.*)$/i.exec(line);
    if (disallow) {
      const path = disallow[1].trim();
      if (path === "/") blanket = true;
      else if (path !== "") narrow = true;
    }
  }

  if (!sawGroup) return "absent";
  if (blanket) return "blocked";
  if (narrow) return "partial";
  return "allowed";
}

// ---------------------------------------------------------------- one domain

async function survey(domain) {
  const origin = `https://${domain}`;

  const control = await get(`${origin}${CONTROL_PATH}`);
  if (control.status === 200) {
    return { domain, outcome: "soft-404" };
  }
  if (control.status === 403 || control.status === 429) {
    return { domain, outcome: "blocked" };
  }

  const llms = await get(`${origin}/llms.txt`);
  if (llms.status === 403 || llms.status === 429) return { domain, outcome: "blocked" };
  if (llms.status === 0) return { domain, outcome: "unreachable" };

  const robots = await get(`${origin}/robots.txt`);
  const robotsText = looksLikeMarkdown(robots) || robots.status === 200 ? robots.body : "";
  const verdicts = {};
  for (const agent of AI_AGENTS) {
    verdicts[agent] = robotsText ? robotsVerdict(robotsText, agent) : "no-robots";
  }
  const blocksAny = AI_AGENTS.some((a) => verdicts[a] === "blocked");

  if (!looksLikeMarkdown(llms)) {
    return {
      domain,
      outcome: llms.status === 200 ? "not-text" : "no-llms",
      robots: robotsText ? "yes" : "no",
      verdicts,
      blocksAny,
    };
  }

  const parsed = parseLlms(llms.body);

  // Check the links the file points at, on the file's own origin rules: at
  // most eight, spaced, HEAD first so we do not pull whole pages.
  let ok = 0;
  let broken = 0;
  let unverified = 0;
  const toCheck = parsed.links.filter((l) => /^https?:\/\//i.test(l)).slice(0, MAX_LINKS_CHECKED);
  for (const link of toCheck) {
    const head = await get(link, { method: "HEAD" });
    let status = head.status;
    // Plenty of servers refuse HEAD but answer GET; that is not a broken link.
    if (status === 405 || status === 501 || status === 0) {
      const full = await get(link);
      status = full.status;
    }
    if (status >= 200 && status < 400) ok += 1;
    else if (status === 0 || status === 403 || status === 429) unverified += 1;
    else broken += 1;
    await sleep(PAUSE_BETWEEN_LINKS_MS);
  }

  const conformant = parsed.hasH1 && parsed.sectionCount > 0 && parsed.links.length > 0;

  return {
    domain,
    outcome: "checked",
    bytes: llms.body.length,
    parsed,
    checked: toCheck.length,
    ok,
    broken,
    unverified,
    conformant,
    robots: robotsText ? "yes" : "no",
    verdicts,
    blocksAny,
  };
}

// ---------------------------------------------------------------- csv

function row(result) {
  const p = result.parsed;
  const v = result.verdicts ?? {};
  const cells = [
    result.domain,
    result.outcome,
    result.bytes ?? "",
    p ? (p.hasH1 ? "yes" : "no") : "",
    p ? (p.hasSummary ? "yes" : "no") : "",
    p ? p.sectionCount : "",
    p ? p.links.length : "",
    result.checked ?? "",
    result.ok ?? "",
    result.broken ?? "",
    result.unverified ?? "",
    result.conformant === undefined ? "" : result.conformant ? "yes" : "no",
    result.robots ?? "",
    ...AI_AGENTS.map((a) => v[a] ?? ""),
    result.blocksAny === undefined ? "" : result.blocksAny ? "yes" : "no",
    result.outcome === "checked" && result.blocksAny ? "yes" : "",
  ];
  return cells.map((c) => String(c)).join(",");
}

// ---------------------------------------------------------------- main

const [domainsPath, outPath] = process.argv.slice(2);
if (!domainsPath || !outPath) {
  process.stderr.write("usage: node survey/llms-conformance.mjs <domains.txt> <out.csv> [--limit N]\n");
  process.exit(2);
}
const limitArg = process.argv.indexOf("--limit");
const limit = limitArg > -1 ? Number(process.argv[limitArg + 1]) : Infinity;

// The domain lists carry a header explaining where the ranking came from, so
// comment lines are dropped rather than looked up as hostnames.
const all = readFileSync(domainsPath, "utf8")
  .split(/\r?\n/)
  .map((d) => d.trim())
  .filter((d) => d.length > 0 && !d.startsWith("#"));

let done = new Set();
if (existsSync(outPath)) {
  const lines = readFileSync(outPath, "utf8").split(/\r?\n/).filter(Boolean);
  for (const line of lines.slice(1)) done.add(line.split(",")[0]);
  process.stdout.write(`resuming: ${done.size} domain(s) already in ${outPath}\n`);
} else {
  appendFileSync(outPath, `${CSV_HEADER}\n`, "utf8");
}

const todo = all.filter((d) => !done.has(d)).slice(0, limit);
process.stdout.write(`${todo.length} domain(s) to check, ${CONCURRENCY} at a time\n`);

let finished = 0;
for (let start = 0; start < todo.length; start += CONCURRENCY) {
  const batch = todo.slice(start, start + CONCURRENCY);
  const results = await Promise.all(batch.map((d) => survey(d)));
  for (const result of results) appendFileSync(outPath, `${row(result)}\n`, "utf8");
  finished += batch.length;
  if (finished % 40 === 0 || finished === todo.length) {
    process.stdout.write(`  ${finished}/${todo.length}\n`);
  }
  if (start + CONCURRENCY < todo.length) await sleep(PAUSE_BETWEEN_BATCHES_MS);
}

process.stdout.write(`done: ${outPath}\n`);
