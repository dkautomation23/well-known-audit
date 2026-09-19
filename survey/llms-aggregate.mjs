/**
 * Turns the conformance run into the few numbers worth publishing.
 *
 * Every rate here is printed with its own denominator written out, because the
 * denominator is where this kind of survey usually lies. A site that could not
 * be checked is never counted as a site that failed: unreachable hosts, hosts
 * that refused us, and hosts that answer 200 to every path are each their own
 * line, and none of them is inside any percentage about broken files.
 *
 *     node survey/llms-aggregate.mjs <run.csv> <out.json>
 */

import { readFileSync, writeFileSync } from "node:fs";

const [inPath, outPath] = process.argv.slice(2);
if (!inPath) {
  process.stderr.write("usage: node survey/llms-aggregate.mjs <run.csv> [out.json]\n");
  process.exit(2);
}

const lines = readFileSync(inPath, "utf8").split(/\r?\n/).filter(Boolean);
const header = lines[0].split(",");
const rows = lines.slice(1).map((line) => {
  const cells = line.split(",");
  return Object.fromEntries(header.map((name, i) => [name, cells[i] ?? ""]));
});

const total = rows.length;
const by = (outcome) => rows.filter((r) => r.outcome === outcome);

const checked = by("checked");
const noLlms = by("no-llms");
const notText = by("not-text");
const soft404 = by("soft-404");
const blocked = by("blocked");
const unreachable = by("unreachable");

/** Sites we could genuinely ask the question of. */
const answered = checked.length + noLlms.length + notText.length;

const conformant = checked.filter((r) => r.conformant === "yes");
const withLinksChecked = checked.filter((r) => Number(r.links_checked) > 0);
const withBroken = withLinksChecked.filter((r) => Number(r.links_broken) > 0);

const linksChecked = withLinksChecked.reduce((sum, r) => sum + Number(r.links_checked), 0);
const linksOk = withLinksChecked.reduce((sum, r) => sum + Number(r.links_ok), 0);
const linksBroken = withLinksChecked.reduce((sum, r) => sum + Number(r.links_broken), 0);
const linksUnverified = withLinksChecked.reduce((sum, r) => sum + Number(r.links_unverified), 0);

const contradiction = checked.filter((r) => r.contradiction === "yes");

const agents = header
  .filter((name) => name.startsWith("robots_"))
  .map((name) => name.slice("robots_".length));

const robotsStance = {};
for (const agent of agents) {
  const withRobots = rows.filter((r) => r.robots === "yes");
  const count = (verdict) => withRobots.filter((r) => r[`robots_${agent}`] === verdict).length;
  robotsStance[agent] = {
    population: withRobots.length,
    blocked: count("blocked"),
    partial: count("partial"),
    allowed: count("allowed"),
    absent: count("absent"),
  };
}

const pct = (part, whole) => (whole === 0 ? null : Number(((part / whole) * 100).toFixed(1)));

const summary = {
  method: {
    source: "Tranco list V3YPN, top 1500 domains",
    collected: new Date().toISOString().slice(0, 10),
    tool: "well-known-audit/survey/llms-conformance.mjs",
    politeness:
      "4 domains at a time, 250ms between batches, 300ms between link checks, at most 8 links per site, no retries, honest User-Agent",
    soft404:
      "each domain is first asked for a path that cannot exist; a 200 there means the site answers 200 to anything, and it is excluded from every rate",
    robots:
      "only a group naming the crawler explicitly counts; the wildcard group is not evidence about a named bot, and only Disallow: / counts as a full block",
  },
  population: {
    total,
    answered,
    could_not_check: {
      soft_404: soft404.length,
      refused_us: blocked.length,
      unreachable: unreachable.length,
    },
  },
  llms_txt: {
    publishing: checked.length,
    publishing_share_of_answered: pct(checked.length, answered),
    served_but_not_text: notText.length,
    absent: noLlms.length,
  },
  conformance: {
    population: checked.length,
    conformant: conformant.length,
    conformant_share: pct(conformant.length, checked.length),
    missing_h1: checked.filter((r) => r.has_h1 === "no").length,
    no_sections: checked.filter((r) => Number(r.section_count) === 0).length,
    no_links: checked.filter((r) => Number(r.link_count) === 0).length,
  },
  links: {
    sites_with_links_checked: withLinksChecked.length,
    sites_with_at_least_one_broken: withBroken.length,
    sites_with_broken_share: pct(withBroken.length, withLinksChecked.length),
    links_checked: linksChecked,
    links_ok: linksOk,
    links_broken: linksBroken,
    links_could_not_verify: linksUnverified,
    broken_share_of_checked: pct(linksBroken, linksChecked),
  },
  contradiction: {
    definition:
      "publishes a usable llms.txt and, in the same breath, bans at least one named AI crawler outright in robots.txt",
    population: checked.length,
    count: contradiction.length,
    share: pct(contradiction.length, checked.length),
  },
  robots_stance: robotsStance,
};

const text = JSON.stringify(summary, null, 2);
if (outPath) writeFileSync(outPath, `${text}\n`, "utf8");
process.stdout.write(`${text}\n`);
