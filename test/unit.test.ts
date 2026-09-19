import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";

import { countByLevel, evaluateTarget, type Finding } from "../src/checks.js";
import { run } from "../src/cli.js";
import {
  parseDomainList,
  renderSummary,
  summarise as summariseBatch,
  toCsv,
  toCsvRow,
  domainsIn,
  CSV_HEADER,
  auditDomain,
  CONTROL_PATH,
  type DomainResult,
} from "../src/batch.js";
import {
  countLlmsLinks,
  isPlainObject,
  looksLikeHtml,
  looksLikeUri,
  parseMtaSts,
  parseRobotsTxt,
  parseSecurityTxt,
  safeJsonParse,
} from "../src/parse.js";
import {
  classifyFetchError,
  httpFetcher,
  isPublicUrl,
  runLimited,
  safeGet,
  type Fetcher,
  type FetchErrorClass,
  type FetchOutcome,
} from "../src/probe.js";
import { renderConsole, renderJson } from "../src/report.js";
import { findTarget, TARGETS, urlsFor } from "../src/targets.js";

const work = mkdtempSync(join(tmpdir(), "well-known-audit-"));
after(() => rmSync(work, { recursive: true, force: true }));

const DAY = 86_400_000;
const NOW = Date.now();
function iso(offsetMs: number): string {
  return new Date(NOW + offsetMs).toISOString();
}
function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
function has(findings: Finding[], id: string): Finding | undefined {
  return findings.find((finding) => finding.id === id);
}

/** A bare-bones successful fetch, overridden per test. */
function outcome(url: string, overrides: Partial<FetchOutcome> = {}): FetchOutcome {
  return {
    url,
    reached: true,
    status: 200,
    redirected: false,
    contentType: "text/plain",
    body: "",
    bytes: 0,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// parsing
// ---------------------------------------------------------------------------

describe("parsing security.txt", () => {
  it("reads every field RFC 9116 defines", () => {
    const fields = parseSecurityTxt(
      "Contact: mailto:security@x.example\n" +
        "Contact: https://x.example/report\n" +
        "Expires: 2026-12-31T18:37:07z\n" +
        "Encryption: https://x.example/pgp-key.txt\n" +
        "Policy: https://x.example/disclosure\n" +
        "Preferred-Languages: en, fr\n" +
        "Canonical: https://x.example/.well-known/security.txt\n" +
        "Acknowledgments: https://x.example/thanks\n",
    );
    assert.deepEqual(fields.contacts, ["mailto:security@x.example", "https://x.example/report"]);
    assert.deepEqual(fields.expiresValues, ["2026-12-31T18:37:07z"]);
    assert.equal(fields.encryption, "https://x.example/pgp-key.txt");
    assert.equal(fields.policy, "https://x.example/disclosure");
    assert.deepEqual(fields.canonical, ["https://x.example/.well-known/security.txt"]);
    assert.deepEqual(fields.preferredLanguagesValues, ["en, fr"]);
    assert.equal(fields.acknowledgments, "https://x.example/thanks");
  });

  it("skips comments and a PGP armour wrapper without choking on them", () => {
    const fields = parseSecurityTxt(
      "-----BEGIN PGP SIGNED MESSAGE-----\n" +
        "Hash: SHA256\n" +
        "\n" +
        "# where to report a vulnerability\n" +
        "Contact: mailto:security@x.example\n" +
        "Expires: 2026-12-31T18:37:07z\n" +
        "-----BEGIN PGP SIGNATURE-----\n" +
        "abcdef\n" +
        "-----END PGP SIGNATURE-----\n",
    );
    assert.deepEqual(fields.contacts, ["mailto:security@x.example"]);
    assert.deepEqual(fields.expiresValues, ["2026-12-31T18:37:07z"]);
  });

  it("counts a field seen more than once, for the RFC's exactly-one fields", () => {
    const fields = parseSecurityTxt("Expires: 2026-01-01T00:00:00z\nExpires: 2027-01-01T00:00:00z\n");
    assert.equal(fields.expiresValues.length, 2);
  });

  it("treats a body with no field-shaped lines as zero fields", () => {
    const fields = parseSecurityTxt("this is somebody's homepage, not a security.txt at all");
    assert.equal(fields.fieldLineCount, 0);
  });
});

describe("parsing robots.txt", () => {
  it("collects Sitemap lines wherever they appear", () => {
    const info = parseRobotsTxt("User-agent: *\nDisallow: /admin\nSitemap: https://x.example/sitemap.xml\n");
    assert.deepEqual(info.sitemaps, ["https://x.example/sitemap.xml"]);
    assert.equal(info.disallowsEverything, false);
  });

  it("flags User-agent: * / Disallow: / with no exception as blocking everyone", () => {
    const info = parseRobotsTxt("User-agent: *\nDisallow: /\n");
    assert.equal(info.disallowsEverything, true);
  });

  it("a narrower Allow in the same block means it is not a full block", () => {
    const info = parseRobotsTxt("User-agent: *\nDisallow: /\nAllow: /public\n");
    assert.equal(info.disallowsEverything, false);
  });

  it("a second User-agent line after rules starts a new record", () => {
    // Only Googlebot is restricted here; the "*" record disallows nothing.
    const info = parseRobotsTxt("User-agent: Googlebot\nDisallow: /private\n\nUser-agent: *\nDisallow:\n");
    assert.equal(info.disallowsEverything, false);
  });

  it("still finds the * record's full block when another record precedes it", () => {
    const info = parseRobotsTxt("User-agent: Googlebot\nDisallow: /private\n\nUser-agent: *\nDisallow: /\n");
    assert.equal(info.disallowsEverything, true);
  });
});

describe("parsing mta-sts.txt", () => {
  it("reads version, mode, repeated mx and max_age", () => {
    const fields = parseMtaSts("version: STSv1\nmode: enforce\nmx: mail1.x.example\nmx: mail2.x.example\nmax_age: 604800\n");
    assert.equal(fields.version, "STSv1");
    assert.equal(fields.mode, "enforce");
    assert.deepEqual(fields.mx, ["mail1.x.example", "mail2.x.example"]);
    assert.equal(fields.maxAge, "604800");
  });

  it("leaves fields undefined when the file does not have them", () => {
    const fields = parseMtaSts("version: STSv1\n");
    assert.equal(fields.mode, undefined);
    assert.deepEqual(fields.mx, []);
  });
});

describe("counting llms.txt links", () => {
  it("counts markdown links and ignores plain text", () => {
    assert.equal(countLlmsLinks("[Docs](https://x.example/docs)\n[API](https://x.example/api)\n"), 2);
    assert.equal(countLlmsLinks("Just a paragraph with no links at all."), 0);
  });
});

describe("looksLikeHtml", () => {
  it("is true when the content type says html", () => {
    assert.equal(looksLikeHtml("gpc: 1", "text/html; charset=utf-8"), true);
  });
  it("is true when the body itself is an HTML shell, whatever the content type", () => {
    assert.equal(looksLikeHtml("<!DOCTYPE html><html><body>app</body></html>", ""), true);
  });
  it("is false for ordinary plain text or JSON", () => {
    assert.equal(looksLikeHtml("Contact: mailto:a@x.example", "text/plain"), false);
    assert.equal(looksLikeHtml('{"gpc":true}', "application/json"), false);
  });
});

describe("safeJsonParse / isPlainObject / looksLikeUri", () => {
  it("parses valid JSON and reports invalid JSON without throwing", () => {
    assert.deepEqual(safeJsonParse('{"a":1}'), { ok: true, value: { a: 1 } });
    const bad = safeJsonParse("{not json");
    assert.equal(bad.ok, false);
  });
  it("tells a plain object apart from an array or null", () => {
    assert.equal(isPlainObject({}), true);
    assert.equal(isPlainObject([]), false);
    assert.equal(isPlainObject(null), false);
  });
  it("recognises a URI and rejects a bare address", () => {
    assert.equal(looksLikeUri("mailto:security@x.example"), true);
    assert.equal(looksLikeUri("https://x.example/report"), true);
    assert.equal(looksLikeUri("security@x.example"), false);
  });
});

// ---------------------------------------------------------------------------
// evaluating each file type
// ---------------------------------------------------------------------------

const GOOD_SECURITY_TXT =
  `Contact: mailto:security@x.example\nExpires: ${iso(30 * DAY)}\nPreferred-Languages: en\n`;

describe("evaluating security.txt", () => {
  const def = findTarget("security.txt")!;
  const wkUrl = "https://x.example/.well-known/security.txt";
  const rootUrl = "https://x.example/security.txt";

  it("a complete, current file has no blockers", () => {
    const result = evaluateTarget(def, [outcome(wkUrl, { body: GOOD_SECURITY_TXT }), outcome(rootUrl, { status: 404 })], NOW);
    assert.equal(countByLevel(result.findings).blocker, 0);
    assert.match(result.summary, /valid/);
  });

  it("an expired Expires is a blocker naming how many days ago", () => {
    const body = `Contact: mailto:security@x.example\nExpires: ${iso(-10 * DAY)}\n`;
    const result = evaluateTarget(def, [outcome(wkUrl, { body }), outcome(rootUrl, { status: 404 })], NOW);
    const finding = has(result.findings, "security-txt-expired");
    assert.equal(finding?.level, "blocker");
    assert.match(finding!.title, /expired 10 day\(s\) ago/);
  });

  it("no Expires field at all is a blocker", () => {
    const body = "Contact: mailto:security@x.example\n";
    const result = evaluateTarget(def, [outcome(wkUrl, { body }), outcome(rootUrl, { status: 404 })], NOW);
    assert.equal(has(result.findings, "security-txt-no-expires")?.level, "blocker");
  });

  it("more than one Expires field is a blocker", () => {
    const body = `Contact: mailto:security@x.example\nExpires: ${iso(DAY)}\nExpires: ${iso(2 * DAY)}\n`;
    const result = evaluateTarget(def, [outcome(wkUrl, { body }), outcome(rootUrl, { status: 404 })], NOW);
    assert.equal(has(result.findings, "security-txt-multiple-expires")?.level, "blocker");
  });

  it("a Contact value that is not a URI is a warning, not a blocker", () => {
    const body = `Contact: security@x.example\nExpires: ${iso(30 * DAY)}\n`;
    const result = evaluateTarget(def, [outcome(wkUrl, { body }), outcome(rootUrl, { status: 404 })], NOW);
    const finding = has(result.findings, "security-txt-contact-malformed");
    assert.equal(finding?.level, "warning");
    assert.equal(countByLevel(result.findings).blocker, 0);
  });

  it("no Contact field at all is a blocker", () => {
    const body = `Expires: ${iso(30 * DAY)}\n`;
    const result = evaluateTarget(def, [outcome(wkUrl, { body }), outcome(rootUrl, { status: 404 })], NOW);
    assert.equal(has(result.findings, "security-txt-no-contact")?.level, "blocker");
  });

  it("more than one Preferred-Languages field is a blocker", () => {
    const body = `Contact: mailto:a@x.example\nExpires: ${iso(30 * DAY)}\nPreferred-Languages: en\nPreferred-Languages: fr\n`;
    const result = evaluateTarget(def, [outcome(wkUrl, { body }), outcome(rootUrl, { status: 404 })], NOW);
    assert.equal(has(result.findings, "security-txt-multiple-preferred-languages")?.level, "blocker");
  });

  it("an Expires more than a year out is a warning", () => {
    const body = `Contact: mailto:a@x.example\nExpires: ${iso(400 * DAY)}\n`;
    const result = evaluateTarget(def, [outcome(wkUrl, { body }), outcome(rootUrl, { status: 404 })], NOW);
    assert.equal(has(result.findings, "security-txt-expires-far")?.level, "warning");
  });

  it("a body with no recognisable fields is not a valid security.txt", () => {
    const result = evaluateTarget(
      def,
      [outcome(wkUrl, { body: "hello, welcome to my website" }), outcome(rootUrl, { status: 404 })],
      NOW,
    );
    assert.equal(has(result.findings, "security-txt-unparseable")?.level, "blocker");
  });

  it("neither location published is reported as missing, not invalid", () => {
    const result = evaluateTarget(def, [outcome(wkUrl, { status: 404 }), outcome(rootUrl, { status: 404 })], NOW);
    assert.equal(has(result.findings, "security.txt-missing")?.level, "warning");
    assert.equal(result.summary, "not found");
  });

  it("only the legacy /security.txt existing is a warning to publish the canonical copy", () => {
    const result = evaluateTarget(
      def,
      [outcome(wkUrl, { status: 404 }), outcome(rootUrl, { body: GOOD_SECURITY_TXT })],
      NOW,
    );
    assert.equal(has(result.findings, "security-txt-legacy-location")?.level, "warning");
  });

  it("two copies that disagree are a note", () => {
    const result = evaluateTarget(
      def,
      [
        outcome(wkUrl, { body: GOOD_SECURITY_TXT }),
        outcome(rootUrl, { body: `Contact: mailto:other@x.example\nExpires: ${iso(30 * DAY)}\n` }),
      ],
      NOW,
    );
    assert.equal(has(result.findings, "security-txt-copies-differ")?.level, "note");
  });
});

describe("evaluating robots.txt", () => {
  const def = findTarget("robots.txt")!;
  const url = "https://x.example/robots.txt";

  it("a normal file with a sitemap and no full block has no findings", () => {
    const result = evaluateTarget(def, [outcome(url, { body: "User-agent: *\nDisallow: /admin\nSitemap: https://x.example/sitemap.xml\n" })]);
    assert.deepEqual(result.findings, []);
    assert.match(result.summary, /1 sitemap/);
  });

  it("no Sitemap: line is a note", () => {
    const result = evaluateTarget(def, [outcome(url, { body: "User-agent: *\nDisallow: /admin\n" })]);
    assert.equal(has(result.findings, "robots-txt-no-sitemap")?.level, "note");
  });

  it("blocking every crawler is a warning", () => {
    const result = evaluateTarget(def, [outcome(url, { body: "User-agent: *\nDisallow: /\n" })]);
    assert.equal(has(result.findings, "robots-txt-disallows-all")?.level, "warning");
  });

  it("served as an HTML page is a blocker", () => {
    const result = evaluateTarget(def, [outcome(url, { body: "<!doctype html><html></html>", contentType: "text/html" })]);
    assert.equal(has(result.findings, "robots-txt-html")?.level, "blocker");
  });

  it("missing entirely is a warning - most sites should have one", () => {
    const result = evaluateTarget(def, [outcome(url, { status: 404 })]);
    assert.equal(has(result.findings, "robots.txt-missing")?.level, "warning");
  });
});

describe("evaluating llms.txt", () => {
  const def = findTarget("llms.txt")!;
  const url = "https://x.example/llms.txt";

  it("counts the links in the summary", () => {
    const result = evaluateTarget(def, [outcome(url, { body: "[Docs](https://x.example/docs)\n[API](https://x.example/api)\n" })]);
    assert.equal(result.summary, "2 link(s)");
    assert.deepEqual(result.findings, []);
  });

  it("zero links is a note", () => {
    const result = evaluateTarget(def, [outcome(url, { body: "Just a sentence, no links." })]);
    assert.equal(has(result.findings, "llms-txt-no-links")?.level, "note");
  });

  it("missing is only a note - not every site needs one", () => {
    const result = evaluateTarget(def, [outcome(url, { status: 404 })]);
    assert.equal(has(result.findings, "llms.txt-missing")?.level, "note");
  });
});

describe("evaluating ai.txt, ucp and dnt-policy.txt (presence-only files)", () => {
  it("ai.txt missing is a note, present is clean, and HTML is flagged", () => {
    const def = findTarget("ai.txt")!;
    const url = "https://x.example/.well-known/ai.txt";
    assert.equal(has(evaluateTarget(def, [outcome(url, { status: 404 })]).findings, "ai.txt-missing")?.level, "note");
    assert.deepEqual(evaluateTarget(def, [outcome(url, { body: "User-agent: *\nAllow: /\n" })]).findings, []);
    assert.equal(has(evaluateTarget(def, [outcome(url, { body: "<html></html>", contentType: "text/html" })]).findings, "ai.txt-html")?.level, "warning");
  });

  it("ucp is only ever reported present or absent, never analysed", () => {
    const def = findTarget("ucp")!;
    const url = "https://x.example/.well-known/ucp";
    const present = evaluateTarget(def, [outcome(url, { body: "<html>this would trip the HTML sniff elsewhere</html>", contentType: "text/html" })]);
    assert.deepEqual(present.findings, [], "ucp is explicitly not analysed, per spec");
    assert.match(present.summary, /not analysed/);
  });

  it("dnt-policy.txt missing is a note", () => {
    const def = findTarget("dnt-policy.txt")!;
    const result = evaluateTarget(def, [outcome("https://x.example/.well-known/dnt-policy.txt", { status: 404 })]);
    assert.equal(has(result.findings, "dnt-policy.txt-missing")?.level, "note");
  });
});

describe("evaluating openid-configuration", () => {
  const def = findTarget("openid-configuration")!;
  const url = "https://x.example/.well-known/openid-configuration";

  it("a valid document with an https issuer is clean", () => {
    const result = evaluateTarget(def, [outcome(url, { body: '{"issuer":"https://x.example"}', contentType: "application/json" })]);
    assert.deepEqual(result.findings, []);
    assert.equal(result.summary, "issuer https://x.example");
  });

  it("no issuer field is a blocker", () => {
    const result = evaluateTarget(def, [outcome(url, { body: "{}", contentType: "application/json" })]);
    assert.equal(has(result.findings, "openid-configuration-no-issuer")?.level, "blocker");
  });

  it("invalid JSON is a blocker", () => {
    const result = evaluateTarget(def, [outcome(url, { body: "{not json", contentType: "application/json" })]);
    assert.equal(has(result.findings, "openid-configuration-invalid-json")?.level, "blocker");
  });

  it("an issuer that is not https is a warning", () => {
    const result = evaluateTarget(def, [outcome(url, { body: '{"issuer":"http://x.example"}', contentType: "application/json" })]);
    assert.equal(has(result.findings, "openid-configuration-issuer-not-https")?.level, "warning");
  });
});

describe("evaluating apple-app-site-association", () => {
  const def = findTarget("apple-app-site-association")!;
  const url = "https://x.example/.well-known/apple-app-site-association";

  it("a valid document with applinks is clean", () => {
    const result = evaluateTarget(def, [outcome(url, { body: '{"applinks":{"details":[]}}', contentType: "application/json" })]);
    assert.deepEqual(result.findings, []);
    assert.match(result.summary, /applinks/);
  });

  it("served as text/html is a blocker - the classic SPA-fallback mistake", () => {
    const result = evaluateTarget(def, [
      outcome(url, { body: "<!doctype html><html><body>Not Found</body></html>", contentType: "text/html; charset=utf-8", status: 200 }),
    ]);
    const finding = has(result.findings, "apple-app-site-association-html");
    assert.equal(finding?.level, "blocker");
  });

  it("invalid JSON is a blocker", () => {
    const result = evaluateTarget(def, [outcome(url, { body: "not json at all", contentType: "application/json" })]);
    assert.equal(has(result.findings, "apple-app-site-association-invalid-json")?.level, "blocker");
  });

  it("valid JSON with none of the known keys is a warning", () => {
    const result = evaluateTarget(def, [outcome(url, { body: '{"unrelated":true}', contentType: "application/json" })]);
    assert.equal(has(result.findings, "apple-app-site-association-no-known-keys")?.level, "warning");
  });
});

describe("evaluating assetlinks.json", () => {
  const def = findTarget("assetlinks.json")!;
  const url = "https://x.example/.well-known/assetlinks.json";

  it("a valid array of statements is clean", () => {
    const body = JSON.stringify([{ relation: ["delegate_permission/common.handle_all_urls"], target: { namespace: "android_app", package_name: "com.x" } }]);
    const result = evaluateTarget(def, [outcome(url, { body, contentType: "application/json" })]);
    assert.deepEqual(result.findings, []);
    assert.equal(result.summary, "1 statement(s)");
  });

  it("a top-level object instead of an array is a blocker", () => {
    const result = evaluateTarget(def, [outcome(url, { body: '{"relation":[]}', contentType: "application/json" })]);
    assert.equal(has(result.findings, "assetlinks-not-array")?.level, "blocker");
  });

  it("entries missing relation or target are a warning", () => {
    const body = JSON.stringify([{ relation: ["x"] }]);
    const result = evaluateTarget(def, [outcome(url, { body, contentType: "application/json" })]);
    assert.equal(has(result.findings, "assetlinks-incomplete-entries")?.level, "warning");
  });
});

describe("evaluating change-password", () => {
  const def = findTarget("change-password")!;
  const url = "https://x.example/.well-known/change-password";

  it("a direct 200 is clean", () => {
    assert.deepEqual(evaluateTarget(def, [outcome(url, { status: 200 })]).findings, []);
  });

  it("a followed redirect that lands on 200 is clean", () => {
    const result = evaluateTarget(def, [outcome(url, { status: 200, redirected: true })]);
    assert.deepEqual(result.findings, []);
    assert.match(result.summary, /redirects, then 200/);
  });

  it("404 is reported as missing, with a warning - this one applies to most sites", () => {
    const result = evaluateTarget(def, [outcome(url, { status: 404 })]);
    assert.equal(has(result.findings, "change-password-missing")?.level, "warning");
  });

  it("a redirect status with no Location to follow is a blocker", () => {
    const result = evaluateTarget(def, [outcome(url, { status: 302, redirected: false })]);
    assert.equal(has(result.findings, "change-password-bad-redirect")?.level, "blocker");
  });

  it("any other status is a blocker", () => {
    const result = evaluateTarget(def, [outcome(url, { status: 500 })]);
    assert.equal(has(result.findings, "change-password-bad-status")?.level, "blocker");
  });
});

describe("evaluating mta-sts.txt", () => {
  const def = findTarget("mta-sts.txt")!;
  const url = "https://x.example/.well-known/mta-sts.txt";

  it("a complete valid policy is clean", () => {
    const result = evaluateTarget(def, [outcome(url, { body: "version: STSv1\nmode: enforce\nmx: mail.x.example\nmax_age: 604800\n" })]);
    assert.deepEqual(result.findings, []);
  });

  it("missing required fields is a blocker naming which ones", () => {
    const result = evaluateTarget(def, [outcome(url, { body: "version: STSv1\n" })]);
    const finding = has(result.findings, "mta-sts-missing-fields");
    assert.equal(finding?.level, "blocker");
    assert.match(finding!.title, /mode/);
    assert.match(finding!.title, /max_age/);
  });

  it("an invalid mode is a blocker", () => {
    const result = evaluateTarget(def, [outcome(url, { body: "version: STSv1\nmode: whenever\nmx: mail.x.example\nmax_age: 604800\n" })]);
    assert.equal(has(result.findings, "mta-sts-bad-mode")?.level, "blocker");
  });

  it("no mx hosts is a warning", () => {
    const result = evaluateTarget(def, [outcome(url, { body: "version: STSv1\nmode: enforce\nmax_age: 604800\n" })]);
    assert.equal(has(result.findings, "mta-sts-no-mx")?.level, "warning");
  });
});

describe("evaluating gpc.json", () => {
  const def = findTarget("gpc.json")!;
  const url = "https://x.example/.well-known/gpc.json";

  it('{"gpc": true} is clean', () => {
    const result = evaluateTarget(def, [outcome(url, { body: '{"gpc":true}', contentType: "application/json" })]);
    assert.deepEqual(result.findings, []);
    assert.equal(result.summary, "gpc: true");
  });

  it("a non-boolean gpc field is a blocker", () => {
    const result = evaluateTarget(def, [outcome(url, { body: '{"gpc":"yes"}', contentType: "application/json" })]);
    assert.equal(has(result.findings, "gpc-bad-shape")?.level, "blocker");
  });

  it("invalid JSON is a blocker", () => {
    const result = evaluateTarget(def, [outcome(url, { body: "nope", contentType: "application/json" })]);
    assert.equal(has(result.findings, "gpc-invalid-json")?.level, "blocker");
  });
});

describe("a failed request becomes a finding, never a crash", () => {
  const def = findTarget("gpc.json")!;
  function errored(errorClass: FetchErrorClass): FetchOutcome {
    return outcome("https://x.example/.well-known/gpc.json", { reached: false, status: 0, error: "boom", errorClass });
  }

  it("a redirect refused for being private is a blocker", () => {
    assert.equal(evaluateTarget(def, [errored("private")]).findings[0]?.level, "blocker");
  });
  it("a response over the size cap is a blocker", () => {
    assert.equal(evaluateTarget(def, [errored("too-large")]).findings[0]?.level, "blocker");
  });
  it("a redirect loop is a blocker", () => {
    assert.equal(evaluateTarget(def, [errored("redirect-loop")]).findings[0]?.level, "blocker");
  });
  it("an ordinary network hiccup is only a warning", () => {
    assert.equal(evaluateTarget(def, [errored("network")]).findings[0]?.level, "warning");
  });
});

// ---------------------------------------------------------------------------
// safety of the tool itself
// ---------------------------------------------------------------------------

describe("isPublicUrl", () => {
  it("refuses private, loopback and non-http addresses", () => {
    for (const url of [
      "http://localhost:8080/admin",
      "http://127.0.0.1/",
      "http://169.254.169.254/latest/meta-data/",
      "http://10.0.0.5/internal",
      "http://192.168.1.1/",
      "http://172.16.0.1/",
      "http://[::1]/",
      "http://intranet/",
      "file:///etc/passwd",
      "not a url",
    ]) {
      assert.equal(isPublicUrl(url), false, `${url} must be refused`);
    }
  });

  it("allows ordinary public addresses", () => {
    for (const url of ["https://example.com/robots.txt", "http://example.com/x", "https://sub.example.co.uk/y"]) {
      assert.equal(isPublicUrl(url), true, `${url} must be allowed`);
    }
  });
});

describe("classifying a failed request", () => {
  it("recognises each of the tool's own error shapes, and falls back to network", () => {
    assert.equal(classifyFetchError('x redirects to http://127.0.0.1/, which is not a public address; refusing to follow it'), "private");
    assert.equal(classifyFetchError("x returned more than 5242880 bytes; refusing to read further"), "too-large");
    assert.equal(classifyFetchError("x sent more than 5 redirects; giving up"), "redirect-loop");
    assert.equal(classifyFetchError("fetch failed: getaddrinfo ENOTFOUND x"), "network");
  });
});

describe("safeGet", () => {
  it("turns a thrown error into data instead of throwing", async () => {
    const fetcher: Fetcher = {
      async get() {
        throw new Error("fetch failed: ECONNREFUSED");
      },
    };
    const result = await safeGet(fetcher, "https://x.example/robots.txt");
    assert.equal(result.reached, false);
    assert.equal(result.errorClass, "network");
  });

  it("passes a successful response through with a byte count", async () => {
    const fetcher: Fetcher = {
      async get() {
        return { status: 200, contentType: "text/plain", body: "hello", redirected: false };
      },
    };
    const result = await safeGet(fetcher, "https://x.example/robots.txt");
    assert.equal(result.reached, true);
    assert.equal(result.bytes, 5);
  });
});

describe("runLimited", () => {
  it("never runs more than the given limit at once", async () => {
    let inFlight = 0;
    let peak = 0;
    await runLimited(Array.from({ length: 10 }, (_, i) => i), 4, 0, async () => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise((resolve) => setTimeout(resolve, 5));
      inFlight -= 1;
    });
    assert.ok(peak <= 4, `peak concurrency was ${peak}`);
  });

  it("keeps results in the original order, whatever order they resolve in", async () => {
    const results = await runLimited([30, 10, 20], 3, 0, async (ms) => {
      await new Promise((resolve) => setTimeout(resolve, ms));
      return ms;
    });
    assert.deepEqual(results, [30, 10, 20]);
  });

  it("pauses between batches", async () => {
    const start = Date.now();
    await runLimited([1, 2, 3, 4, 5], 2, 25, async (n) => n);
    const elapsed = Date.now() - start;
    // 3 batches of size 2,2,1 -> 2 pauses of 25ms between them.
    assert.ok(elapsed >= 45, `expected roughly 50ms of pauses, took ${elapsed}ms`);
  });
});

describe("the fetcher a stranger controls", () => {
  type Handler = (request: IncomingMessage, response: ServerResponse) => void;

  async function serve(handler: Handler): Promise<{ origin: string; close: () => Promise<void> }> {
    const server = createServer(handler);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as { port: number };
    return {
      origin: `http://127.0.0.1:${port}`,
      close: () => new Promise<void>((resolve) => server.close(() => resolve())),
    };
  }

  it("does not follow a redirect into the private network", async () => {
    const metadata = await serve((_request, response) => {
      response.writeHead(200, { "content-type": "text/plain" });
      response.end("secret");
    });
    const site = await serve((_request, response) => {
      response.writeHead(302, { location: `${metadata.origin}/latest/meta-data/` });
      response.end();
    });
    try {
      const fetcher = httpFetcher(5000);
      await assert.rejects(
        () => fetcher.get(`${site.origin}/.well-known/security.txt`),
        /private|refus/i,
        "a redirect into 127.0.0.1 must be refused, not followed",
      );
    } finally {
      await site.close();
      await metadata.close();
    }
  });

  it("stops reading a body over the cap instead of buffering it", async () => {
    let sent = 0;
    const chunk = "x".repeat(64 * 1024);
    const flood = await serve((_request, response) => {
      response.writeHead(200, { "content-type": "text/plain" });
      const push = () => {
        if (!response.writableEnded && sent < 64 * 1024 * 1024) {
          sent += chunk.length;
          if (response.write(chunk)) setImmediate(push);
          else response.once("drain", push);
        }
      };
      push();
    });
    try {
      const fetcher = httpFetcher(5000);
      await assert.rejects(() => fetcher.get(`${flood.origin}/.well-known/security.txt`), /bytes|refusing/i);
      assert.ok(sent < 12 * 1024 * 1024, `read ${Math.round(sent / 1024 / 1024)} MB before giving up; the cap is 5 MB`);
    } finally {
      await flood.close();
    }
  });

  it("gives up rather than following a redirect chain forever", async () => {
    let hops = 0;
    const loop = await serve((_request, response) => {
      hops += 1;
      response.writeHead(302, { location: `/again/${hops}` });
      response.end();
    });
    try {
      const fetcher = httpFetcher(5000);
      await assert.rejects(() => fetcher.get(`${loop.origin}/.well-known/security.txt`), /redirect/i);
      assert.ok(hops <= 6, `followed ${hops} redirects`);
    } finally {
      await loop.close();
    }
  });

  it("a direct response with no redirect reports status, body and redirected: false", async () => {
    // A same-host redirect cannot be used to test the positive follow path:
    // 127.0.0.1 is private by definition, so a hop from one loopback server to
    // another (or to itself) is correctly refused by the same guard the
    // "redirect into the private network" test above relies on. What IS safe
    // to prove against a real server is that an unredirected response comes
    // back with the right shape end to end.
    const target = await serve((_request, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end('{"gpc":true}');
    });
    try {
      const fetcher = httpFetcher(5000);
      const result = await fetcher.get(`${target.origin}/.well-known/gpc.json`);
      assert.equal(result.status, 200);
      assert.equal(result.redirected, false);
      assert.equal(result.contentType, "application/json");
      assert.equal(result.body, '{"gpc":true}');
    } finally {
      await target.close();
    }
  });
});

// ---------------------------------------------------------------------------
// the target list
// ---------------------------------------------------------------------------

describe("the target list", () => {
  it("requests two URLs for security.txt and one for everything else", () => {
    const urls = urlsFor("https://x.example", TARGETS);
    assert.equal(urls.filter((entry) => entry.target.id === "security.txt").length, 2);
    assert.equal(
      urls.length,
      TARGETS.reduce((total, target) => total + target.paths.length, 0),
    );
  });

  it("finds a target by id and reports an unknown one as absent", () => {
    assert.equal(findTarget("robots.txt")?.label, "robots.txt");
    assert.equal(findTarget("not-a-real-target"), undefined);
  });
});

// ---------------------------------------------------------------------------
// rendering
// ---------------------------------------------------------------------------

describe("rendering the report", () => {
  const context = { domain: "x.example", checkedAt: "2026-01-01T00:00:00.000Z", timeoutMs: 10_000 };

  it("prints one ok row for a file with no findings", () => {
    const text = renderConsole([{ id: "gpc.json", label: "gpc.json", urls: ["u"], summary: "gpc: true", findings: [] }], context);
    assert.match(text, /ok\s+gpc\.json\s+gpc: true/);
  });

  it("prints the worst finding first when a file has more than one", () => {
    const findings: Finding[] = [
      { id: "a", level: "note", title: "a note", detail: "" },
      { id: "b", level: "blocker", title: "a blocker", detail: "why it matters", fix: "do this" },
    ];
    const text = renderConsole([{ id: "security.txt", label: "security.txt", urls: ["u"], summary: "invalid", findings }], context);
    const lines = text.split("\n");
    const blockLine = lines.findIndex((line) => line.includes("BLOCK"));
    const noteLine = lines.findIndex((line) => line.includes("a note"));
    assert.ok(blockLine >= 0 && noteLine >= 0 && blockLine < noteLine, "blocker must print before note");
    assert.match(text, /-> do this/);
  });

  it("totals blockers, warnings and notes across every file", () => {
    const text = renderConsole(
      [
        { id: "ai.txt", label: "a", urls: [], summary: "", findings: [{ id: "x", level: "blocker", title: "t", detail: "" }] },
        { id: "dnt-policy.txt", label: "b", urls: [], summary: "", findings: [{ id: "y", level: "warning", title: "t", detail: "" }] },
      ],
      context,
    );
    assert.match(text, /1 blocker\(s\), 1 warning\(s\), 0 note\(s\)/);
  });

  it("renderJson carries the domain and the same counts", () => {
    const findings: Finding[] = [{ id: "a", level: "warning", title: "t", detail: "d" }];
    const parsed = JSON.parse(renderJson([{ id: "gpc.json", label: "x", urls: ["u"], summary: "s", findings }], context));
    assert.equal(parsed.domain, "x.example");
    assert.equal(parsed.summary.warning, 1);
  });
});

// ---------------------------------------------------------------------------
// the whole run, through the CLI, against a fake fetcher
// ---------------------------------------------------------------------------

interface TableEntry {
  status: number;
  body?: string;
  contentType?: string;
  redirected?: boolean;
}

function tableFetcher(table: Record<string, TableEntry>): Fetcher {
  return {
    async get(url) {
      const entry = table[url];
      if (!entry) return { status: 404, contentType: "text/plain", body: "", redirected: false };
      return {
        status: entry.status,
        contentType: entry.contentType ?? "text/plain",
        body: entry.body ?? "",
        redirected: entry.redirected ?? false,
      };
    },
  };
}

describe("the whole run", () => {
  it("exits 1 and shows the blocker for a domain with an expired security.txt", async () => {
    const fetcher = tableFetcher({
      "https://x.example/.well-known/security.txt": {
        status: 200,
        body: `Contact: mailto:sec@x.example\nExpires: ${iso(-10 * DAY)}\n`,
      },
    });
    let printed = "";
    const code = await run(["x.example"], fetcher, (text) => {
      printed += text;
    });
    assert.equal(code, 1);
    assert.match(printed, /BLOCK\s+security\.txt\s+expired/);
  });

  it("exits 0 when every file is simply absent (an empty domain)", async () => {
    const fetcher = tableFetcher({});
    let printed = "";
    const code = await run(["empty.example"], fetcher, (text) => {
      printed += text;
    });
    assert.equal(code, 0);
    for (const target of TARGETS) {
      assert.match(printed, new RegExp(`${escapeRegExp(target.label)}\\s+not found`), `${target.id} should say not found`);
    }
    assert.match(printed, /0 blocker\(s\)/);
  });

  it("exits 2 when the domain answers nothing at all", async () => {
    const fetcher: Fetcher = {
      async get() {
        throw new Error("fetch failed: getaddrinfo ENOTFOUND dead.example");
      },
    };
    const code = await run(["dead.example", "--quiet"], fetcher, () => {});
    assert.equal(code, 2);
  });

  it("refuses to audit a private address, and makes no request at all", async () => {
    let calls = 0;
    const fetcher: Fetcher = {
      async get() {
        calls += 1;
        return { status: 200, contentType: "text/plain", body: "", redirected: false };
      },
    };
    const code = await run(["localhost", "--quiet"], fetcher, () => {});
    assert.equal(code, 2);
    assert.equal(calls, 0, "no request should be made to a private address");
  });

  it("checks only the targets named by --only", async () => {
    const requested: string[] = [];
    const fetcher: Fetcher = {
      async get(url) {
        requested.push(url);
        return { status: 404, contentType: "text/plain", body: "", redirected: false };
      },
    };
    const code = await run(["x.example", "--only", "gpc.json,dnt-policy.txt", "--quiet"], fetcher, () => {});
    assert.equal(code, 0);
    assert.equal(requested.length, 2);
    assert.ok(requested.every((url) => url.includes("gpc.json") || url.includes("dnt-policy.txt")));
  });

  it("rejects an unknown --only name without making a request", async () => {
    let calls = 0;
    const fetcher: Fetcher = {
      async get() {
        calls += 1;
        return { status: 200, contentType: "text/plain", body: "", redirected: false };
      },
    };
    let printed = "";
    const code = await run(["x.example", "--only", "made-up.txt"], fetcher, (text) => {
      printed += text;
    });
    assert.equal(code, 2);
    assert.match(printed, /unknown target/);
    assert.equal(calls, 0);
  });

  it("rejects a non-numeric --timeout", async () => {
    const code = await run(["x.example", "--timeout", "soon"], tableFetcher({}), () => {});
    assert.equal(code, 2);
  });

  it("a switch before the domain does not swallow it", async () => {
    const path = join(work, "quiet-first.json");
    const code = await run(["--quiet", "x.example", "--json", path], tableFetcher({}), () => {});
    assert.equal(code, 0, "an empty invocation (target eaten by --quiet) would exit 2, not 0");
    const report = JSON.parse(readFileSync(path, "utf8"));
    assert.equal(report.domain, "x.example");
  });

  for (const flag of ["--help", "-h"]) {
    it(`answers \`${flag}\` with the usage text and exit 0`, async () => {
      let printed = "";
      const code = await run([flag], undefined, (text) => {
        printed += text;
      });
      assert.equal(code, 0, "asking for help is not a mistake");
      assert.match(printed, /well-known-audit - /);
    });
  }

  it("exits 2 when nothing at all was named", async () => {
    const code = await run([], undefined, () => {});
    assert.equal(code, 2, "an empty invocation is a usage error, not help");
  });

  it("writes a JSON report a script can read", async () => {
    const path = join(work, "report.json");
    const fetcher = tableFetcher({
      "https://x.example/.well-known/security.txt": {
        status: 200,
        body: `Contact: mailto:a@x.example\nExpires: ${iso(-DAY)}\n`,
      },
    });
    const code = await run(["x.example", "--quiet", "--json", path], fetcher, () => {});
    assert.equal(code, 1);
    const report = JSON.parse(readFileSync(path, "utf8"));
    assert.equal(report.summary.blocker, 1);
    assert.ok(report.targets.some((target: { id: string }) => target.id === "security.txt"));
  });

  it("--quiet writes the file but prints nothing", async () => {
    const path = join(work, "quiet.json");
    let printed = "";
    const code = await run(["x.example", "--quiet", "--json", path], tableFetcher({}), (text) => {
      printed += text;
    });
    assert.equal(code, 0);
    assert.equal(printed, "");
    assert.ok(readFileSync(path, "utf8").length > 0);
  });
});


describe("auditing a list of sites", () => {
  it("reads a domain list the way a person writes one", () => {
    const domains = parseDomainList(
      "example.com\n# a comment\n\nhttps://shop.example/collections\n  EXAMPLE.com  \nnot a host\n",
    );
    assert.deepEqual(domains, ["example.com", "shop.example"]);
  });

  it("counts an unreachable site apart from a site with nothing published", () => {
    const results: DomainResult[] = [
      { domain: "a", outcome: "checked", blockers: 1, warnings: 0, present: ["robots.txt"],
        securityTxt: { found: false, hasExpires: false, expired: false } },
      { domain: "b", outcome: "unreachable" },
      { domain: "c", outcome: "checked", blockers: 0, warnings: 1, present: ["security.txt", "robots.txt"],
        securityTxt: { found: true, hasExpires: true, expired: false } },
      { domain: "d", outcome: "checked", blockers: 1, warnings: 0, present: ["security.txt"],
        securityTxt: { found: true, hasExpires: true, expired: true, daysLeft: -12 } },
      { domain: "e", outcome: "checked", blockers: 1, warnings: 0, present: ["security.txt"],
        securityTxt: { found: true, hasExpires: false, expired: false } },
    ];

    const totals = summariseBatch(results);
    assert.equal(totals.total, 5);
    assert.equal(totals.checked, 4, "a site that never answered is not a site we checked");
    assert.equal(totals.unreachable, 1);
    assert.equal(totals.securityTxt.published, 3);
    assert.equal(totals.securityTxt.valid, 1);
    assert.equal(totals.securityTxt.expired, 1);
    assert.equal(totals.securityTxt.withoutExpires, 1);
    assert.equal(totals.filePresence["robots.txt"], 2);
  });

  it("writes CSV a spreadsheet can open", () => {
    const csv = toCsv([
      { domain: "a.example", outcome: "checked", blockers: 1, warnings: 2, present: ["security.txt", "robots.txt"],
        securityTxt: { found: true, hasExpires: true, expired: true, daysLeft: -12 } },
      { domain: "b.example", outcome: "unreachable" },
    ]);
    const rows = csv.trimEnd().split("\n");
    assert.equal(rows[0], "domain,outcome,blockers,warnings,security_txt,security_txt_expires,security_txt_expired,days_left,files_present");
    assert.equal(rows[1], "a.example,checked,1,2,yes,yes,yes,-12,security.txt robots.txt");
    assert.equal(rows[2], "b.example,unreachable,,,,,,,");
  });

  it("a site that answers nothing does not fail the whole survey", () => {
    const summary = summariseBatch([
      { domain: "a", outcome: "unreachable" },
      { domain: "b", outcome: "checked", blockers: 3, warnings: 0, present: [] },
    ]);
    const text = renderSummary(summary);
    assert.match(text, /answered\s+1/);
    assert.match(text, /never answered\s+1/);
  });
});


describe("picking up where a run stopped", () => {
  it("writes a row that matches the header it will be read back with", () => {
    const row = toCsvRow({
      domain: "a.example",
      outcome: "checked",
      blockers: 1,
      warnings: 0,
      present: ["security.txt"],
      securityTxt: { found: true, hasExpires: false, expired: false },
    });
    assert.equal(row.split(",").length, CSV_HEADER.split(",").length,
      "a row must have exactly as many cells as the header promises");
  });

  it("knows which domains a half-finished file already holds", () => {
    const csv =
      `${CSV_HEADER}\n` +
      "a.example,checked,0,0,yes,yes,no,,security.txt\n" +
      "B.EXAMPLE,unreachable,,,,,,,\n";
    const done = domainsIn(csv);
    assert.ok(done.has("a.example"));
    assert.ok(done.has("b.example"), "a domain is a domain whatever its case");
    assert.equal(done.size, 2);
    assert.ok(!done.has("domain"), "the header is not a domain");
  });

  it("treats an empty file as nothing done rather than everything done", () => {
    assert.equal(domainsIn("").size, 0);
    assert.equal(domainsIn(`${CSV_HEADER}\n`).size, 0);
  });
});


describe("a host that answers 200 to anything", () => {
  /** Answers every request with an HTML shell, the way a large SPA does. */
  const shell: Fetcher = {
    async get() {
      return { status: 200, contentType: "text/html; charset=utf-8", body: "<!doctype html><html><body>app</body></html>", redirected: false };
    },
  };

  it("does not count a bare 200 as a published file", async () => {
    const result = await auditDomain(shell, "spa.example", { pauseMs: 0 });
    assert.equal(result.outcome, "checked");
    assert.equal(result.answersAnything, true, "the control path answered 200, so nothing here is evidence");
    assert.deepEqual(result.present, [], "an HTML shell is not twelve published files");
    assert.equal(result.securityTxt?.found, false);
  });

  it("asks for a path that cannot exist, exactly once", async () => {
    const asked: string[] = [];
    const counting: Fetcher = {
      async get(url) {
        asked.push(url);
        return { status: 404, contentType: "text/plain", body: "", redirected: false };
      },
    };
    await auditDomain(counting, "plain.example", { pauseMs: 0 });
    const controls = asked.filter((url) => url.includes(CONTROL_PATH));
    assert.equal(controls.length, 1, "one control request per domain, not one per file");
  });

  it("leaves an ordinary site alone", async () => {
    const ordinary: Fetcher = {
      async get(url) {
        if (url.includes(CONTROL_PATH)) return { status: 404, contentType: "text/plain", body: "", redirected: false };
        if (url.endsWith("/robots.txt")) {
          return { status: 200, contentType: "text/plain", body: "User-agent: *\nDisallow:\n", redirected: false };
        }
        return { status: 404, contentType: "text/plain", body: "", redirected: false };
      },
    };
    const result = await auditDomain(ordinary, "plain.example", { pauseMs: 0 });
    assert.equal(result.answersAnything, undefined, "a 404 to the control path is what a normal site does");
    assert.ok(result.present?.includes("robots.txt"));
  });
});
