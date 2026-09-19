/**
 * Turning what was fetched into findings a human can act on.
 *
 * Three levels, and the line between them is not "how unusual is this" but
 * "what does it cost the site":
 *
 *   blocker  the file is published but does not do its job - an expired
 *            security.txt is formally invalid per RFC 9116, an
 *            apple-app-site-association served as HTML breaks universal
 *            links completely. Same bucket as "answers with garbage".
 *   warning  either a file that essentially every public site should have
 *            (security.txt, robots.txt, change-password) is missing, or a
 *            present file has a soft defect that degrades but does not break
 *            it - a Contact address that is not a URI is still readable by a
 *            person, just not by tooling.
 *   note     a file that only applies to some sites (a mobile app, a mail
 *            server, an OIDC provider) is missing, or a present file has a
 *            cosmetic issue.
 *
 * Every evaluator below takes the raw fetch outcome(s) for one target and
 * returns a summary line plus zero or more findings. None of them fetch
 * anything, which is what makes them testable against a fixture body.
 */

import {
  countLlmsLinks,
  isPlainObject,
  looksLikeHtml,
  looksLikeUri,
  parseMtaSts,
  parseRobotsTxt,
  parseSecurityTxt,
  safeJsonParse,
} from "./parse.js";
import type { FetchOutcome } from "./probe.js";
import type { TargetDef, TargetId } from "./targets.js";

export type Level = "blocker" | "warning" | "note";

export interface Finding {
  id: string;
  level: Level;
  title: string;
  detail: string;
  /** What to do about it, when there is something more specific to say than the detail already does. */
  fix?: string;
}

export interface TargetResult {
  id: TargetId;
  label: string;
  urls: string[];
  summary: string;
  findings: Finding[];
}

function reachedOk(outcome: FetchOutcome): boolean {
  return outcome.reached && outcome.status >= 200 && outcome.status < 300;
}

function daysBetween(fromMs: number, toMs: number): number {
  return Math.round((toMs - fromMs) / 86_400_000);
}

function normalizeWhitespace(text: string): string {
  return text.trim().replace(/\s+/g, " ");
}

function describeJsonShape(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "an array";
  return `a ${typeof value}`;
}

function missingFinding(def: TargetDef, outcome?: FetchOutcome): Finding {
  const statusNote =
    outcome && outcome.reached && outcome.status !== 404
      ? `Server answered ${outcome.status} at ${outcome.url}. `
      : "";
  return {
    id: `${def.id}-missing`,
    level: def.neededByAll ? "warning" : "note",
    title: "not found",
    detail: `${statusNote}${def.purpose}.`,
  };
}

function fetchErrorFinding(def: TargetDef, outcome: FetchOutcome): Finding {
  const cls = outcome.errorClass ?? "network";
  const level: Level = cls === "network" ? "warning" : "blocker";
  const title =
    cls === "private"
      ? "redirected to a private address; refused"
      : cls === "too-large"
        ? "response exceeded the 5 MB cap"
        : cls === "redirect-loop"
          ? "too many redirects"
          : "could not be checked";
  return { id: `${def.id}-fetch-error`, level, title, detail: outcome.error ?? "unknown error" };
}

// --- security.txt (RFC 9116) ------------------------------------------------

function evaluateSecurityTxt(
  def: TargetDef,
  outcomes: FetchOutcome[],
  now: number,
): { summary: string; findings: Finding[] } {
  const wk = outcomes[0]!;
  const root = outcomes[1]!;
  const wkOk = reachedOk(wk);
  const rootOk = reachedOk(root);

  if (!wkOk && !rootOk) {
    const errored = [wk, root].find((outcome) => !outcome.reached);
    if (errored) return { summary: "error", findings: [fetchErrorFinding(def, errored)] };
    return { summary: "not found", findings: [missingFinding(def, wk)] };
  }

  const findings: Finding[] = [];
  const primary = wkOk ? wk : root;

  if (!wkOk && rootOk) {
    if (!wk.reached) {
      findings.push({
        id: "security-txt-wellknown-error",
        level: "note",
        title: "could not confirm /.well-known/security.txt",
        detail: wk.error ?? "unknown error",
      });
    } else {
      findings.push({
        id: "security-txt-legacy-location",
        level: "warning",
        title: "published only at /security.txt, not /.well-known/security.txt",
        detail: "RFC 9116 treats /.well-known/security.txt as canonical; /security.txt is for older clients only.",
        fix: "Publish the same file at /.well-known/security.txt (or redirect it there).",
      });
    }
  }
  if (wkOk && rootOk && normalizeWhitespace(wk.body) !== normalizeWhitespace(root.body)) {
    findings.push({
      id: "security-txt-copies-differ",
      level: "note",
      title: "the two published copies differ",
      detail: "/.well-known/security.txt and /security.txt do not have the same content.",
    });
  }

  const fields = parseSecurityTxt(primary.body);
  if (fields.fieldLineCount === 0) {
    findings.push({
      id: "security-txt-unparseable",
      level: "blocker",
      title: "not a valid security.txt",
      detail: `${primary.url} returned no recognisable "Field: value" lines.`,
    });
    return { summary: "not a valid security.txt", findings };
  }

  let expirySummary = "";
  if (fields.expiresValues.length === 0) {
    findings.push({
      id: "security-txt-no-expires",
      level: "blocker",
      title: "no Expires field",
      detail: "RFC 9116 requires exactly one Expires field; without it the file has no defined shelf life.",
      fix: "Add `Expires: <RFC 3339 date-time>`, at most a year out.",
    });
  } else if (fields.expiresValues.length > 1) {
    findings.push({
      id: "security-txt-multiple-expires",
      level: "blocker",
      title: "more than one Expires field",
      detail: `RFC 9116 allows exactly one; found ${fields.expiresValues.length}.`,
    });
  } else {
    const raw = fields.expiresValues[0]!;
    const parsed = Date.parse(raw);
    if (Number.isNaN(parsed)) {
      findings.push({
        id: "security-txt-expires-unparseable",
        level: "blocker",
        title: `Expires value is not a valid date: "${raw}"`,
        detail: "RFC 9116 requires an RFC 3339 date-time, for example 2026-12-31T18:37:07z.",
      });
    } else {
      const days = daysBetween(now, parsed);
      if (days < 0) {
        findings.push({
          id: "security-txt-expired",
          level: "blocker",
          title: `expired ${Math.abs(days)} day(s) ago`,
          detail: `Expires: ${raw}. RFC 9116 treats an expired file as formally invalid, the same as a missing one.`,
          fix: "Publish a fresh Expires date - this is the single most common security.txt mistake.",
        });
        expirySummary = `expired ${Math.abs(days)}d ago`;
      } else {
        if (days > 366) {
          findings.push({
            id: "security-txt-expires-far",
            level: "warning",
            title: `Expires is ${days} days out, more than a year`,
            detail: "RFC 9116 recommends refreshing the file at least yearly so it does not go stale unnoticed.",
          });
        }
        expirySummary = `expires in ${days}d`;
      }
    }
  }

  if (fields.contacts.length === 0) {
    findings.push({
      id: "security-txt-no-contact",
      level: "blocker",
      title: "no Contact field",
      detail: "RFC 9116 requires at least one Contact field.",
      fix: "Add `Contact: mailto:security@yourdomain` (or a https: / tel: URI).",
    });
  } else {
    const malformed = fields.contacts.filter((value) => !looksLikeUri(value));
    if (malformed.length > 0) {
      findings.push({
        id: "security-txt-contact-malformed",
        level: "warning",
        title: `Contact value is not a URI: "${malformed[0]}"`,
        detail: "RFC 9116 requires Contact values to be URIs so tooling can act on them, not just a human.",
        fix: "Prefix it, e.g. `mailto:security@yourdomain` instead of a bare address.",
      });
    }
  }

  if (fields.preferredLanguagesValues.length > 1) {
    findings.push({
      id: "security-txt-multiple-preferred-languages",
      level: "blocker",
      title: "more than one Preferred-Languages field",
      detail: `RFC 9116 allows at most one; found ${fields.preferredLanguagesValues.length}.`,
    });
  }

  const contentType = primary.contentType.toLowerCase();
  if (contentType && !contentType.includes("text/plain")) {
    findings.push({
      id: "security-txt-content-type",
      level: "note",
      title: `served as "${primary.contentType}", not text/plain`,
      detail: "RFC 9116 specifies a media type of text/plain; charset=utf-8.",
    });
  }

  const hasBlocker = findings.some((finding) => finding.level === "blocker");
  const summary = hasBlocker ? expirySummary || "invalid" : `valid${expirySummary ? `, ${expirySummary}` : ""}`;
  return { summary, findings };
}

// --- robots.txt --------------------------------------------------------------

function evaluateRobotsTxt(def: TargetDef, outcomes: FetchOutcome[]): { summary: string; findings: Finding[] } {
  const outcome = outcomes[0]!;
  if (!outcome.reached) return { summary: "error", findings: [fetchErrorFinding(def, outcome)] };
  if (!reachedOk(outcome)) return { summary: "not found", findings: [missingFinding(def, outcome)] };

  if (looksLikeHtml(outcome.body, outcome.contentType)) {
    return {
      summary: "served as HTML",
      findings: [
        {
          id: "robots-txt-html",
          level: "blocker",
          title: "looks like an HTML page, not robots.txt",
          detail: `Content-Type "${outcome.contentType}" or the body itself looks like HTML - a common static-host fallback mistake.`,
          fix: "Serve a plain-text robots.txt at this exact path, not a catch-all page.",
        },
      ],
    };
  }

  const parsed = parseRobotsTxt(outcome.body);
  const findings: Finding[] = [];
  if (parsed.sitemaps.length === 0) {
    findings.push({
      id: "robots-txt-no-sitemap",
      level: "note",
      title: "no Sitemap: line",
      detail: "Pointing crawlers at a sitemap is optional but makes indexing more complete.",
    });
  }
  if (parsed.disallowsEverything) {
    findings.push({
      id: "robots-txt-disallows-all",
      level: "warning",
      title: "blocks all crawlers",
      detail:
        "User-agent: * with Disallow: / and no exception hides the entire site from anything that honours " +
        "robots.txt, AI crawlers included.",
      fix: "Confirm that is intentional; otherwise narrow the Disallow rule.",
    });
  }

  const summary = `${parsed.sitemaps.length} sitemap(s)${parsed.disallowsEverything ? ", blocks all" : ""}`;
  return { summary, findings };
}

// --- llms.txt ------------------------------------------------------------

function evaluateLlmsTxt(def: TargetDef, outcomes: FetchOutcome[]): { summary: string; findings: Finding[] } {
  const outcome = outcomes[0]!;
  if (!outcome.reached) return { summary: "error", findings: [fetchErrorFinding(def, outcome)] };
  if (!reachedOk(outcome)) return { summary: "not found", findings: [missingFinding(def, outcome)] };

  if (looksLikeHtml(outcome.body, outcome.contentType)) {
    return {
      summary: "served as HTML",
      findings: [
        {
          id: "llms-txt-html",
          level: "warning",
          title: "looks like an HTML page, not llms.txt",
          detail: `Content-Type "${outcome.contentType}" or the body itself looks like HTML.`,
        },
      ],
    };
  }

  const count = countLlmsLinks(outcome.body);
  const findings: Finding[] = [];
  if (count === 0) {
    findings.push({
      id: "llms-txt-no-links",
      level: "note",
      title: "no links found",
      detail: "llms.txt is usually a list of markdown links to the pages worth an LLM reading.",
    });
  }
  return { summary: `${count} link(s)`, findings };
}

// --- ai.txt, dnt-policy.txt, ucp: presence only ------------------------------

function evaluatePresenceOnly(
  def: TargetDef,
  outcomes: FetchOutcome[],
  options: { sniffHtml: boolean },
): { summary: string; findings: Finding[] } {
  const outcome = outcomes[0]!;
  if (!outcome.reached) return { summary: "error", findings: [fetchErrorFinding(def, outcome)] };
  if (!reachedOk(outcome)) return { summary: "not found", findings: [missingFinding(def, outcome)] };

  const findings: Finding[] = [];
  if (options.sniffHtml && looksLikeHtml(outcome.body, outcome.contentType)) {
    findings.push({
      id: `${def.id}-html`,
      level: "warning",
      title: "looks like an HTML page",
      detail: `Content-Type "${outcome.contentType}" or the body itself looks like HTML.`,
    });
  }
  return { summary: options.sniffHtml ? "present" : "present (not analysed - see ucp-audit)", findings };
}

// --- openid-configuration ------------------------------------------------

function evaluateOpenIdConfiguration(
  def: TargetDef,
  outcomes: FetchOutcome[],
): { summary: string; findings: Finding[] } {
  const outcome = outcomes[0]!;
  if (!outcome.reached) return { summary: "error", findings: [fetchErrorFinding(def, outcome)] };
  if (!reachedOk(outcome)) return { summary: "not found", findings: [missingFinding(def, outcome)] };

  const json = safeJsonParse(outcome.body);
  if (!json.ok) {
    return {
      summary: "invalid JSON",
      findings: [{ id: "openid-configuration-invalid-json", level: "blocker", title: "not valid JSON", detail: json.error }],
    };
  }
  if (!isPlainObject(json.value)) {
    return {
      summary: "not a JSON object",
      findings: [
        {
          id: "openid-configuration-not-object",
          level: "blocker",
          title: "top-level value is not a JSON object",
          detail: `Got ${describeJsonShape(json.value)}.`,
        },
      ],
    };
  }

  const issuer = json.value.issuer;
  if (typeof issuer !== "string" || issuer.length === 0) {
    return {
      summary: "missing issuer",
      findings: [
        {
          id: "openid-configuration-no-issuer",
          level: "blocker",
          title: "no issuer field",
          detail: "OpenID Connect Discovery requires a string `issuer`.",
          fix: "Add the provider's issuer URL as `issuer`.",
        },
      ],
    };
  }

  const findings: Finding[] = [];
  if (!issuer.startsWith("https://")) {
    findings.push({
      id: "openid-configuration-issuer-not-https",
      level: "warning",
      title: `issuer is not https: "${issuer}"`,
      detail: "OpenID Connect requires the issuer to be an https URL.",
    });
  }
  return { summary: `issuer ${issuer}`, findings };
}

// --- apple-app-site-association ------------------------------------------

function evaluateAppleAppSiteAssociation(
  def: TargetDef,
  outcomes: FetchOutcome[],
): { summary: string; findings: Finding[] } {
  const outcome = outcomes[0]!;
  if (!outcome.reached) return { summary: "error", findings: [fetchErrorFinding(def, outcome)] };
  if (!reachedOk(outcome)) return { summary: "not found", findings: [missingFinding(def, outcome)] };

  if (looksLikeHtml(outcome.body, outcome.contentType)) {
    return {
      summary: "served as HTML",
      findings: [
        {
          id: "apple-app-site-association-html",
          level: "blocker",
          title: "served as HTML, not JSON",
          detail:
            `Content-Type "${outcome.contentType}" or the body itself looks like HTML - the classic ` +
            "static-host SPA-fallback mistake: the route answers 200 with the app shell instead of 404.",
          fix: "Make sure this exact path serves the real file, with no catch-all route intercepting it.",
        },
      ],
    };
  }

  const json = safeJsonParse(outcome.body);
  if (!json.ok) {
    return {
      summary: "invalid JSON",
      findings: [{ id: "apple-app-site-association-invalid-json", level: "blocker", title: "not valid JSON", detail: json.error }],
    };
  }
  if (!isPlainObject(json.value)) {
    return {
      summary: "not a JSON object",
      findings: [
        {
          id: "apple-app-site-association-not-object",
          level: "blocker",
          title: "top-level value is not a JSON object",
          detail: `Got ${describeJsonShape(json.value)}.`,
        },
      ],
    };
  }

  const value = json.value;
  const KNOWN_KEYS = ["applinks", "webcredentials", "appclips"];
  const foundKeys = KNOWN_KEYS.filter((key) => key in value);
  const findings: Finding[] = [];
  if (foundKeys.length === 0) {
    findings.push({
      id: "apple-app-site-association-no-known-keys",
      level: "warning",
      title: "no applinks, webcredentials or appclips key",
      detail: "Apple reads one of these three top-level keys; without any of them the file does nothing.",
    });
  }
  const contentType = outcome.contentType.toLowerCase();
  if (contentType && !contentType.includes("json") && !contentType.includes("octet-stream")) {
    findings.push({
      id: "apple-app-site-association-content-type",
      level: "note",
      title: `served as "${outcome.contentType}"`,
      detail: "Apple tolerates most content types here as long as the body is valid JSON, but application/json is the safe default.",
    });
  }
  return { summary: foundKeys.length > 0 ? `keys: ${foundKeys.join(", ")}` : "no recognised keys", findings };
}

// --- assetlinks.json -------------------------------------------------------

function evaluateAssetlinks(def: TargetDef, outcomes: FetchOutcome[]): { summary: string; findings: Finding[] } {
  const outcome = outcomes[0]!;
  if (!outcome.reached) return { summary: "error", findings: [fetchErrorFinding(def, outcome)] };
  if (!reachedOk(outcome)) return { summary: "not found", findings: [missingFinding(def, outcome)] };

  if (looksLikeHtml(outcome.body, outcome.contentType)) {
    return {
      summary: "served as HTML",
      findings: [
        {
          id: "assetlinks-html",
          level: "blocker",
          title: "served as HTML, not JSON",
          detail: `Content-Type "${outcome.contentType}" or the body itself looks like HTML.`,
        },
      ],
    };
  }

  const json = safeJsonParse(outcome.body);
  if (!json.ok) {
    return {
      summary: "invalid JSON",
      findings: [{ id: "assetlinks-invalid-json", level: "blocker", title: "not valid JSON", detail: json.error }],
    };
  }
  if (!Array.isArray(json.value)) {
    return {
      summary: "not a JSON array",
      findings: [
        {
          id: "assetlinks-not-array",
          level: "blocker",
          title: "top-level value is not a JSON array",
          detail: `Digital Asset Links requires a top-level array of statements; got ${describeJsonShape(json.value)}.`,
        },
      ],
    };
  }

  const findings: Finding[] = [];
  if (json.value.length === 0) {
    findings.push({
      id: "assetlinks-empty",
      level: "note",
      title: "empty array",
      detail: "No statements are declared, so no app is linked yet.",
    });
  } else {
    const incomplete = json.value.filter(
      (entry: unknown) => !isPlainObject(entry) || !("relation" in entry) || !("target" in entry),
    ).length;
    if (incomplete > 0) {
      findings.push({
        id: "assetlinks-incomplete-entries",
        level: "warning",
        title: `${incomplete} of ${json.value.length} entries missing relation/target`,
        detail: "Each statement needs a `relation` array and a `target` object to mean anything.",
      });
    }
  }
  return { summary: `${json.value.length} statement(s)`, findings };
}

// --- change-password -------------------------------------------------------

function evaluateChangePassword(def: TargetDef, outcomes: FetchOutcome[]): { summary: string; findings: Finding[] } {
  const outcome = outcomes[0]!;
  if (!outcome.reached) return { summary: "error", findings: [fetchErrorFinding(def, outcome)] };

  if (outcome.status === 404) return { summary: "not found", findings: [missingFinding(def, outcome)] };

  if (outcome.status >= 200 && outcome.status < 300) {
    return { summary: outcome.redirected ? "redirects, then 200" : "200", findings: [] };
  }

  // `httpFetcher` already follows valid redirects; seeing a 3xx here means it
  // had a redirect status but no Location header to follow.
  if (outcome.status >= 300 && outcome.status < 400) {
    return {
      summary: `${outcome.status}, no Location`,
      findings: [
        {
          id: "change-password-bad-redirect",
          level: "blocker",
          title: `answered ${outcome.status} with no Location header`,
          detail: "The well-known change-password URL expects a redirect a client can follow, or 200.",
          fix: "Send a Location header with the redirect, or answer 200 directly.",
        },
      ],
    };
  }

  return {
    summary: `answered ${outcome.status}`,
    findings: [
      {
        id: "change-password-bad-status",
        level: "blocker",
        title: `answered ${outcome.status}, neither a redirect nor 200`,
        detail: `${outcome.url} answered ${outcome.status}.`,
        fix: "Serve a redirect to the password-change page, or 200 with the form itself.",
      },
    ],
  };
}

// --- mta-sts.txt (RFC 8461) ------------------------------------------------

function evaluateMtaSts(def: TargetDef, outcomes: FetchOutcome[]): { summary: string; findings: Finding[] } {
  const outcome = outcomes[0]!;
  if (!outcome.reached) return { summary: "error", findings: [fetchErrorFinding(def, outcome)] };
  if (!reachedOk(outcome)) return { summary: "not found", findings: [missingFinding(def, outcome)] };

  if (looksLikeHtml(outcome.body, outcome.contentType)) {
    return {
      summary: "served as HTML",
      findings: [
        {
          id: "mta-sts-html",
          level: "blocker",
          title: "served as HTML, not the policy file",
          detail: `Content-Type "${outcome.contentType}" or the body itself looks like HTML.`,
        },
      ],
    };
  }

  const fields = parseMtaSts(outcome.body);
  const missing: string[] = [];
  const findings: Finding[] = [];

  if (!fields.version) missing.push("version");
  else if (fields.version !== "STSv1") {
    findings.push({
      id: "mta-sts-bad-version",
      level: "blocker",
      title: `unexpected version "${fields.version}"`,
      detail: 'RFC 8461 defines only "STSv1".',
    });
  }

  if (!fields.mode) missing.push("mode");
  else if (!["enforce", "testing", "none"].includes(fields.mode)) {
    findings.push({
      id: "mta-sts-bad-mode",
      level: "blocker",
      title: `invalid mode "${fields.mode}"`,
      detail: "RFC 8461 defines mode as enforce, testing or none.",
    });
  }

  if (!fields.maxAge) missing.push("max_age");
  else if (!/^\d+$/.test(fields.maxAge) || Number(fields.maxAge) <= 0) {
    findings.push({
      id: "mta-sts-bad-max-age",
      level: "blocker",
      title: `max_age is not a positive integer: "${fields.maxAge}"`,
      detail: "max_age is a number of seconds.",
    });
  }

  if (fields.mx.length === 0) {
    findings.push({
      id: "mta-sts-no-mx",
      level: "warning",
      title: "no mx hosts listed",
      detail: "Without at least one mx pattern, no mail server is covered by this policy.",
    });
  }

  if (missing.length > 0) {
    findings.unshift({
      id: "mta-sts-missing-fields",
      level: "blocker",
      title: `missing required field(s): ${missing.join(", ")}`,
      detail: "RFC 8461 requires version, mode, mx and max_age.",
    });
  }

  const summary = `${fields.mode ?? "?"}, ${fields.mx.length} mx, max_age ${fields.maxAge ?? "?"}`;
  return { summary, findings };
}

// --- gpc.json ----------------------------------------------------------------

function evaluateGpc(def: TargetDef, outcomes: FetchOutcome[]): { summary: string; findings: Finding[] } {
  const outcome = outcomes[0]!;
  if (!outcome.reached) return { summary: "error", findings: [fetchErrorFinding(def, outcome)] };
  if (!reachedOk(outcome)) return { summary: "not found", findings: [missingFinding(def, outcome)] };

  const json = safeJsonParse(outcome.body);
  if (!json.ok) {
    return { summary: "invalid JSON", findings: [{ id: "gpc-invalid-json", level: "blocker", title: "not valid JSON", detail: json.error }] };
  }
  const gpc = isPlainObject(json.value) ? json.value.gpc : undefined;
  if (typeof gpc !== "boolean") {
    return {
      summary: "malformed",
      findings: [
        {
          id: "gpc-bad-shape",
          level: "blocker",
          title: "no boolean gpc field",
          detail: 'The Global Privacy Control spec expects `{"gpc": true}` (or false).',
        },
      ],
    };
  }
  return { summary: `gpc: ${gpc}`, findings: [] };
}

// --- dispatch ----------------------------------------------------------------

function evaluateByKind(
  def: TargetDef,
  outcomes: FetchOutcome[],
  now: number,
): { summary: string; findings: Finding[] } {
  switch (def.id) {
    case "security.txt":
      return evaluateSecurityTxt(def, outcomes, now);
    case "robots.txt":
      return evaluateRobotsTxt(def, outcomes);
    case "llms.txt":
      return evaluateLlmsTxt(def, outcomes);
    case "ai.txt":
      return evaluatePresenceOnly(def, outcomes, { sniffHtml: true });
    case "dnt-policy.txt":
      return evaluatePresenceOnly(def, outcomes, { sniffHtml: true });
    case "ucp":
      return evaluatePresenceOnly(def, outcomes, { sniffHtml: false });
    case "openid-configuration":
      return evaluateOpenIdConfiguration(def, outcomes);
    case "apple-app-site-association":
      return evaluateAppleAppSiteAssociation(def, outcomes);
    case "assetlinks.json":
      return evaluateAssetlinks(def, outcomes);
    case "change-password":
      return evaluateChangePassword(def, outcomes);
    case "mta-sts.txt":
      return evaluateMtaSts(def, outcomes);
    case "gpc.json":
      return evaluateGpc(def, outcomes);
    default: {
      const exhaustive: never = def.id;
      throw new Error(`unhandled target: ${String(exhaustive)}`);
    }
  }
}

export function evaluateTarget(def: TargetDef, outcomes: FetchOutcome[], now: number = Date.now()): TargetResult {
  const { summary, findings } = evaluateByKind(def, outcomes, now);
  return { id: def.id, label: def.label, urls: outcomes.map((outcome) => outcome.url), summary, findings };
}

export function allFindings(results: TargetResult[]): Finding[] {
  return results.flatMap((result) => result.findings);
}

export function countByLevel(findings: Finding[]): Record<Level, number> {
  return {
    blocker: findings.filter((finding) => finding.level === "blocker").length,
    warning: findings.filter((finding) => finding.level === "warning").length,
    note: findings.filter((finding) => finding.level === "note").length,
  };
}
