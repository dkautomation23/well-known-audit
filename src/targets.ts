/**
 * The files this tool looks for, and where.
 *
 * Two of the twelve - `robots.txt` and `llms.txt` - live at the domain root
 * by convention that predates `/.well-known/` (RFC 8615, 2019). `security.txt`
 * lives in both places on purpose: RFC 9116 calls `/.well-known/security.txt`
 * canonical but still permits the root copy for older clients, so both are
 * fetched and compared.
 *
 * `neededByAll` decides nothing about whether a file is *valid* - only how
 * loudly its absence is reported. A missing `security.txt`, `robots.txt` or
 * `change-password` is a `warning`: these three apply to essentially any
 * public site. Everything else - mobile app links, an OpenID provider, mail
 * transport security - only applies to a site that does that particular
 * thing, so its absence is a `note`, not a `warning`.
 */

export type TargetId =
  | "security.txt"
  | "robots.txt"
  | "llms.txt"
  | "ai.txt"
  | "ucp"
  | "openid-configuration"
  | "apple-app-site-association"
  | "assetlinks.json"
  | "change-password"
  | "mta-sts.txt"
  | "gpc.json"
  | "dnt-policy.txt";

export interface TargetDef {
  id: TargetId;
  label: string;
  /** What this file is for, shown next to "not found" so the note is self-explanatory. */
  purpose: string;
  neededByAll: boolean;
  /** Paths tried, relative to the origin. security.txt is the only one with two. */
  paths: string[];
}

export const TARGETS: readonly TargetDef[] = [
  {
    id: "security.txt",
    label: "security.txt",
    purpose: "how to report a vulnerability (RFC 9116)",
    neededByAll: true,
    paths: ["/.well-known/security.txt", "/security.txt"],
  },
  {
    id: "robots.txt",
    label: "robots.txt",
    purpose: "crawler rules and sitemap location",
    neededByAll: true,
    paths: ["/robots.txt"],
  },
  {
    id: "llms.txt",
    label: "llms.txt",
    purpose: "a map of the site for LLMs, in place of crawling it",
    neededByAll: false,
    paths: ["/llms.txt"],
  },
  {
    id: "ai.txt",
    label: "ai.txt",
    purpose: "an emerging robots.txt-style convention aimed at AI crawlers specifically",
    neededByAll: false,
    paths: ["/.well-known/ai.txt"],
  },
  {
    id: "ucp",
    label: "ucp",
    purpose: "Universal Commerce Protocol profile - only relevant to a shop",
    neededByAll: false,
    paths: ["/.well-known/ucp"],
  },
  {
    id: "openid-configuration",
    label: "openid-configuration",
    purpose: "OIDC discovery document - only relevant to an identity provider",
    neededByAll: false,
    paths: ["/.well-known/openid-configuration"],
  },
  {
    id: "apple-app-site-association",
    label: "apple-app-site-association",
    purpose: "iOS universal links - only relevant to a site with an iOS app",
    neededByAll: false,
    paths: ["/.well-known/apple-app-site-association"],
  },
  {
    id: "assetlinks.json",
    label: "assetlinks.json",
    purpose: "Android app links (Digital Asset Links) - only relevant to a site with an Android app",
    neededByAll: false,
    paths: ["/.well-known/assetlinks.json"],
  },
  {
    id: "change-password",
    label: "change-password",
    purpose: "lets password managers jump straight to the change-password page",
    neededByAll: true,
    paths: ["/.well-known/change-password"],
  },
  {
    id: "mta-sts.txt",
    label: "mta-sts.txt",
    purpose: "mail transport security policy - only relevant if this domain receives mail",
    neededByAll: false,
    paths: ["/.well-known/mta-sts.txt"],
  },
  {
    id: "gpc.json",
    label: "gpc.json",
    purpose: "confirms Global Privacy Control is honoured",
    neededByAll: false,
    paths: ["/.well-known/gpc.json"],
  },
  {
    id: "dnt-policy.txt",
    label: "dnt-policy.txt",
    purpose: "the old Do Not Track compliance policy, rarely implemented now",
    neededByAll: false,
    paths: ["/.well-known/dnt-policy.txt"],
  },
];

export function findTarget(id: string): TargetDef | undefined {
  return TARGETS.find((target) => target.id === id);
}

/** Every path this run will request, across every selected target. */
export function urlsFor(origin: string, targets: readonly TargetDef[]): { target: TargetDef; url: string }[] {
  const found: { target: TargetDef; url: string }[] = [];
  for (const target of targets) {
    for (const path of target.paths) found.push({ target, url: `${origin}${path}` });
  }
  return found;
}
