/**
 * The pairing deep-link surface: the /pair landing page behind the
 * dashboard QR, and the apple-app-site-association document that makes
 * it a universal link.  Static routes only — the pairing payload rides
 * in the URL fragment, which never reaches the worker.
 */

import { exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

describe("pairing routes", () => {
  it("serves the landing page on GET /pair, read-only", async () => {
    const res = await exports.default.fetch("https://relay.test/pair");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
    const body = await res.text();
    expect(body).toContain("Pair with Cronstable");
    // The custom-scheme fallback hands the untouched fragment to the app.
    expect(body).toContain("cronstable://pair#");

    const post = await exports.default.fetch("https://relay.test/pair", {
      method: "POST",
    });
    expect(post.status).toBe(405);
    expect(post.headers.get("allow")).toBe("GET, HEAD");
  });

  it("serves the app-association file Apple's CDN fetches", async () => {
    const res = await exports.default.fetch(
      "https://relay.test/.well-known/apple-app-site-association",
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/json");
    const doc = (await res.json()) as {
      applinks: {
        details: { appIDs: string[]; components: { "/": string }[] }[];
      };
    };
    const detail = doc.applinks.details[0]!;
    expect(detail.appIDs).toEqual(["6392RHBP25.com.cronstable.app"]);
    expect(detail.components[0]!["/"]).toBe("/pair");

    const post = await exports.default.fetch(
      "https://relay.test/.well-known/apple-app-site-association",
      { method: "POST" },
    );
    expect(post.status).toBe(405);
  });
});
