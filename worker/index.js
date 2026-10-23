import { isImmutableAssetPath } from "../lib/content-addressing.mjs";

const productionHost = "webappsec.metalagman.dev";
const verifierOrigin = "https://verify.webappsec.metalagman.dev";
const versionHost = /^[a-z0-9][a-z0-9-]*-webappsec\.[a-z0-9][a-z0-9-]*\.workers\.dev$/;

const fallbackContentSecurityPolicy = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

function validReleaseContentSecurityPolicy(value) {
  const match = /script-src 'self' '(sha384-[A-Za-z0-9+/]{64})'/.exec(value);
  if (!match) return false;
  return value === [
    "default-src 'none'",
    `script-src 'self' '${match[1]}'`,
    "style-src 'self'",
    "img-src 'self' data:",
    "connect-src 'self'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join("; ");
}

async function releaseContentSecurityPolicy(url, env) {
  const policyUrl = new URL("/security-policy.txt", url);
  const response = await env.ASSETS.fetch(new Request(policyUrl, { method: "GET" }));
  if (!response.ok) throw new Error("release security policy is unavailable");
  const declaredLength = Number(response.headers.get("Content-Length"));
  if (Number.isFinite(declaredLength) && declaredLength > 2048) throw new Error("release security policy is too large");
  const policy = await response.text();
  if (policy.length > 2048 || !validReleaseContentSecurityPolicy(policy)) {
    throw new Error("release security policy is invalid");
  }
  return policy;
}

function isVersionHost(hostname) {
  return versionHost.test(hostname);
}

function safeMetadata(value) {
  return typeof value === "string" && /^[A-Za-z0-9._:-]{1,128}$/.test(value) ? value : "unknown";
}

function addVary(headers, value) {
  const values = (headers.get("Vary") ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  if (!values.some((item) => item.toLowerCase() === value.toLowerCase())) values.push(value);
  headers.set("Vary", values.join(", "));
}

function addHeaders(request, response, {
  versionId,
  versionTag,
  noindex,
  secure,
  contentSecurityPolicy = fallbackContentSecurityPolicy,
}) {
  const headers = new Headers(response.headers);
  headers.delete("Access-Control-Allow-Credentials");
  headers.delete("Access-Control-Allow-Origin");
  headers.delete("Access-Control-Expose-Headers");
  headers.set("Content-Security-Policy", contentSecurityPolicy);
  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  headers.set("Permissions-Policy", "camera=(), geolocation=(), microphone=()");
  headers.set("Referrer-Policy", "no-referrer");
  if (secure) headers.set("Strict-Transport-Security", "max-age=31536000");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("X-Webappsec-Release", safeMetadata(versionTag));
  headers.set("X-Webappsec-Worker-Version", safeMetadata(versionId));
  addVary(headers, "Origin");
  if (
    (request.method === "GET" || request.method === "HEAD") &&
    request.headers.get("Origin") === verifierOrigin
  ) {
    headers.set("Access-Control-Allow-Origin", verifierOrigin);
    headers.set(
      "Access-Control-Expose-Headers",
      "X-Webappsec-Release, X-Webappsec-Worker-Version",
    );
  }
  if (noindex) headers.set("X-Robots-Tag", "noindex");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function cachePolicy(pathname, status) {
  if (status !== 200) return "no-store";
  if (isImmutableAssetPath(pathname)) return "public, max-age=31536000, immutable";
  return "no-cache";
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const versionRequest = isVersionHost(url.hostname);
    const metadata = env.CF_VERSION_METADATA ?? {};

    if (url.hostname !== productionHost && !versionRequest) {
      return addHeaders(request, new Response("Misdirected Request\n", { status: 421 }), {
        versionId: metadata.id,
        versionTag: metadata.tag,
        noindex: true,
        secure: url.protocol === "https:",
      });
    }

    if (url.protocol !== "https:") {
      url.protocol = "https:";
      return addHeaders(request, Response.redirect(url, 308), {
        versionId: metadata.id,
        versionTag: metadata.tag,
        noindex: versionRequest,
        secure: false,
      });
    }

    let contentSecurityPolicy;
    try {
      contentSecurityPolicy = await releaseContentSecurityPolicy(url, env);
    } catch {
      const response = addHeaders(request, new Response("Release policy unavailable\n", { status: 503 }), {
        versionId: metadata.id,
        versionTag: metadata.tag,
        noindex: versionRequest,
        secure: true,
      });
      response.headers.set("Cache-Control", "no-store");
      return response;
    }

    const assetRequest = url.pathname === "/"
      ? new Request(new URL("/index.html", url), request)
      : request;
    const assetResponse = await env.ASSETS.fetch(assetRequest);
    const response = addHeaders(request, assetResponse, {
      versionId: metadata.id,
      versionTag: metadata.tag,
      noindex: versionRequest,
      secure: true,
      contentSecurityPolicy,
    });
    response.headers.set("Cache-Control", cachePolicy(url.pathname, response.status));
    return response;
  },
};
