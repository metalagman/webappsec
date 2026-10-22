import { isImmutableAssetPath } from "../lib/content-addressing.mjs";

const verifierHost = "verify.webappsec.metalagman.dev";
const versionHost = /^[a-z0-9][a-z0-9-]*-webappsec-verifier\.[a-z0-9][a-z0-9-]*\.workers\.dev$/;
const contentSecurityPolicy = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self' https://webappsec.metalagman.dev",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

function safeMetadata(value) {
  return typeof value === "string" && /^[A-Za-z0-9._:-]{1,128}$/.test(value) ? value : "unknown";
}

function cachePolicy(pathname, status) {
  if (status !== 200) return "no-store";
  if (isImmutableAssetPath(pathname)) return "public, max-age=31536000, immutable";
  return "no-store";
}

function addHeaders(response, { versionId, noindex, secure, pathname }) {
  const headers = new Headers(response.headers);
  headers.set("Cache-Control", cachePolicy(pathname, response.status));
  headers.set("Content-Security-Policy", contentSecurityPolicy);
  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  headers.set("Cross-Origin-Resource-Policy", "same-origin");
  headers.set("Permissions-Policy", "camera=(), geolocation=(), microphone=()");
  headers.set("Referrer-Policy", "no-referrer");
  if (secure) headers.set("Strict-Transport-Security", "max-age=31536000");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("X-Webappsec-Verifier-Version", safeMetadata(versionId));
  if (noindex) headers.set("X-Robots-Tag", "noindex");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const preview = versionHost.test(url.hostname);
    const metadata = env.CF_VERSION_METADATA ?? {};
    const options = {
      versionId: metadata.id,
      noindex: preview,
      secure: url.protocol === "https:",
      pathname: url.pathname,
    };

    if (url.hostname !== verifierHost && !preview) {
      return addHeaders(new Response("Misdirected Request\n", { status: 421 }), {
        ...options,
        noindex: true,
      });
    }
    if (url.protocol !== "https:") {
      url.protocol = "https:";
      return addHeaders(Response.redirect(url, 308), { ...options, secure: false });
    }
    return addHeaders(await env.ASSETS.fetch(request), options);
  },
};
