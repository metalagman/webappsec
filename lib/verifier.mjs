import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { parse } from "parse5";

import { validateManifest } from "./artifact.mjs";
import { canonicalJson } from "./canonical-json.mjs";
import { isImmutableAssetPath } from "./content-addressing.mjs";

const maxBodySize = 25 * 1024 * 1024;

function hash(algorithm, bytes, encoding = "hex") {
  return createHash(algorithm).update(bytes).digest(encoding);
}

async function responseBytes(response, limit) {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > limit) throw new Error("response exceeds size limit");
  const chunks = [];
  let size = 0;
  try {
    for await (const chunk of response.body ?? []) {
      size += chunk.length;
      if (size > limit) throw new ResponseLimitError("response exceeds size limit");
      chunks.push(chunk);
    }
  } catch (error) {
    if (error instanceof ResponseLimitError) throw error;
    throw new UnavailableError(error?.name === "TimeoutError" || /timeout|aborted/i.test(error?.message)
      ? "response body timeout"
      : `response body unavailable: ${error?.message ?? error}`);
  }
  return Buffer.concat(chunks);
}

async function fetchSameOrigin(url, origin, { timeoutMs, fetchImplementation }) {
  let current = new URL(url, origin);
  for (let redirects = 0; redirects <= 3; redirects += 1) {
    if (current.origin !== origin) throw new Error(`off-origin URL rejected: ${current.href}`);
    let response;
    try {
      response = await fetchImplementation(current, {
        redirect: "manual",
        headers: { "Accept-Encoding": "identity" },
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      throw new UnavailableError(error?.name === "TimeoutError" || /timeout|aborted/i.test(error?.message)
        ? "request timeout"
        : `network unavailable: ${error?.message ?? error}`);
    }
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");
      if (!location) throw new Error(`redirect without Location: ${current.pathname}`);
      if (redirects === 3) throw new Error("redirect limit exceeded");
      current = new URL(location, current);
      continue;
    }
    if (response.status >= 500) throw new UnavailableError(`service returned HTTP ${response.status}: ${current.pathname}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}: ${current.pathname}`);
    return response;
  }
  throw new Error("redirect limit exceeded");
}

class UnavailableError extends Error {}
class ResponseLimitError extends Error {}

function localResourceReferences(html, documentUrl) {
  const references = [];
  const visit = (node) => {
    if (node.tagName === "base" && (node.attrs ?? []).some((attribute) => attribute.name === "href")) {
      throw new Error("base href is forbidden by verifier policy");
    }
    if (node.tagName === "script" || node.tagName === "link") {
      const attributes = new Map((node.attrs ?? []).map((attribute) => [attribute.name, attribute.value]));
      const stylesheet = node.tagName === "link" && (attributes.get("rel") ?? "").split(/\s+/).some((token) => token.toLowerCase() === "stylesheet");
      if (node.tagName === "script" || stylesheet) {
        const rawUrl = attributes.get(node.tagName === "script" ? "src" : "href");
        if (rawUrl) references.push({
          kind: node.tagName === "script" ? "script" : "stylesheet",
          url: new URL(rawUrl, documentUrl),
          integrity: attributes.get("integrity"),
        });
      }
    }
    for (const child of node.childNodes ?? []) visit(child);
  };
  visit(parse(html));
  return references;
}

function finalReport(manifestDigest, layers, target) {
  const unavailable = layers.some((layer) => layer.state === "unavailable");
  const ok = layers.every((layer) => layer.state === "pass");
  return {
    ok,
    result: ok ? "verified" : unavailable ? "service-unavailable" : "verification-failed",
    exitCode: ok ? 0 : unavailable ? 3 : 1,
    manifestDigest,
    layers,
    ...(target ? { target } : {}),
  };
}

function result(name, state, detail) {
  return { name, state, detail };
}

export async function verifyProduction({ manifestPath, origin, expectedHeaders, timeoutMs = 5000, fetchImplementation = fetch }) {
  const layers = [];
  let manifest;
  let manifestDigest;
  try {
    const bytes = await readFile(manifestPath);
    manifest = JSON.parse(bytes);
    if (!bytes.equals(Buffer.from(canonicalJson(manifest)))) throw new Error("manifest is not canonical JSON");
    validateManifest(manifest);
    manifestDigest = hash("sha256", bytes);
    layers.push(result("manifest", "pass", `${manifest.files.length} declared files`));
  } catch (error) {
    return finalReport(null, [result("manifest", "fail", error.message), result("production-bytes", "skipped", "manifest failed"), result("sri", "skipped", "manifest failed")]);
  }

  const effectiveOrigin = new URL(origin ?? manifest.origin).origin;
  const target = expectedHeaders ? { origin: effectiveOrigin, expectedHeaders: { ...expectedHeaders } } : undefined;
  const bodies = new Map();
  const headers = new Map();
  try {
    for (const entry of manifest.files) {
      const response = await fetchSameOrigin(entry.urlPath, effectiveOrigin, { timeoutMs, fetchImplementation });
      const bytes = await responseBytes(response, Math.min(maxBodySize, entry.size + 1));
      if (bytes.length !== entry.size) throw new Error(`size mismatch: ${entry.urlPath}`);
      if (hash("sha256", bytes) !== entry.sha256) throw new Error(`SHA-256 mismatch: ${entry.urlPath}`);
      bodies.set(entry.urlPath, bytes);
      headers.set(entry.urlPath, response.headers);
    }
    layers.push(result("production-bytes", "pass", `${bodies.size} exact responses`));
  } catch (error) {
    layers.push(result("production-bytes", error instanceof UnavailableError ? "unavailable" : "fail", error.message));
    if (expectedHeaders) layers.push(result("response-headers", "skipped", "production bytes failed"));
    layers.push(result("sri", "skipped", "production bytes failed"));
    return finalReport(manifestDigest, layers, target);
  }

  if (expectedHeaders) {
    try {
      const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
      const required = [
        ["Content-Security-Policy", (value) => value === contentSecurityPolicy],
        ["Cross-Origin-Opener-Policy", (value) => value === "same-origin"],
        ["Permissions-Policy", (value) => value === "camera=(), geolocation=(), microphone=()"],
        ["Referrer-Policy", (value) => value === "no-referrer"],
        ["Strict-Transport-Security", (value) => value === "max-age=31536000"],
        ["X-Content-Type-Options", (value) => value === "nosniff"],
        ["X-Frame-Options", (value) => value === "DENY"],
        ["X-Webappsec-Release", (value) => value === expectedHeaders.release],
        ["X-Webappsec-Worker-Version", (value) => value === expectedHeaders.versionId],
      ];
      for (const [urlPath, responseHeaders] of headers) {
        for (const [name, valid] of required) {
          if (!valid(responseHeaders.get(name))) throw new Error(`${name} mismatch: ${urlPath}`);
        }
        const robots = responseHeaders.get("X-Robots-Tag");
        if (expectedHeaders.noindex === true && robots !== "noindex") throw new Error(`X-Robots-Tag mismatch: ${urlPath}`);
        if (expectedHeaders.noindex === false && robots !== null) throw new Error(`unexpected X-Robots-Tag: ${urlPath}`);
        const expectedCache = isImmutableAssetPath(urlPath) ? "public, max-age=31536000, immutable" : "no-cache";
        if (responseHeaders.get("Cache-Control") !== expectedCache) throw new Error(`Cache-Control mismatch: ${urlPath}`);
      }
      layers.push(result("response-headers", "pass", `${headers.size} exact Worker responses for version ${expectedHeaders.versionId}`));
    } catch (error) {
      layers.push(result("response-headers", "fail", error.message));
      layers.push(result("sri", "skipped", "response headers failed"));
      return finalReport(manifestDigest, layers, target);
    }
  }

  try {
    const manifestByUrl = new Map(manifest.files.map((entry) => [entry.urlPath, entry]));
    let checked = 0;
    for (const entry of manifest.files.filter((candidate) => candidate.mediaType.startsWith("text/html"))) {
      const html = bodies.get(entry.urlPath).toString("utf8");
      const documentUrl = new URL(entry.urlPath, effectiveOrigin);
      for (const reference of localResourceReferences(html, documentUrl)) {
        if (reference.url.origin !== effectiveOrigin) throw new Error(`off-origin subresource: ${reference.url.href}`);
        const urlPath = `${reference.url.pathname}${reference.url.search}`;
        const target = manifestByUrl.get(urlPath);
        if (!target) throw new Error(`undeclared subresource: ${urlPath}`);
        const baseMediaType = target.mediaType.split(";", 1)[0].trim().toLowerCase();
        const validType = reference.kind === "script"
          ? target.path.endsWith(".js") && ["application/javascript", "text/javascript"].includes(baseMediaType)
          : target.path.endsWith(".css") && baseMediaType === "text/css";
        if (!validType) throw new Error(`${reference.kind} has invalid media type: ${urlPath}`);
        if (!reference.integrity) throw new Error(`missing SRI: ${urlPath}`);
        const expected = `sha384-${hash("sha384", bodies.get(urlPath), "base64")}`;
        if (reference.integrity.trim() !== expected) throw new Error(`SRI mismatch: ${urlPath}`);
        checked += 1;
      }
    }
    if (checked === 0) throw new Error("no SRI-protected resources found");
    layers.push(result("sri", "pass", `${checked} HTML references`));
  } catch (error) {
    layers.push(result("sri", "fail", error.message));
    return finalReport(manifestDigest, layers, target);
  }
  return finalReport(manifestDigest, layers, target);
}

export function humanReport(report) {
  const lines = report.layers.map((layer) => `${layer.state.toUpperCase().padEnd(9)} ${layer.name}: ${layer.detail}`);
  lines.push(report.ok ? "PASS deployment verified" : "FAIL deployment verification failed");
  return `${lines.join("\n")}\n`;
}
