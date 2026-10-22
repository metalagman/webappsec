#!/usr/bin/env node
import { createHash } from "node:crypto";
import { parse } from "parse5";

import {
  validateBrowserReleaseManifest,
  validateOnlineVerifierSnapshot,
} from "../lib/browser-verifier.mjs";

const usage = "Usage: node scripts/verify-verifier-static.mjs --origin <https-origin> --expected-version <uuid> [--preview]";
const args = process.argv.slice(2);
const options = { preview: false };
for (let index = 0; index < args.length; index += 1) {
  if (args[index] === "--preview") options.preview = true;
  else if (["--origin", "--expected-version"].includes(args[index]) && args[index + 1]) {
    options[args[index].slice(2)] = args[++index];
  } else {
    process.stderr.write(`${usage}\n`);
    process.exit(2);
  }
}

let origin;
try {
  const url = new URL(options.origin);
  if (url.protocol !== "https:" || url.origin !== options.origin || url.username || url.password) throw new Error();
  origin = url.origin;
} catch {
  process.stderr.write(`${usage}\n`);
  process.exit(2);
}
if (!/^[a-f0-9-]{36}$/.test(options["expected-version"] ?? "")) {
  process.stderr.write(`${usage}\n`);
  process.exit(2);
}

const expectedCsp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' https://webappsec.metalagman.dev; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const request = async (path) => {
  const response = await fetch(`${origin}${path}`, {
    cache: "no-store",
    credentials: "omit",
    redirect: "error",
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error(`${path} returned HTTP ${response.status}`);
  if (response.headers.get("X-Webappsec-Verifier-Version") !== options["expected-version"]) {
    throw new Error(`${path} verifier version mismatch`);
  }
  if (response.headers.get("Content-Security-Policy") !== expectedCsp) throw new Error(`${path} CSP mismatch`);
  if (options.preview && response.headers.get("X-Robots-Tag") !== "noindex") throw new Error(`${path} preview is indexable`);
  return response;
};
const readBytes = async (path, limit = 2 * 1024 * 1024) => {
  const response = await request(path);
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength < 1 || bytes.byteLength > limit) throw new Error(`${path} byte limit exceeded`);
  return { response, bytes };
};
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const sha384 = (bytes) => createHash("sha384").update(bytes).digest("base64");
const attributes = (node) => Object.fromEntries((node.attrs ?? []).map(({ name, value }) => [name, value]));
const resources = [];
const visit = (node) => {
  const attrs = attributes(node);
  if (node.nodeName === "script" && attrs.src) resources.push({ path: attrs.src, integrity: attrs.integrity, kind: "script" });
  if (node.nodeName === "link" && (attrs.rel ?? "").split(/\s+/).includes("stylesheet") && attrs.href) {
    resources.push({ path: attrs.href, integrity: attrs.integrity, kind: "style" });
  }
  for (const child of node.childNodes ?? []) visit(child);
};

const htmlLoad = await readBytes("/");
if (htmlLoad.response.headers.get("Cache-Control") !== "no-store") throw new Error("HTML cache policy mismatch");
visit(parse(new TextDecoder().decode(htmlLoad.bytes)));
if (resources.length !== 2 || resources.filter(({ kind }) => kind === "script").length !== 1
  || resources.filter(({ kind }) => kind === "style").length !== 1) throw new Error("verifier resource inventory mismatch");
for (const resource of resources) {
  const url = new URL(resource.path, origin);
  if (url.origin !== origin || url.search || url.hash || !url.pathname.startsWith("/app/")) throw new Error("verifier asset URL mismatch");
  const load = await readBytes(url.pathname, 5 * 1024 * 1024);
  if (load.response.headers.get("Cache-Control") !== "public, max-age=31536000, immutable") {
    throw new Error(`${url.pathname} cache policy mismatch`);
  }
  if (resource.integrity !== `sha384-${sha384(load.bytes)}`) throw new Error(`${url.pathname} SRI mismatch`);
}

const snapshotLoad = await readBytes("/current-verification.json");
const manifestLoad = await readBytes("/release-manifest.json");
for (const [path, load] of [["/current-verification.json", snapshotLoad], ["/release-manifest.json", manifestLoad]]) {
  if (load.response.headers.get("Cache-Control") !== "no-store") throw new Error(`${path} cache policy mismatch`);
  if (load.response.headers.get("Content-Type")?.split(";", 1)[0] !== "application/json") {
    throw new Error(`${path} content type mismatch`);
  }
}
const snapshot = validateOnlineVerifierSnapshot(JSON.parse(new TextDecoder().decode(snapshotLoad.bytes)));
const manifest = validateBrowserReleaseManifest(JSON.parse(new TextDecoder().decode(manifestLoad.bytes)));
if (snapshot.manifest.size !== manifestLoad.bytes.byteLength
  || snapshot.manifest.sha256 !== sha256(manifestLoad.bytes)
  || snapshot.target.manifestDigest !== snapshot.manifest.sha256
  || manifest.release.tag !== snapshot.sourceRelease.tag
  || manifest.release.revision !== snapshot.sourceRelease.revision) {
  throw new Error("published snapshot and manifest mismatch");
}
process.stdout.write(`${JSON.stringify({ ok: true, origin, versionId: options["expected-version"], release: snapshot.sourceRelease.tag })}\n`);
