export const onlineVerifierSnapshotSchema = "https://webappsec.metalagman.dev/schema/online-verifier-snapshot-v1";
export const releaseManifestSchema = "https://webappsec.metalagman.dev/schema/deployment-manifest-v1";
export const productionOrigin = "https://webappsec.metalagman.dev";

export const ciLayerNames = [
  "release-resolution",
  "evidence-inventory",
  "signatures",
  "attestations",
  "sbom",
  "vulnerability-evidence",
  "reproducible-build",
  "production-bytes",
  "sri",
];

export const proofNames = [
  "release-signatures",
  "deployment-signatures",
  "verification-signatures",
];

const sha256Pattern = /^[a-f0-9]{64}$/;
const revisionPattern = /^[a-f0-9]{40}$/;
const uuidPattern = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const semverPattern = /^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/;
export const browserLimits = Object.freeze({
  maxFiles: 128,
  maxFileBytes: 8 * 1024 * 1024,
  maxTotalBytes: 32 * 1024 * 1024,
  concurrency: 4,
  timeoutMs: 10_000,
});

export class VerificationUnavailableError extends Error {}

function bytesToHex(bytes) {
  return [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64(bytes, base64Implementation = globalThis.btoa) {
  if (typeof base64Implementation !== "function") throw new VerificationUnavailableError("Base64 encoding is unavailable");
  let binary = "";
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return base64Implementation(binary);
}

async function digest(algorithm, bytes, cryptoImplementation) {
  if (!cryptoImplementation?.subtle?.digest) throw new VerificationUnavailableError("Web Crypto is unavailable");
  try {
    return await cryptoImplementation.subtle.digest(algorithm, bytes);
  } catch (error) {
    throw new VerificationUnavailableError(`Web Crypto ${algorithm} failed: ${error.message}`);
  }
}

function exactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort().join("\0");
  const expected = [...keys].sort().join("\0");
  if (actual !== expected) throw new Error(`${label} fields mismatch`);
}

function exactUrl(value, expected, label) {
  if (value !== expected) throw new Error(`${label} mismatch`);
}

export function validateOnlineVerifierSnapshot(snapshot) {
  exactKeys(snapshot, ["schema", "version", "target", "sourceRelease", "deploymentEvidence", "verificationEvidence", "proofs", "manifest"], "snapshot");
  if (snapshot.schema !== onlineVerifierSnapshotSchema || snapshot.version !== 1) throw new Error("unsupported snapshot schema");

  exactKeys(snapshot.target, ["origin", "manifestDigest", "workerVersion", "deploymentId"], "target");
  if (snapshot.target.origin !== productionOrigin || !sha256Pattern.test(snapshot.target.manifestDigest)
    || !uuidPattern.test(snapshot.target.workerVersion) || !uuidPattern.test(snapshot.target.deploymentId)) {
    throw new Error("invalid target identity");
  }

  exactKeys(snapshot.sourceRelease, ["tag", "revision", "url"], "source release");
  if (!semverPattern.test(snapshot.sourceRelease.tag) || !revisionPattern.test(snapshot.sourceRelease.revision)) {
    throw new Error("invalid source release identity");
  }
  exactUrl(snapshot.sourceRelease.url,
    `https://github.com/metalagman/webappsec/releases/tag/${snapshot.sourceRelease.tag}`, "source release URL");

  exactKeys(snapshot.deploymentEvidence, ["release", "url", "runUrl"], "deployment evidence");
  const escapedTag = snapshot.sourceRelease.tag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const deploymentMatch = new RegExp(`^deployment-(?:bootstrap|deploy|rollback|restore)-${escapedTag}-([0-9]+)$`)
    .exec(snapshot.deploymentEvidence.release);
  const deploymentRunMatch = /^https:\/\/github\.com\/metalagman\/webappsec\/actions\/runs\/([0-9]+)$/.exec(snapshot.deploymentEvidence.runUrl);
  if (!deploymentMatch || !deploymentRunMatch || deploymentMatch[1] !== deploymentRunMatch[1]) {
    throw new Error("deployment evidence identity mismatch");
  }
  exactUrl(snapshot.deploymentEvidence.url,
    `https://github.com/metalagman/webappsec/releases/tag/${snapshot.deploymentEvidence.release}`, "deployment evidence URL");

  exactKeys(snapshot.verificationEvidence, ["release", "url", "runUrl", "verifiedAt", "layers"], "verification evidence");
  const verificationMatch = new RegExp(`^verification-${escapedTag}-([0-9]+)$`).exec(snapshot.verificationEvidence.release);
  const verificationRunMatch = /^https:\/\/github\.com\/metalagman\/webappsec\/actions\/runs\/([0-9]+)$/.exec(snapshot.verificationEvidence.runUrl);
  if (!verificationMatch || !verificationRunMatch || verificationMatch[1] !== verificationRunMatch[1]) {
    throw new Error("verification evidence identity mismatch");
  }
  exactUrl(snapshot.verificationEvidence.url,
    `https://github.com/metalagman/webappsec/releases/tag/${snapshot.verificationEvidence.release}`, "verification evidence URL");
  const verifiedTimestamp = typeof snapshot.verificationEvidence.verifiedAt === "string"
    ? Date.parse(snapshot.verificationEvidence.verifiedAt) : Number.NaN;
  if (typeof snapshot.verificationEvidence.verifiedAt !== "string"
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(snapshot.verificationEvidence.verifiedAt)
    || Number.isNaN(verifiedTimestamp)
    || new Date(verifiedTimestamp).toISOString() !== snapshot.verificationEvidence.verifiedAt) {
    throw new Error("invalid verification timestamp");
  }
  if (!Array.isArray(snapshot.verificationEvidence.layers)
    || snapshot.verificationEvidence.layers.length !== ciLayerNames.length) throw new Error("CI layer inventory mismatch");
  for (const [index, layer] of snapshot.verificationEvidence.layers.entries()) {
    exactKeys(layer, ["name", "state", "detail"], "CI layer");
    if (layer.name !== ciLayerNames[index] || layer.state !== "pass" || typeof layer.detail !== "string" || !layer.detail) {
      throw new Error("CI layer inventory mismatch");
    }
  }

  if (!Array.isArray(snapshot.proofs) || snapshot.proofs.length !== proofNames.length) throw new Error("proof inventory mismatch");
  for (const [index, proof] of snapshot.proofs.entries()) {
    exactKeys(proof, ["name", "state", "source"], "proof");
    if (proof.name !== proofNames[index] || proof.state !== "pass" || proof.source !== "ci") {
      throw new Error("proof inventory mismatch");
    }
  }

  exactKeys(snapshot.manifest, ["path", "size", "sha256"], "manifest reference");
  if (snapshot.manifest.path !== "release-manifest.json"
    || !Number.isSafeInteger(snapshot.manifest.size) || snapshot.manifest.size < 1 || snapshot.manifest.size > 2 * 1024 * 1024
    || snapshot.manifest.sha256 !== snapshot.target.manifestDigest) {
    throw new Error("invalid manifest reference");
  }
  return snapshot;
}

function safeRelativePath(value) {
  return typeof value === "string"
    && value.length > 0
    && value.length <= 240
    && value === value.normalize("NFC")
    && /^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(value)
    && !value.split("/").some((part) => !part || part === "." || part === ".." || part.startsWith("."));
}

function assertSortedUnique(values, label) {
  const sorted = [...values].sort((a, b) => a.localeCompare(b, "en"));
  if (values.some((value, index) => value !== sorted[index])) throw new Error(`${label} must be sorted`);
  if (new Set(values).size !== values.length) throw new Error(`duplicate ${label}`);
}

function expectedMediaType(path) {
  if (path.endsWith(".html")) return "text/html; charset=utf-8";
  if (path.endsWith(".css")) return "text/css; charset=utf-8";
  if (path.endsWith(".js")) return "text/javascript; charset=utf-8";
  if (path.endsWith(".json")) return "application/json; charset=utf-8";
  if (path.endsWith(".svg")) return "image/svg+xml";
  return "application/octet-stream";
}

export function validateBrowserReleaseManifest(manifest) {
  exactKeys(manifest, ["schema", "version", "origin", "release", "worker", "inputs", "files"], "release manifest");
  if (manifest.schema !== releaseManifestSchema || manifest.version !== 1 || manifest.origin !== productionOrigin) {
    throw new Error("unsupported release manifest");
  }
  exactKeys(manifest.release, ["repository", "revision", "tag", "workflow"], "manifest release");
  if (manifest.release.repository !== "https://github.com/metalagman/webappsec"
    || !revisionPattern.test(manifest.release.revision) || !semverPattern.test(manifest.release.tag)
    || !/^\.github\/workflows\/[A-Za-z0-9._-]+\.ya?ml$/.test(manifest.release.workflow)) {
    throw new Error("invalid manifest release identity");
  }
  exactKeys(manifest.worker, ["name"], "manifest worker");
  if (manifest.worker.name !== "webappsec") throw new Error("invalid manifest worker");
  if (!Array.isArray(manifest.inputs) || !Array.isArray(manifest.files)
    || manifest.files.length < 1 || manifest.files.length > browserLimits.maxFiles) {
    throw new Error("manifest file limit exceeded");
  }

  const inputPaths = manifest.inputs.map((entry) => entry.path);
  const filePaths = manifest.files.map((entry) => entry.path);
  const urlPaths = manifest.files.map((entry) => entry.urlPath);
  assertSortedUnique(inputPaths, "input paths");
  assertSortedUnique(filePaths, "file paths");
  if (new Set(urlPaths).size !== urlPaths.length) throw new Error("duplicate public URL paths");

  const requiredInputs = new Map([["worker/index.js", "worker"], ["wrangler.jsonc", "configuration"]]);
  let totalBytes = 0;
  for (const entry of manifest.inputs) {
    exactKeys(entry, ["path", "role", "size", "sha256"], "manifest input");
    if (!safeRelativePath(entry.path)) throw new Error(`expected a safe relative path: ${entry.path}`);
    if (requiredInputs.get(entry.path) !== entry.role && !["worker", "configuration"].includes(entry.role)) {
      throw new Error(`unsupported manifest input role: ${entry.role}`);
    }
    if (!Number.isSafeInteger(entry.size) || entry.size < 0 || entry.size > browserLimits.maxFileBytes
      || !sha256Pattern.test(entry.sha256)) throw new Error(`invalid manifest input: ${entry.path}`);
  }
  for (const [path, role] of requiredInputs) {
    if (manifest.inputs.filter((entry) => entry.path === path && entry.role === role).length !== 1) {
      throw new Error(`missing required manifest input: ${path}`);
    }
  }

  for (const entry of manifest.files) {
    exactKeys(entry, ["path", "urlPath", "mediaType", "size", "sha256"], "manifest file");
    if (!safeRelativePath(entry.path)) throw new Error(`expected a safe relative path: ${entry.path}`);
    if (!entry.path.startsWith("assets/")) throw new Error(`invalid public file path: ${entry.path}`);
    const relative = entry.path.slice("assets/".length);
    const expectedUrlPath = relative === "index.html" ? "/" : `/${relative}`;
    if (entry.urlPath !== expectedUrlPath || !entry.urlPath.startsWith("/")
      || entry.urlPath.includes("?") || entry.urlPath.includes("#") || entry.urlPath.includes("%")) {
      throw new Error(`invalid public URL path: ${entry.path}`);
    }
    if (entry.mediaType !== expectedMediaType(entry.path)
      || !Number.isSafeInteger(entry.size) || entry.size < 0 || entry.size > browserLimits.maxFileBytes
      || !sha256Pattern.test(entry.sha256)) throw new Error(`invalid manifest file: ${entry.path}`);
    totalBytes += entry.size;
  }
  if (totalBytes > browserLimits.maxTotalBytes) throw new Error("manifest total byte limit exceeded");
  if (manifest.files.filter((entry) => entry.path === "assets/index.html" && entry.urlPath === "/").length !== 1) {
    throw new Error("manifest requires one homepage");
  }
  return manifest;
}

async function withTimedResponse(fetchImplementation, url, signal, timeoutMs, consume, {
  method = "GET",
  AbortControllerImplementation = globalThis.AbortController,
} = {}) {
  if (!AbortControllerImplementation) throw new VerificationUnavailableError("AbortController is unavailable");
  const controller = new AbortControllerImplementation();
  let timedOut = false;
  const abort = () => controller.abort(signal?.reason);
  if (signal?.aborted) abort();
  else signal?.addEventListener("abort", abort, { once: true });
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort(new Error("request timed out"));
  }, timeoutMs);
  try {
    const response = await fetchImplementation(url, {
      cache: "no-store",
      credentials: "omit",
      method,
      mode: "cors",
      redirect: "error",
      signal: controller.signal,
    });
    return await consume(response, controller.signal);
  } catch (error) {
    if (signal?.aborted) throw signal.reason ?? new Error("request aborted");
    if (timedOut) throw new VerificationUnavailableError(`request timed out: ${url}`);
    if (error instanceof VerificationUnavailableError) throw error;
    if (error instanceof TypeError || error?.name === "AbortError") {
      throw new VerificationUnavailableError(`request unavailable: ${url}: ${error.message}`);
    }
    throw error;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", abort);
  }
}

async function boundedResponseBytes(response, entry, total, maxFileBytes = browserLimits.maxFileBytes) {
  const declared = response.headers.get("Content-Length");
  if (declared !== null && (!/^[0-9]+$/.test(declared) || Number(declared) > maxFileBytes)) {
    throw new Error(`response byte limit exceeded: ${entry.urlPath}`);
  }
  const chunks = [];
  let length = 0;
  if (response.body?.getReader) {
    const reader = response.body.getReader();
    try {
      while (true) {
        let read;
        try {
          read = await reader.read();
        } catch (error) {
          throw new VerificationUnavailableError(`response body unavailable: ${entry.urlPath}: ${error.message}`);
        }
        const { done, value } = read;
        if (done) break;
        length += value.byteLength;
        total.bytes += value.byteLength;
        if (length > maxFileBytes || total.bytes > browserLimits.maxTotalBytes) {
          await reader.cancel("byte limit exceeded");
          throw new Error(`response byte limit exceeded: ${entry.urlPath}`);
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
  } else {
    const bytes = new Uint8Array(await response.arrayBuffer());
    length = bytes.byteLength;
    total.bytes += length;
    if (length > maxFileBytes || total.bytes > browserLimits.maxTotalBytes) {
      throw new Error(`response byte limit exceeded: ${entry.urlPath}`);
    }
    chunks.push(bytes);
  }
  const output = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

function validateResponseIdentity(response, target, urlPath) {
  if (response.headers.get("X-Webappsec-Release") !== target.manifestDigest) {
    throw new Error(`release digest mismatch: ${urlPath}`);
  }
  if (response.headers.get("X-Webappsec-Worker-Version") !== target.workerVersion) {
    throw new Error(`Worker version mismatch: ${urlPath}`);
  }
}

export async function verifyProductionFiles({
  manifest,
  target,
  fetchImplementation = globalThis.fetch,
  cryptoImplementation = globalThis.crypto,
  signal,
  onFile,
  AbortControllerImplementation = globalThis.AbortController,
}) {
  validateBrowserReleaseManifest(manifest);
  if (!fetchImplementation) throw new VerificationUnavailableError("Fetch is unavailable");
  if (manifest.origin !== target.origin || target.origin !== productionOrigin) throw new Error("production origin mismatch");
  if (!AbortControllerImplementation) throw new VerificationUnavailableError("AbortController is unavailable");
  const total = { bytes: 0 };
  const bodies = new Map();
  let nextIndex = 0;
  const group = new AbortControllerImplementation();
  const abortGroup = () => group.abort(signal?.reason);
  if (signal?.aborted) abortGroup();
  else signal?.addEventListener("abort", abortGroup, { once: true });

  async function worker() {
    while (nextIndex < manifest.files.length) {
      const entry = manifest.files[nextIndex++];
      const url = new URL(entry.urlPath, productionOrigin);
      if (url.origin !== productionOrigin || url.pathname !== entry.urlPath || url.search || url.hash) {
        throw new Error(`production URL mismatch: ${entry.urlPath}`);
      }
      await withTimedResponse(fetchImplementation, url.href, group.signal, browserLimits.timeoutMs, async (response) => {
        if (!response.ok) {
          if (response.status >= 500) throw new VerificationUnavailableError(`production returned HTTP ${response.status}: ${entry.urlPath}`);
          throw new Error(`production returned HTTP ${response.status}: ${entry.urlPath}`);
        }
        validateResponseIdentity(response, target, entry.urlPath);
        const bytes = await boundedResponseBytes(response, entry, total);
        if (bytes.byteLength !== entry.size) throw new Error(`size mismatch: ${entry.urlPath}`);
        const actual = bytesToHex(await digest("SHA-256", bytes, cryptoImplementation));
        if (actual !== entry.sha256) throw new Error(`SHA-256 mismatch: ${entry.urlPath}`);
        bodies.set(entry.urlPath, bytes);
        onFile?.(entry);
      }, { AbortControllerImplementation });
    }
  }

  const workers = Array.from({ length: Math.min(browserLimits.concurrency, manifest.files.length) }, () => worker());
  try {
    await Promise.all(workers);
    return bodies;
  } catch (error) {
    group.abort(error);
    await Promise.allSettled(workers);
    throw error;
  } finally {
    signal?.removeEventListener("abort", abortGroup);
  }
}

const sriAlgorithms = new Map([
  ["sha256", { webCrypto: "SHA-256", rank: 1, pattern: /^sha256-[A-Za-z0-9+/]{43}=$/ }],
  ["sha384", { webCrypto: "SHA-384", rank: 2, pattern: /^sha384-[A-Za-z0-9+/]{64}$/ }],
  ["sha512", { webCrypto: "SHA-512", rank: 3, pattern: /^sha512-[A-Za-z0-9+/]{86}==$/ }],
]);

function sriResource(element, attribute, kind, documentUrl, manifestByUrl) {
  const raw = element.getAttribute(attribute);
  if (!raw) throw new Error(`missing resource ${attribute}`);
  const url = new URL(raw, documentUrl);
  if (url.origin !== productionOrigin || url.username || url.password || url.search || url.hash || url.pathname.includes("%")) {
    throw new Error(`SRI resource must use the same production origin: ${raw}`);
  }
  const entry = manifestByUrl.get(url.pathname);
  if (!entry) throw new Error(`SRI resource is absent from manifest: ${url.pathname}`);
  const expectedMediaType = kind === "script" ? "text/javascript; charset=utf-8" : "text/css; charset=utf-8";
  if (entry.mediaType !== expectedMediaType) throw new Error(`SRI ${kind} media type mismatch: ${url.pathname}`);
  const integrity = element.getAttribute("integrity");
  if (!integrity) throw new Error(`missing SRI for ${url.pathname}`);
  const tokens = integrity.trim().split(/\s+/);
  const supported = [];
  for (const token of tokens) {
    const algorithmName = token.slice(0, token.indexOf("-"));
    const algorithm = sriAlgorithms.get(algorithmName);
    if (algorithm?.pattern.test(token)) supported.push({ token, algorithmName, ...algorithm });
  }
  if (supported.length === 0) throw new Error(`unsupported or malformed SRI for ${url.pathname}`);
  if (!supported.some(({ algorithmName }) => algorithmName === "sha384")) {
    throw new Error(`SHA-384 is required for ${url.pathname}`);
  }
  const strongestRank = Math.max(...supported.map(({ rank }) => rank));
  const strongest = supported.filter(({ rank }) => rank === strongestRank);
  return { entry, algorithmName: strongest[0].algorithmName, webCrypto: strongest[0].webCrypto, tokens: strongest.map(({ token }) => token) };
}

export async function verifySriDocuments({
  manifest,
  bodies,
  DOMParserImplementation = globalThis.DOMParser,
  cryptoImplementation = globalThis.crypto,
  TextDecoderImplementation = globalThis.TextDecoder,
  base64Implementation = globalThis.btoa,
}) {
  validateBrowserReleaseManifest(manifest);
  if (!DOMParserImplementation) throw new VerificationUnavailableError("DOMParser is unavailable");
  const parser = new DOMParserImplementation();
  const manifestByUrl = new Map(manifest.files.map((entry) => [entry.urlPath, entry]));
  const digestCache = new Map();
  let scripts = 0;
  let stylesheets = 0;
  let importMapModules = 0;
  let importMapDocuments = 0;

  if (!TextDecoderImplementation) throw new VerificationUnavailableError("TextDecoder is unavailable");
  const verifyResource = async ({ entry, algorithmName, webCrypto, tokens }) => {
    const bytes = bodies.get(entry.urlPath);
    if (!(bytes instanceof Uint8Array)) throw new Error(`SRI resource bytes are missing: ${entry.urlPath}`);
    const cacheKey = `${algorithmName}:${entry.urlPath}`;
    let expected = digestCache.get(cacheKey);
    if (!expected) {
      expected = `${algorithmName}-${bytesToBase64(await digest(webCrypto, bytes, cryptoImplementation), base64Implementation)}`;
      digestCache.set(cacheKey, expected);
    }
    if (!tokens.includes(expected)) throw new Error(`SRI mismatch: ${entry.urlPath}`);
  };

  for (const entry of manifest.files.filter((candidate) => candidate.mediaType === "text/html; charset=utf-8")) {
    const bytes = bodies.get(entry.urlPath);
    if (!(bytes instanceof Uint8Array)) throw new Error(`HTML bytes are missing: ${entry.urlPath}`);
    const document = parser.parseFromString(new TextDecoderImplementation().decode(bytes), "text/html");
    const documentUrl = new URL(entry.urlPath, productionOrigin);
    if (document.querySelectorAll("base[href]").length > 0) throw new Error(`base href is not allowed: ${entry.urlPath}`);
    for (const element of document.querySelectorAll("script[src]")) {
      await verifyResource(sriResource(element, "src", "script", documentUrl, manifestByUrl));
      scripts += 1;
    }
    for (const element of document.querySelectorAll('link[rel~="stylesheet"][href]')) {
      await verifyResource(sriResource(element, "href", "stylesheet", documentUrl, manifestByUrl));
      stylesheets += 1;
    }

    const moduleScripts = [...document.querySelectorAll('script[type="module"][src]')];
    const importMaps = [...document.querySelectorAll('script[type="importmap"]')];
    if (moduleScripts.length > 0) {
      if (importMaps.length !== 1) throw new Error(`expected exactly one import map: ${entry.urlPath}`);
      const [importMapElement] = importMaps;
      if (importMapElement.hasAttribute("src")) throw new Error("import map must be inline");
      const scriptsInOrder = [...document.querySelectorAll("script")];
      const importMapIndex = scriptsInOrder.indexOf(importMapElement);
      if (moduleScripts.some((element) => scriptsInOrder.indexOf(element) < importMapIndex)) {
        throw new Error(`import map must precede module scripts: ${entry.urlPath}`);
      }

      const source = importMapElement.textContent ?? "";
      let importMap;
      try {
        importMap = JSON.parse(source);
      } catch (error) {
        throw new Error(`invalid import map JSON: ${error.message}`);
      }
      if (!importMap || Array.isArray(importMap) || typeof importMap !== "object"
        || Object.keys(importMap).length !== 1 || !("integrity" in importMap)
        || !importMap.integrity || Array.isArray(importMap.integrity) || typeof importMap.integrity !== "object") {
        throw new Error("import map must contain only an integrity object");
      }
      if (JSON.stringify(importMap) !== source) throw new Error("import map must use canonical JSON");

      const javascriptEntries = manifest.files
        .filter((candidate) => candidate.mediaType === "text/javascript; charset=utf-8")
        .sort((left, right) => left.urlPath.localeCompare(right.urlPath, "en"));
      const expectedPaths = javascriptEntries.map((candidate) => candidate.urlPath);
      const actualPaths = Object.keys(importMap.integrity);
      if (actualPaths.length !== expectedPaths.length
        || actualPaths.some((urlPath, index) => urlPath !== expectedPaths[index])) {
        throw new Error("import map integrity inventory does not match declared JavaScript modules");
      }
      for (const candidate of javascriptEntries) {
        const candidateBytes = bodies.get(candidate.urlPath);
        if (!(candidateBytes instanceof Uint8Array)) throw new Error(`import map resource bytes are missing: ${candidate.urlPath}`);
        const expected = `sha384-${bytesToBase64(await digest("SHA-384", candidateBytes, cryptoImplementation), base64Implementation)}`;
        if (importMap.integrity[candidate.urlPath] !== expected) {
          throw new Error(`import map integrity mismatch: ${candidate.urlPath}`);
        }
      }

      const importMapHash = `sha384-${bytesToBase64(await digest("SHA-384", new TextEncoder().encode(source), cryptoImplementation), base64Implementation)}`;
      const documentPolicy = [
        "default-src 'none'",
        `script-src 'self' '${importMapHash}'`,
        "style-src 'self'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "base-uri 'none'",
        "form-action 'none'",
      ].join("; ");
      const policyElements = [...document.querySelectorAll("meta[http-equiv]")]
        .filter((element) => element.getAttribute("http-equiv")?.toLowerCase() === "content-security-policy");
      if (policyElements.length !== 1 || policyElements[0].getAttribute("content") !== documentPolicy) {
        throw new Error(`document CSP does not pin the import map: ${entry.urlPath}`);
      }
      const responsePolicyBytes = bodies.get("/security-policy.txt");
      if (!(responsePolicyBytes instanceof Uint8Array)
        || new TextDecoderImplementation().decode(responsePolicyBytes) !== `${documentPolicy}; frame-ancestors 'none'`) {
        throw new Error("signed response CSP does not pin the import map");
      }
      importMapModules += javascriptEntries.length;
      importMapDocuments += 1;
    } else if (importMaps.length > 0) {
      throw new Error(`unused import map: ${entry.urlPath}`);
    }
  }
  if (scripts < 1 || stylesheets < 1) throw new Error("SRI requires at least one script and one stylesheet");
  if (importMapDocuments < 1) throw new Error("no import map found");
  return { scripts, stylesheets, resources: scripts + stylesheets, importMapModules };
}

export function verificationAge(verifiedAt, now = Date.now()) {
  const timestamp = Date.parse(verifiedAt);
  if (Number.isNaN(timestamp) || !Number.isFinite(now) || now < timestamp) throw new Error("invalid verification timestamp");
  const thresholdMs = 36 * 60 * 60 * 1000;
  const ageMs = now - timestamp;
  return { stale: ageMs > thresholdMs, ageMs, thresholdMs };
}

async function readJson(url, label, fetchImplementation, signal, {
  AbortControllerImplementation = globalThis.AbortController,
  TextDecoderImplementation = globalThis.TextDecoder,
} = {}) {
  return withTimedResponse(fetchImplementation, url, signal, browserLimits.timeoutMs, async (response) => {
    if (!response.ok) {
      if (response.status >= 500) throw new VerificationUnavailableError(`${label} returned HTTP ${response.status}`);
      throw new Error(`${label} returned HTTP ${response.status}`);
    }
    const contentType = response.headers.get("Content-Type")?.split(";", 1)[0].trim().toLowerCase();
    if (contentType !== "application/json") throw new Error(`${label} content type mismatch`);
    const bytes = await boundedResponseBytes(response, { urlPath: new URL(url).pathname }, { bytes: 0 }, 2 * 1024 * 1024);
    try {
      return { bytes, value: JSON.parse(new TextDecoderImplementation().decode(bytes)) };
    } catch (error) {
      throw new Error(`${label} is malformed JSON: ${error.message}`);
    }
  }, { AbortControllerImplementation });
}

async function readProductionIdentity(fetchImplementation, target, signal, AbortControllerImplementation) {
  return withTimedResponse(fetchImplementation, `${productionOrigin}/`, signal, browserLimits.timeoutMs, async (response) => {
    if (!response.ok) throw new VerificationUnavailableError(`production identity returned HTTP ${response.status}`);
    validateResponseIdentity(response, target, "/");
    return { manifestDigest: target.manifestDigest, workerVersion: target.workerVersion };
  }, { method: "HEAD", AbortControllerImplementation });
}

function failureState(error) {
  return error instanceof VerificationUnavailableError ? "unavailable" : "fail";
}

export async function verifyOnlineDeployment({
  verifierOrigin = globalThis.location?.origin,
  fetchImplementation = globalThis.fetch,
  cryptoImplementation = globalThis.crypto,
  DOMParserImplementation = globalThis.DOMParser,
  AbortControllerImplementation = globalThis.AbortController,
  TextDecoderImplementation = globalThis.TextDecoder,
  base64Implementation = globalThis.btoa,
  signal,
  now = Date.now,
  onCheck,
} = {}) {
  const missingCapabilities = [
    [typeof fetchImplementation === "function", "Fetch"],
    [typeof cryptoImplementation?.subtle?.digest === "function", "Web Crypto"],
    [typeof DOMParserImplementation === "function", "DOMParser"],
    [typeof AbortControllerImplementation === "function", "AbortController"],
    [typeof TextDecoderImplementation === "function", "TextDecoder"],
    [typeof base64Implementation === "function", "Base64 encoding"],
  ].filter(([available]) => !available).map(([, name]) => name);
  if (missingCapabilities.length > 0) {
    const check = Object.freeze({
      id: "browser:capabilities",
      group: "browser",
      state: "unavailable",
      label: "Возможности браузера",
      detail: `Недоступно: ${missingCapabilities.join(", ")}`,
    });
    onCheck?.(check);
    return { ok: false, stale: false, identity: null, checks: [check], error: { state: "unavailable", message: check.detail } };
  }
  let parsedVerifierOrigin;
  try {
    parsedVerifierOrigin = new URL(verifierOrigin).origin;
  } catch {
    throw new Error("invalid verifier origin");
  }
  if (!parsedVerifierOrigin.startsWith("https://") || parsedVerifierOrigin !== verifierOrigin) {
    throw new Error("verifier origin must be an HTTPS origin");
  }

  const checks = new Map();
  const publish = (check) => {
    if (signal?.aborted) throw signal.reason ?? new Error("verification aborted");
    const frozen = Object.freeze({ ...check });
    checks.set(check.id, frozen);
    onCheck?.(frozen);
  };
  const stage = async (id, label, operation, detail) => {
    publish({ id, group: "browser", state: "running", label, detail: "Проверка выполняется" });
    try {
      const value = await operation();
      publish({ id, group: "browser", state: "pass", label, detail: typeof detail === "function" ? detail(value) : detail });
      return value;
    } catch (error) {
      publish({ id, group: "browser", state: failureState(error), label, detail: error.message });
      throw error;
    }
  };

  let snapshot;
  let manifest;
  let age = { stale: false, ageMs: 0, thresholdMs: 36 * 60 * 60 * 1000 };
  try {
    publish({ id: "browser:capabilities", group: "browser", state: "pass", label: "Возможности браузера", detail: "Fetch, Web Crypto, DOMParser и AbortController доступны" });
    snapshot = await stage("browser:snapshot", "Проверенный CI snapshot", async () => {
      const loaded = await readJson(`${parsedVerifierOrigin}/current-verification.json`, "verification snapshot", fetchImplementation, signal, {
        AbortControllerImplementation, TextDecoderImplementation,
      });
      return validateOnlineVerifierSnapshot(loaded.value);
    }, (value) => `${value.sourceRelease.tag}, ${value.target.manifestDigest}`);

    const manifestLoad = await stage("browser:manifest", "Подписанный release manifest", async () => {
      const loaded = await readJson(`${parsedVerifierOrigin}/${snapshot.manifest.path}`, "release manifest", fetchImplementation, signal, {
        AbortControllerImplementation, TextDecoderImplementation,
      });
      if (loaded.bytes.byteLength !== snapshot.manifest.size) throw new Error("release manifest size mismatch");
      const actualDigest = bytesToHex(await digest("SHA-256", loaded.bytes, cryptoImplementation));
      if (actualDigest !== snapshot.manifest.sha256 || actualDigest !== snapshot.target.manifestDigest) {
        throw new Error("release manifest SHA-256 mismatch");
      }
      const value = validateBrowserReleaseManifest(loaded.value);
      if (value.release.tag !== snapshot.sourceRelease.tag || value.release.revision !== snapshot.sourceRelease.revision) {
        throw new Error("release manifest source identity mismatch");
      }
      return value;
    }, (value) => `${value.files.length} public files`);
    manifest = manifestLoad;

    for (const proof of snapshot.proofs) {
      publish({ id: `ci:${proof.name}`, group: "ci", state: "pass", label: proof.name, detail: "Cosign policy verified by trusted CI" });
    }
    for (const layer of snapshot.verificationEvidence.layers) {
      publish({ id: `ci:${layer.name}`, group: "ci", state: "pass", label: layer.name, detail: layer.detail });
    }
    age = verificationAge(snapshot.verificationEvidence.verifiedAt, now());

    await stage("browser:identity", "Текущий deployment", () =>
      readProductionIdentity(fetchImplementation, snapshot.target, signal, AbortControllerImplementation),
    () => `${snapshot.target.manifestDigest}, Worker ${snapshot.target.workerVersion}`);

    const bodies = await stage("browser:production-bytes", "Production-файлы", () => verifyProductionFiles({
      manifest,
      target: snapshot.target,
      fetchImplementation,
      cryptoImplementation,
      signal,
      AbortControllerImplementation,
    }), (value) => `${value.size} files match SHA-256`);

    await stage("browser:sri", "Subresource Integrity", () => verifySriDocuments({
      manifest,
      bodies,
      DOMParserImplementation,
      cryptoImplementation,
      TextDecoderImplementation,
      base64Implementation,
    }), (value) => `${value.resources} script/style resources and ${value.importMapModules} import-map modules match SHA-384`);

    await stage("browser:stability", "Deployment не изменился", () =>
      readProductionIdentity(fetchImplementation, snapshot.target, signal, AbortControllerImplementation),
    () => `Worker ${snapshot.target.workerVersion} remained current`);
  } catch (error) {
    if (signal?.aborted) throw signal.reason ?? error;
    return {
      ok: false,
      stale: age.stale,
      identity: snapshot?.target ?? null,
      sourceRelease: snapshot?.sourceRelease,
      deploymentEvidence: snapshot?.deploymentEvidence,
      verificationEvidence: snapshot?.verificationEvidence,
      checks: [...checks.values()],
      error: { state: failureState(error), message: error.message },
    };
  }

  return {
    ok: [...checks.values()].every((check) => check.state === "pass"),
    stale: age.stale,
    ageMs: age.ageMs,
    identity: snapshot.target,
    sourceRelease: snapshot.sourceRelease,
    deploymentEvidence: snapshot.deploymentEvidence,
    verificationEvidence: snapshot.verificationEvidence,
    checks: [...checks.values()],
  };
}
