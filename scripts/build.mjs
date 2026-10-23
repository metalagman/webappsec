import { createHash } from "node:crypto";
import { lstat, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { contentHashName } from "../lib/content-addressing.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const digest = (algorithm, bytes, encoding = "hex") =>
  createHash(algorithm).update(bytes).digest(encoding);

const replaceExactlyOnce = (source, marker, replacement) => {
  const parts = source.split(marker);
  if (parts.length !== 2) {
    throw new Error(`expected exactly one ${marker} marker`);
  }
  return parts.join(replacement);
};

export async function buildSite({
  outputDirectory = path.join(repositoryRoot, "dist"),
  sourceDirectory = path.join(repositoryRoot, "site"),
} = {}) {
  const sourceMetadata = await lstat(sourceDirectory);
  if (sourceMetadata.isSymbolicLink() || !sourceMetadata.isDirectory()) throw new Error("site source must be a regular directory");
  const sourceFiles = ["index.html", "404.html", "styles.css", "app.js", "interactions.js"];
  for (const name of sourceFiles) {
    const metadata = await lstat(path.join(sourceDirectory, name));
    if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error(`site source must be a regular file: ${name}`);
    if (metadata.size > 5 * 1024 * 1024) throw new Error(`site source exceeds size limit: ${name}`);
  }
  const [template, notFoundTemplate, styleBytes, scriptTemplate, interactionsBytes] = await Promise.all([
    readFile(path.join(sourceDirectory, "index.html"), "utf8"),
    readFile(path.join(sourceDirectory, "404.html"), "utf8"),
    readFile(path.join(sourceDirectory, "styles.css")),
    readFile(path.join(sourceDirectory, "app.js"), "utf8"),
    readFile(path.join(sourceDirectory, "interactions.js")),
  ]);

  const styleName = contentHashName("site", digest("sha256", styleBytes), "css");
  const interactionsName = contentHashName("interactions", digest("sha256", interactionsBytes), "js");
  const scriptBytes = Buffer.from(replaceExactlyOnce(
    scriptTemplate,
    "{{INTERACTIONS_MODULE}}",
    `/app/${interactionsName}`,
  ));
  const scriptName = contentHashName("app", digest("sha256", scriptBytes), "js");
  const styleIntegrity = `sha384-${digest("sha384", styleBytes, "base64")}`;
  const scriptIntegrity = `sha384-${digest("sha384", scriptBytes, "base64")}`;
  const interactionsIntegrity = `sha384-${digest("sha384", interactionsBytes, "base64")}`;
  const importMap = JSON.stringify({
    integrity: Object.fromEntries([
      [`/app/${scriptName}`, scriptIntegrity],
      [`/app/${interactionsName}`, interactionsIntegrity],
    ].sort(([left], [right]) => left.localeCompare(right, "en"))),
  });
  const importMapIntegrity = `sha384-${digest("sha384", Buffer.from(importMap), "base64")}`;
  const documentCsp = [
    "default-src 'none'",
    `script-src 'self' '${importMapIntegrity}'`,
    "style-src 'self'",
    "img-src 'self' data:",
    "connect-src 'self'",
    "base-uri 'none'",
    "form-action 'none'",
  ].join("; ");
  const responseCsp = `${documentCsp}; frame-ancestors 'none'`;

  let html = replaceExactlyOnce(template, "{{DOCUMENT_CSP}}", documentCsp);
  html = replaceExactlyOnce(html, "{{IMPORT_MAP}}", importMap);
  html = replaceExactlyOnce(html, "{{STYLE_HREF}}", `/app/${styleName}`);
  html = replaceExactlyOnce(html, "{{STYLE_INTEGRITY}}", styleIntegrity);
  html = replaceExactlyOnce(html, "{{SCRIPT_SRC}}", `/app/${scriptName}`);
  html = replaceExactlyOnce(html, "{{SCRIPT_INTEGRITY}}", scriptIntegrity);

  let notFound = replaceExactlyOnce(
    notFoundTemplate,
    "{{STYLE_HREF}}",
    `/app/${styleName}`,
  );
  notFound = replaceExactlyOnce(notFound, "{{STYLE_INTEGRITY}}", styleIntegrity);

  await rm(outputDirectory, { recursive: true, force: true });
  await mkdir(path.join(outputDirectory, "app"), { recursive: true });
  await Promise.all([
    writeFile(path.join(outputDirectory, "index.html"), html),
    writeFile(path.join(outputDirectory, "404.html"), notFound),
    writeFile(path.join(outputDirectory, "app", styleName), styleBytes),
    writeFile(path.join(outputDirectory, "app", scriptName), scriptBytes),
    writeFile(path.join(outputDirectory, "app", interactionsName), interactionsBytes),
    writeFile(path.join(outputDirectory, "security-policy.txt"), responseCsp),
  ]);

  return {
    outputDirectory,
    files: [
      "404.html",
      `app/${scriptName}`,
      `app/${interactionsName}`,
      `app/${styleName}`,
      "index.html",
      "security-policy.txt",
    ],
  };
}

const isMain = process.argv[1]
  && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (isMain) {
  const result = await buildSite();
  process.stdout.write(`Built ${result.files.length} deterministic files in ${result.outputDirectory}\n`);
}
