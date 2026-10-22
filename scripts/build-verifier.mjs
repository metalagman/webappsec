import { createHash } from "node:crypto";
import { lstat, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { contentHashName } from "../lib/content-addressing.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const hash = (algorithm, bytes, encoding = "hex") =>
  createHash(algorithm).update(bytes).digest(encoding);

function replaceOnce(source, marker, replacement) {
  const parts = source.split(marker);
  if (parts.length !== 2) throw new Error(`expected exactly one ${marker} marker`);
  return parts.join(replacement);
}

async function readRegularFile(filename, limit = 5 * 1024 * 1024) {
  const metadata = await lstat(filename);
  if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error(`verifier source must be a regular file: ${filename}`);
  if (metadata.size > limit) throw new Error(`verifier source exceeds size limit: ${filename}`);
  return readFile(filename);
}

export async function buildVerifierSite({
  outputDirectory = path.join(root, "dist-verifier"),
  sourceDirectory = path.join(root, "verifier-site"),
  enginePath = path.join(root, "lib/browser-verifier.mjs"),
} = {}) {
  const sourceMetadata = await lstat(sourceDirectory);
  if (sourceMetadata.isSymbolicLink() || !sourceMetadata.isDirectory()) throw new Error("verifier source must be a regular directory");

  const [templateBytes, styleBytes, appTemplateBytes, engineBytes] = await Promise.all([
    readRegularFile(path.join(sourceDirectory, "index.html")),
    readRegularFile(path.join(sourceDirectory, "styles.css")),
    readRegularFile(path.join(sourceDirectory, "app.js")),
    readRegularFile(enginePath),
  ]);
  const engineSource = engineBytes.toString("utf8").replace(/^export\s+/gm, "");
  const appSource = appTemplateBytes.toString("utf8").replace(
    'import { verifyOnlineDeployment } from "./{{ENGINE_MODULE}}";\n',
    "",
  );
  if (appSource === appTemplateBytes.toString("utf8")) throw new Error("expected verifier engine import marker");
  const appBytes = Buffer.from(`${engineSource}\n${appSource}`);
  const styleName = contentHashName("verifier", hash("sha256", styleBytes), "css");
  const appName = contentHashName("verifier", hash("sha256", appBytes), "js");
  const styleIntegrity = `sha384-${hash("sha384", styleBytes, "base64")}`;
  const appIntegrity = `sha384-${hash("sha384", appBytes, "base64")}`;

  let html = replaceOnce(templateBytes.toString("utf8"), "{{STYLE_HREF}}", `/app/${styleName}`);
  html = replaceOnce(html, "{{STYLE_INTEGRITY}}", styleIntegrity);
  html = replaceOnce(html, "{{SCRIPT_SRC}}", `/app/${appName}`);
  html = replaceOnce(html, "{{SCRIPT_INTEGRITY}}", appIntegrity);

  await rm(outputDirectory, { recursive: true, force: true });
  await mkdir(path.join(outputDirectory, "app"), { recursive: true });
  await Promise.all([
    writeFile(path.join(outputDirectory, "index.html"), html),
    writeFile(path.join(outputDirectory, "app", styleName), styleBytes),
    writeFile(path.join(outputDirectory, "app", appName), appBytes),
  ]);
  return {
    outputDirectory,
    files: [`app/${appName}`, `app/${styleName}`, "index.html"].sort(),
  };
}

const isMain = process.argv[1]
  && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain) {
  const result = await buildVerifierSite();
  process.stdout.write(`Built ${result.files.length} deterministic verifier files in ${result.outputDirectory}\n`);
}
