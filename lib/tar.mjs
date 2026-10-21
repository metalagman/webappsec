import { createReadStream } from "node:fs";
import { lstat, mkdir, open, readdir, writeFile } from "node:fs/promises";
import path from "node:path";

const blockSize = 512;
const maxEntries = 20_256;
const maxFileSize = 25 * 1024 * 1024;

function writeText(header, offset, length, value) {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length > length) throw new Error(`tar field too long: ${value}`);
  bytes.copy(header, offset);
}

function writeOctal(header, offset, length, value) {
  const encoded = value.toString(8).padStart(length - 1, "0");
  if (encoded.length >= length) throw new Error(`tar numeric field overflow: ${value}`);
  writeText(header, offset, length, `${encoded}\0`);
}

function splitName(name) {
  if (Buffer.byteLength(name) <= 100) return { name, prefix: "" };
  const slashOffsets = [...name.matchAll(/\//g)].map((match) => match.index).reverse();
  const split = slashOffsets.find((offset) =>
    offset > 0
    && Buffer.byteLength(name.slice(0, offset)) <= 155
    && Buffer.byteLength(name.slice(offset + 1)) <= 100
  );
  if (split === undefined) throw new Error(`tar path exceeds ustar limits: ${name}`);
  return { prefix: name.slice(0, split), name: name.slice(split + 1) };
}

function headerFor(archivePath, size, directory) {
  const split = splitName(archivePath);
  const header = Buffer.alloc(blockSize);
  writeText(header, 0, 100, split.name);
  writeOctal(header, 100, 8, directory ? 0o755 : 0o644);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, size);
  writeOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  writeText(header, 156, 1, directory ? "5" : "0");
  writeText(header, 257, 6, "ustar\0");
  writeText(header, 263, 2, "00");
  writeText(header, 345, 155, split.prefix);
  const checksum = [...header].reduce((sum, byte) => sum + byte, 0);
  writeText(header, 148, 8, `${checksum.toString(8).padStart(6, "0")}\0 `);
  return header;
}

async function entries(directory, prefix = "", state = { count: 0 }) {
  const output = [];
  const names = await readdir(path.join(directory, prefix), { withFileTypes: true });
  for (const entry of names.sort((a, b) => a.name.localeCompare(b.name, "en"))) {
    state.count += 1;
    if (state.count > maxEntries) throw new Error("tar entry limit exceeded");
    const name = path.posix.join(prefix, entry.name);
    const metadata = await lstat(path.join(directory, name));
    if (metadata.isSymbolicLink()) throw new Error(`symlink is not allowed in tar: ${name}`);
    if (metadata.isDirectory()) {
      output.push({ name: `${name}/`, directory: true, size: 0 });
      output.push(...await entries(directory, name, state));
    } else if (metadata.isFile()) {
      if (metadata.size > maxFileSize) throw new Error(`tar file exceeds size limit: ${name}`);
      output.push({ name, directory: false, size: metadata.size });
    } else {
      throw new Error(`unsupported tar entry: ${name}`);
    }
  }
  return output;
}

async function writeAll(file, buffer) {
  let offset = 0;
  while (offset < buffer.length) {
    const { bytesWritten } = await file.write(buffer, offset);
    if (bytesWritten === 0) throw new Error("short tar write");
    offset += bytesWritten;
  }
}

export async function writeNormalizedTar(directory, destination) {
  const file = await open(destination, "w", 0o644);
  try {
    for (const entry of await entries(directory)) {
      await writeAll(file, headerFor(entry.name, entry.size, entry.directory));
      if (!entry.directory) {
        for await (const chunk of createReadStream(path.join(directory, entry.name))) {
          await writeAll(file, chunk);
        }
        const remainder = entry.size % blockSize;
        if (remainder) await writeAll(file, Buffer.alloc(blockSize - remainder));
      }
    }
    await writeAll(file, Buffer.alloc(blockSize * 2));
  } finally {
    await file.close();
  }
}

function readText(header, offset, length) {
  const field = header.subarray(offset, offset + length);
  const end = field.indexOf(0);
  return field.subarray(0, end === -1 ? field.length : end).toString("utf8");
}

function readOctal(header, offset, length, label) {
  const text = readText(header, offset, length).trim();
  if (!/^[0-7]+$/.test(text)) throw new Error(`invalid tar ${label}`);
  return Number.parseInt(text, 8);
}

function safeArchivePath(value, directory) {
  const normalized = directory && value.endsWith("/") ? value.slice(0, -1) : value;
  return normalized.length > 0
    && normalized.length <= 255
    && normalized === normalized.normalize("NFC")
    && /^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(normalized)
    && !normalized.split("/").some((part) => !part || part === "." || part === ".." || part.startsWith("."))
    && path.posix.normalize(normalized) === normalized;
}

async function readExact(file, length, position) {
  const buffer = Buffer.alloc(length);
  let offset = 0;
  while (offset < length) {
    const { bytesRead } = await file.read(buffer, offset, length - offset, position + offset);
    if (bytesRead === 0) throw new Error("truncated tar archive");
    offset += bytesRead;
  }
  return buffer;
}

function verifyHeaderChecksum(header) {
  const expected = readOctal(header, 148, 8, "checksum");
  const copy = Buffer.from(header);
  copy.fill(0x20, 148, 156);
  const actual = [...copy].reduce((sum, byte) => sum + byte, 0);
  if (actual !== expected) throw new Error("tar header checksum mismatch");
}

export async function extractNormalizedTar(archive, destination) {
  const file = await open(archive, "r");
  let position = 0;
  let count = 0;
  let zeroBlocks = 0;
  try {
    await mkdir(destination, { recursive: true });
    const archiveSize = (await file.stat()).size;
    while (position < archiveSize) {
      const header = await readExact(file, blockSize, position);
      position += blockSize;
      if (header.every((byte) => byte === 0)) {
        zeroBlocks += 1;
        if (zeroBlocks === 2) break;
        continue;
      }
      if (zeroBlocks !== 0) throw new Error("invalid tar end marker");
      count += 1;
      if (count > maxEntries) throw new Error("tar entry limit exceeded");
      verifyHeaderChecksum(header);
      if (readText(header, 257, 6) !== "ustar" || readText(header, 263, 2) !== "00") throw new Error("unsupported tar format");
      const type = readText(header, 156, 1) || "0";
      if (type !== "0" && type !== "5") throw new Error(`unsafe tar entry type: ${type}`);
      const directory = type === "5";
      const name = readText(header, 0, 100);
      const prefix = readText(header, 345, 155);
      const archivePath = prefix ? `${prefix}/${name}` : name;
      if (!safeArchivePath(archivePath, directory)) throw new Error(`unsafe tar path: ${archivePath}`);
      const cleanPath = directory && archivePath.endsWith("/") ? archivePath.slice(0, -1) : archivePath;
      if (!["assets", "inputs", "manifest.json"].includes(cleanPath.split("/")[0])) throw new Error(`unexpected tar entry: ${cleanPath}`);
      const size = readOctal(header, 124, 12, "size");
      if (size > maxFileSize) throw new Error(`tar file exceeds size limit: ${cleanPath}`);
      const expectedMode = directory ? 0o755 : 0o644;
      if (readOctal(header, 100, 8, "mode") !== expectedMode
          || readOctal(header, 108, 8, "uid") !== 0
          || readOctal(header, 116, 8, "gid") !== 0
          || readOctal(header, 136, 12, "mtime") !== 0) {
        throw new Error(`noncanonical tar metadata: ${cleanPath}`);
      }
      if ((directory && size !== 0) || (!directory && archivePath.endsWith("/"))) throw new Error(`invalid tar entry shape: ${cleanPath}`);
      const destinationPath = path.join(destination, cleanPath);
      if (directory) {
        await mkdir(destinationPath, { recursive: true, mode: 0o755 });
      } else {
        const bytes = await readExact(file, size, position);
        await mkdir(path.dirname(destinationPath), { recursive: true, mode: 0o755 });
        await writeFile(destinationPath, bytes, { mode: 0o644, flag: "wx" });
      }
      position += Math.ceil(size / blockSize) * blockSize;
    }
    if (zeroBlocks !== 2) throw new Error("tar archive is missing end markers");
    if (position !== archiveSize) throw new Error("tar archive has trailing data");
  } finally {
    await file.close();
  }
}
