export const contentHashHexLength = 12;

const immutableAssetPattern = new RegExp(
  `\\.[a-f0-9]{${contentHashHexLength}}\\.(?:css|js)$`,
);

export function contentHashName(prefix, digest, extension) {
  return `${prefix}.${digest.slice(0, contentHashHexLength)}.${extension}`;
}

export function isImmutableAssetPath(pathname) {
  return immutableAssetPattern.test(pathname);
}
