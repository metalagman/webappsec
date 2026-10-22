const accountIdPattern = /^[A-Za-z0-9_-]{1,128}$/;

export async function detectVerifierDeployMode({
  accountId,
  apiToken,
  fetchImplementation = globalThis.fetch,
} = {}) {
  if (!accountIdPattern.test(accountId ?? "")
    || typeof apiToken !== "string" || apiToken.length < 1 || apiToken.length > 4096
    || typeof fetchImplementation !== "function") {
    throw new Error("invalid Cloudflare credentials or runtime");
  }

  let response;
  try {
    response = await fetchImplementation(
      `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/webappsec-verifier`,
      {
        method: "GET",
        headers: { Authorization: `Bearer ${apiToken}` },
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
      },
    );
  } catch (error) {
    throw new Error(`Cloudflare Worker lookup unavailable: ${error.message}`);
  }
  if (response.status === 404) return "bootstrap";
  if (response.ok) return "deploy";
  throw new Error(`Cloudflare Worker lookup returned HTTP ${response.status}`);
}
