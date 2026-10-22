import assert from "node:assert/strict";
import test from "node:test";

import { detectVerifierDeployMode } from "../lib/verifier-deploy-mode.mjs";

test("verifier deploy mode distinguishes absent and existing Worker without exposing credentials", async () => {
  const calls = [];
  const request = (status) => detectVerifierDeployMode({
    accountId: "account-id",
    apiToken: "super-secret-token",
    fetchImplementation: async (url, init) => {
      calls.push({ url, init });
      return new Response(null, { status });
    },
  });
  assert.equal(await request(404), "bootstrap");
  assert.equal(await request(200), "deploy");
  assert.equal(calls[0].url, "https://api.cloudflare.com/client/v4/accounts/account-id/workers/scripts/webappsec-verifier");
  assert.equal(calls[0].init.headers.Authorization, "Bearer super-secret-token");
});

test("verifier deploy mode fails closed on invalid input and Cloudflare errors", async () => {
  await assert.rejects(() => detectVerifierDeployMode({
    accountId: "bad/account",
    apiToken: "token",
    fetchImplementation: async () => new Response(null, { status: 404 }),
  }), /credentials/);
  await assert.rejects(() => detectVerifierDeployMode({
    accountId: "account-id",
    apiToken: "token",
    fetchImplementation: async () => new Response(null, { status: 503 }),
  }), /HTTP 503/);
});
