#!/usr/bin/env node
import { detectVerifierDeployMode } from "../lib/verifier-deploy-mode.mjs";

const mode = await detectVerifierDeployMode({
  accountId: process.env.CLOUDFLARE_ACCOUNT_ID,
  apiToken: process.env.CLOUDFLARE_API_TOKEN,
});
process.stdout.write(`${mode}\n`);
