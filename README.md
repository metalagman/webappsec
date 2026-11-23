# Proof of Deploy

> [Русская версия](README.ru.md)

[`webappsec.metalagman.dev`](https://webappsec.metalagman.dev) is an open demonstration of a verifiable web supply chain: source code → CI build → signed artifact → deployment → live production bytes.

The site explains the role of SBOMs, CVE correlation, SLSA provenance, reproducible builds, Sigstore/Cosign, a signed deployment manifest, an external verifier, browser SRI, and `importmap.integrity`. The source code, Cloudflare Worker configurations, and GitHub Actions workflows are all published in this repository.

## Local verification

Node.js 22 is required. Exact npm dependency versions are pinned in `package-lock.json`.

```sh
npm ci
npm run check
npm run deploy:validate
npm run deploy:verifier:validate
```

`npm run deploy:validate` builds the site and runs a local `wrangler deploy --dry-run`; no network access or Cloudflare credentials are required.

## Online verification of the live deployment

[`verify.webappsec.metalagman.dev`](https://verify.webappsec.metalagman.dev) automatically verifies the release currently serving the main site. A trusted GitHub Actions workflow verifies Cosign signatures, attestations, SBOM/CVE evidence, and the reproducible build ahead of time. On every visit to the verifier, your browser independently fetches the live production files, checks their SHA-256 digests against the signed manifest, verifies entry script and stylesheet SRI plus complete `importmap.integrity` for all JavaScript modules, and confirms that the Worker version did not change during verification.

The verifier snapshot is created only after [Verify production](https://github.com/metalagman/webappsec/actions/workflows/verify-production.yml) succeeds. A privileged workflow re-verifies the immutable release, deployment, and verification evidence, builds the separate `webappsec-verifier` Worker, validates its Version URL before promotion, and runs hosted Chromium after publication. Production grants credentialless CORS only to the exact verifier origin for `GET`/`HEAD` requests and exposes only the deployment identity headers. Secrets remain in the GitHub Environment `production`; static verifier files never contain them.

## Cloudflare deployment contract

`wrangler.jsonc` declares a single Worker `webappsec`, Static Assets from `dist`, a mandatory Worker-first wrapper, public Version URLs, and the Custom Domain `webappsec.metalagman.dev`. Custom Domains provision the required DNS and TLS records through Cloudflare Workers automatically, so no separate Terraform setup is needed.

The Worker serves the exact response body returned by the Static Assets binding without modification. It adds security headers, splits cache policy between content-hashed assets and HTML, rejects unknown `Host` headers, and redirects HTTP requests for allowed hosts to HTTPS. On Version URLs, Cloudflare responses include `X-Robots-Tag: noindex`. The `X-Webappsec-Release` and `X-Webappsec-Worker-Version` headers come from Cloudflare Version Metadata; the release workflow passes the manifest digest as the version tag. Before promotion, Cloudflare reports the tag as `unknown` on Version URLs, so the preview gate binds exact bytes to the version ID, while the post-promotion production gate requires the manifest digest.

The production job uses the GitHub Environment `production` and two Environment secrets:

- `CLOUDFLARE_API_TOKEN` — a custom token scoped to the target Cloudflare account and the `metalagman.dev` zone: **Account / Workers Scripts / Write** and **Zone / Workers Routes / Write**;
- `CLOUDFLARE_ACCOUNT_ID` — the Cloudflare account identifier.

Deployment does not require DNS Write permissions, a Global API Key, or access to other zones. Secrets live only in the GitHub Environment and are never committed to the repository, release artifacts, or logs.

Deployments must use a signed content-addressed release, re-verify it before upload, and invoke the pinned Wrangler version with a tag equal to the manifest digest. The Worker source, shared content-addressing policy module, and `wrangler.jsonc` are included in the manifest as deploy inputs, so altering any of them changes the release identity.

The initial bootstrap runs manually from a SemVer tag and creates the Worker, Version URL, and Custom Domain:

```sh
gh workflow run deploy.yml --ref <tag> -f release=<tag> -f bootstrap=true
```

Subsequent deployments upload a new version without shifting traffic, verify its Version URL for exact bytes, SRI, security headers, `noindex`, and headless Chromium rendering, and only then route 100% of traffic to that exact `version_id`:

```sh
gh workflow run deploy.yml --ref <tag> -f release=<tag> -f bootstrap=false
```

Every successful transition publishes a separate immutable GitHub Release `deployment-<action>-<tag>-<run-id>`. It contains the canonical deployment record, production verifier report, their SHA-256 index, and three keyless Cosign bundles. The record pins the source release, manifest digest, GitHub run, Wrangler `4.151.3`, Cloudflare Worker version, and deployment ID.

Rollback never selects a "previous" version automatically. The operator passes the target tag, manifest digest, Worker version UUID, and signed Deployment Release. The workflow re-verifies both signature chains and the Cloudflare version tag before switching traffic; `restore` uses the same explicit fields:

```sh
gh workflow run rollback.yml --ref <workflow-tag> \
  -f action=rollback -f release=<target-tag> \
  -f manifest_digest=<sha256> -f version_id=<uuid> \
  -f deployment_release=<immutable-deployment-release>
```

Official references: [Static Assets](https://developers.cloudflare.com/workers/static-assets/), [Custom Domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/), [Version URLs](https://developers.cloudflare.com/workers/versions-and-deployments/version-urls/), [Version Metadata](https://developers.cloudflare.com/workers/runtime-apis/bindings/version-metadata/), [API token permissions](https://developers.cloudflare.com/fundamentals/api/reference/permissions/).

## SBOM and vulnerability evidence

`npm run tools:evidence` installs Syft `1.55.0` and Grype `0.121.0` for Linux amd64. The script verifies the SHA-256 checksums of official release archives before extraction. Versions and checksums are pinned in `tools/install-evidence-tools.sh`, making tool updates explicit in Git history.

After creating a content-addressed release, generate its evidence with:

```sh
npm run evidence:generate -- --release .artifacts/releases/<manifest-sha256> --output .artifacts/evidence
```

The output contains a runtime SBOM in SPDX 2.3 and CycloneDX 1.7, a separate build SBOM in CycloneDX 1.7, and separate Grype reports for runtime and build. Runtime documents inventory the entire release filesystem: public assets, Worker runtime source, deployment configuration, and the manifest itself; categories remain distinct and every SHA-256 is checked against the manifest. The build SBOM is generated from the full `package-lock.json`, capturing direct and transitive dependencies and their relationships. All documents are bound to the same manifest digest. Official SPDX and CycloneDX JSON Schemas are vendored in the repository, and the generator validates documents before scanning.

Every vulnerability report records the pinned Grype version, scan timestamp, vulnerability database metadata, matched and ignored findings, and an explicit status. `no-known-vulnerabilities` means the scan completed with zero matches; `unavailable` or `not-scanned` includes the reason and fails generation. Matched CVEs are published without an arbitrary severity gate: this demo presents verifiable scan results rather than imposing a product risk-acceptance policy.

## Independent production verification

Run the verifier from a trusted checkout rather than from the website itself:

```sh
git checkout v0.4.0
npm ci
npm run tools:signing
npm run verify:release -- --release v0.4.0 --rebuild
```

The command accepts only an explicit SemVer tag, downloads the matching GitHub Release, and verifies Cosign bundles against the exact GitHub OIDC issuer, repository, workflow path, and tag ref. It then verifies the signed evidence index, SLSA and CycloneDX in-toto subjects, SPDX/CycloneDX contents, and completed vulnerability reports, rebuilds the manifest and tar from a clean tag checkout, and only then inspects live production.

The production layer fetches each URL with `Accept-Encoding: identity`, enforces redirect, byte-size, and timeout limits, rejects cross-origin redirects, and compares exact size and SHA-256. The HTML parser matches browser-loaded script and stylesheet references against the manifest and expected SHA-384 SRI without executing fetched code. It also requires a canonical import map before module scripts, exact SHA-384 digests for every JavaScript file in the manifest, and a CSP hash pinning the import map itself. The full response CSP is stored as the signed `security-policy.txt`; the Worker applies it to responses, and the verifier compares the header byte for byte. Human and JSON outputs report `pass`, `fail`, `unavailable`, or `skipped` for each layer. The lower-level `npm run verify -- --manifest ./manifest.json` command is available for local HTTP fixtures, but does not authenticate the manifest on its own.

Exit code `0` means every required check ran and passed; `1` indicates a signature, evidence policy, or production byte failure; `2` indicates invalid CLI usage; `3` means a required GitHub, Sigstore, or production service is unavailable. An unavailable check never becomes a pass.

The scheduled [Verify production](https://github.com/metalagman/webappsec/actions/workflows/verify-production.yml) workflow uses only the explicitly configured repository variable `PRODUCTION_RELEASE_TAG`. A read-only job with `contents: read` takes the verifier and its dependencies from an exact revision of trusted `main`; the tag checkout lives in a separate directory and is read strictly as source data for the reproducible build. Release assets are downloaded in a separate trusted step, while the verifier itself runs without a GitHub token and retains the exact JSON report as an Actions artifact for 90 days. Manual dispatch requires an explicit tag input.

Only after verification succeeds does a separate publisher job receive `contents: write` and a short-lived `id-token: write`; Cloudflare credentials are unavailable to it. It re-validates all nine layers, retains the exact JSON and deterministic human report, binds them with a SHA-256 index and verification record, signs every file with keyless Cosign, and publishes the immutable Release `verification-<tag>-<run-id>`. This job never deploys or modifies production.

## Signed release pipeline

`.github/workflows/verify.yml` runs on pull requests and `main` with `contents: read` only: it installs the exact Node.js version, restores the locked npm graph, runs unit and browser checks, and performs a Wrangler dry run. It receives no OIDC token, release write permission, or Cloudflare secrets.

Publication is triggered only by an immutable SemVer tag via `.github/workflows/release.yml`. The single release job receives `contents: write` and a short-lived `id-token: write`. It builds the manifest and normalized tar twice, verifies byte-for-byte equality, generates SBOM/CVE evidence, the SLSA v1 predicate, and canonical `evidence-index.json`, and signs the manifest, tar, and index with keyless Cosign. Separate in-toto bundles bind the SLSA predicate to both the manifest and the tar, and bind runtime/build CycloneDX SBOMs to the tar. Signer policy pins issuer `https://token.actions.githubusercontent.com` and identity `https://github.com/metalagman/webappsec/.github/workflows/release.yml@refs/tags/<tag>`.

Cosign `3.1.3`, Syft `1.55.0`, and Grype `0.121.0` are downloaded only from pinned URLs and accepted after SHA-256 verification. GitHub Actions are pinned by full commit SHA. The release script refuses to overwrite an existing GitHub Release, uploads the complete asset set into a draft first, and publishes only afterward. **Release immutability** should be enabled in the public repository settings so GitHub enforces immutability server-side once published.

Release contents can be checked locally prior to the cryptographic layer:

```sh
npm run evidence:verify -- .artifacts/publish
```

`evidence-index.json` lists the SHA-256 digest and size of the canonical manifest, content-addressed `<manifest-sha256>.tar`, SPDX/CycloneDX SBOMs, both vulnerability reports, and the SLSA predicate. Cosign bundles are published alongside them as authentication envelopes and are excluded from the signed index to avoid self-reference.
