# Webappsec static-site build type

This URI identifies the build described by `.github/workflows/release.yml`.
Its external parameters are the public repository URL, exact Git commit, immutable
SemVer tag, workflow path, and production origin. The builder installs the exact
Node version from `.nvmrc`, installs the locked npm graph, creates the canonical
manifest and normalized tar twice, and requires byte-for-byte equality before it
generates the evidence set.

The resolved dependencies contain the Git commit and SHA-256 of
`package-lock.json`. The SLSA v1 `byproducts` bind `manifest.json` and
the content-addressed `<manifest-sha256>.tar`; Cosign creates the in-toto statement subject from the exact tar
bytes when it signs `provenance.slsa.json` as a predicate.
