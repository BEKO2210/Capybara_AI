# Supply Chain Security

Practices for keeping Capybara_AI's dependencies and build trustworthy, aligned
with NIST SSDF (PW/PS/RV practices). Automated in
[`.github/workflows/security.yml`](./.github/workflows/security.yml).

## Lockfile hygiene

- `package-lock.json` is committed and authoritative. `.npmrc` sets
  `save-exact=true`, so direct dependencies are pinned to exact versions.
- CI installs with `npm ci` (exact, reproducible) — never `npm install` in CI.
- Builds and audits run with `--ignore-scripts` to avoid executing arbitrary
  dependency lifecycle scripts; `@node-rs/argon2` uses prebuilt binaries so no
  native build step is needed.
- `engine-strict=true` pins the Node major (`>=22 <23`).

## Automated scanning & cadence

| Check | Tool | When |
|---|---|---|
| Known vulns (deps) | `npm audit --audit-level=high` | every push to `main`, every PR, weekly |
| Vulnerability DB | OSV-Scanner (`google/osv-scanner-action`) on the lockfile | every push to `main`, every PR, weekly |
| Secret leakage | gitleaks (`gitleaks/gitleaks-action`) | every push to `main`, every PR, weekly |
| SBOM | CycloneDX (`@cyclonedx/cyclonedx-npm`) → uploaded artifact | every push to `main`, every PR, weekly |

The weekly schedule (`cron: 0 6 * * 1`) catches advisories disclosed after a
commit landed. High-or-above audit findings and OSV/gitleaks hits fail the job.

## Dependency `overrides`

`package.json` `overrides` force-resolve transitive packages to patched
versions, removing the vulnerable ones from the tree entirely (so both `npm
audit` and OSV stay clean without suppressions):

- `esbuild >=0.25.0` — drizzle-kit's deprecated `@esbuild-kit` chain pulled a
  vulnerable esbuild (dev-server advisory; dev-only).
- `uuid >=11.1.1` — `exceljs` depended on an old `uuid` (GHSA-w5hq-g745-h8pq).

**Spreadsheet parsing note:** we use `exceljs` (not the npm `xlsx`/SheetJS
package). The npm `xlsx` build is genuinely vulnerable, and SheetJS publishes
fixes only via its own CDN — an unusual supply-chain shape that also trips OSV
regardless of version. `exceljs` is maintained on npm and, with the `uuid`
override, leaves zero advisories.

## SBOM

A CycloneDX JSON SBOM (`sbom.cdx.json`) is generated in CI and uploaded as a
build artifact, providing a component inventory for downstream review and
vulnerability correlation. Generate locally with:

```bash
npx --yes @cyclonedx/cyclonedx-npm --output-format JSON --output-file sbom.cdx.json
```

## Build provenance & images

- The runtime container is multi-stage; the final image contains only
  production `node_modules`, compiled `dist/`, and `package.json` — no build
  tools, source, tests, or secrets (`docker/Dockerfile`, `.dockerignore`).
- Images run as a non-root user (uid 10001).
- Recommended hardening (operator): pin base images by digest, enable
  registry image signing/verification (cosign), and pin GitHub Actions to commit
  SHAs. Action pinning to SHAs is a tracked follow-up (currently major-version
  tags for readability).

## Adding or updating dependencies

1. Prefer well-maintained, widely-used packages; review transitive additions.
2. Update the lockfile via `npm install <pkg>` (exact pin) and commit it.
3. Ensure CI security jobs pass (audit/OSV/gitleaks) before merge.
4. Regenerate/review the SBOM when the dependency graph changes materially.

## Incident linkage

A dependency vulnerability is handled per
[`INCIDENT_RESPONSE.md`](./INCIDENT_RESPONSE.md): assess exploitability in our
context, patch/upgrade, rebuild image, and rotate anything potentially exposed.
