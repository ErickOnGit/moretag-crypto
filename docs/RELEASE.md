# Release Checklist

## Pre-flight
- Ensure CI is green (`npm run verify`).
- Review `SECURITY.md` reporting contact is correct.
- Review `vectors/` tests pass (interop stability).

## Versioning
- Bump `package.json` version (semver).
- Update `package-lock.json` (run `npm i` if needed).

## Validate Package Contents
- `npm pack --dry-run` to verify included files (`dist`, `LICENSE`, `NOTICE`, `README.md`).
- `npm run prepack` (build + tests).

## Publish
- `npm publish` (with appropriate access and provenance settings for your org).

## Post-release
- Tag release in git.
- Monitor Dependabot and `npm audit` workflow output.
