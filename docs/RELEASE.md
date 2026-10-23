# Release checklist

moretag-crypto is not published to npm. The moreTag app consumes it as a git
submodule pinned to a release tag.

## Before the tag

- `npm run verify` is green on Node 24 (typecheck, typecheck of the tests,
  `vectors:check`, tests, build). CI runs the same on the pull request.
- `npm pack --dry-run` lists only `dist`, `LICENSE`, `NOTICE`, `README.md` and
  `package.json`.
- `package.json` carries the new version (semver: a protocol change is a major
  version). The lockfile's own version matches.
- `docs/SPEC.md` describes every byte that changed, and `SECURITY.md` lists the
  supported versions.

## Release

1. Merge the release pull request into `main`.
2. Tag the merge commit `vX.Y.Z` and push the tag.

## After the tag

1. In moreTag, move the `packages/moretag-crypto` submodule pointer to the tag in
   the pull request that adopts it (never by editing the submodule's checkout).
2. A protocol change ships in one coordinated moreTag release with a reset
   (`docs/VERSION_MIGRATION.md`).
3. Watch Dependabot alerts and the weekly `npm audit` workflow.
