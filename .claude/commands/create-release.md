---
description: Guide through creating a new Rspamd release
---

Guide through the Rspamd release process:

1. Ask for the new version number (X.Y.Z)
2. Show recent commits since last release to help write ChangeLog
3. Help update ChangeLog with proper format:
   ```
   X.Y.Z: DD MMM YYYY
     * [Feature] Feature description
     * [Fix] Fix description
   ```
4. Update version in CMakeLists.txt, and set `RSPAMD_RELEASE_BASE` to X.Y.Z
   in the release commit (it records the last release tag the tree descends from)
5. Create release commit with full changelog:
   ```
   git commit --no-verify -S -m "Release X.Y.Z

   * [Feature] ...
   * [Fix] ..."
   ```
6. Create signed release tag:
   ```
   git tag -s X.Y.Z -m "Rspamd X.Y.Z

   Main features:
   * ...

   Critical fixes:
   * ..."
   ```
7. Verify the tag before pushing it:
   - `git describe --tags --long` at the tag gives distance 0
     (`X.Y.Z-0-g<hash>`)
   - `git show X.Y.Z:CMakeLists.txt | grep RSPAMD_RELEASE_BASE` prints X.Y.Z.
     A stale base makes every build from the release tarball report
     `X.Y.Z-dev` and `dev: true`; 4.3.1 shipped like that
   - cmake prints `Build identity: release base X.Y.Z, dev=FALSE`
8. Create follow-up commit updating version for next dev cycle: change only
   `RSPAMD_VERSION_PATCH`, leave `RSPAMD_RELEASE_BASE` alone (it stays X.Y.Z)
9. Remind to push commits and tags

Walk through each step interactively.
