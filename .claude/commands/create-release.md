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
4. Update version in CMakeLists.txt
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
7. Create follow-up commit updating version for next dev cycle
8. Remind to push commits and tags

Walk through each step interactively.
