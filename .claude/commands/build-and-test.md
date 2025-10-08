---
description: Build Rspamd and run all unit tests
---

Complete build and test workflow for Rspamd:

1. Build project:
   - `cd ~/rspamd.build`
   - `ninja -j8 install`
2. If build succeeds, run unit tests:
   - C/C++ tests: `test/rspamd-test-cxx`
   - Lua tests: `test/rspamd-test -p /rspamd/lua`
3. Report comprehensive results:
   - Build status
   - Test results
   - Any failures or errors

This is the standard pre-commit verification workflow.
