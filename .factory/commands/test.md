---
description: Run Rspamd unit tests (C/C++ and Lua)
---

Run Rspamd unit tests:

1. First, ensure the project is built (`ninja -j8 install` in ~/rspamd.build)
2. Run C/C++ unit tests: `test/rspamd-test-cxx`
3. Run Lua unit tests: `test/rspamd-test -p /rspamd/lua`
4. Report results from both test suites
5. If tests fail, provide details on failures

**Note**: Functional tests are run manually only, not part of this command.
