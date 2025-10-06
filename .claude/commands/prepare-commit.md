---
description: Prepare for commit - build, test, format, check, suggest commit message
---

Complete pre-commit workflow for Rspamd project:

1. Check git status to see what files are staged/modified
2. **Code formatting and checks**:
   - C/C++ files: Run clang-format
   - Lua files: Run luacheck and report issues
   - Stage formatted files if needed
3. **Build project**:
   - `cd ~/rspamd.build && ninja -j8 install`
   - Report build status
4. **Run unit tests** (if build succeeds):
   - C/C++ tests: `test/rspamd-test-cxx`
   - Lua tests: `test/rspamd-test -p /rspamd/lua`
   - Report test results
5. **Suggest commit message** following Rspamd format:
   - Use appropriate tag: [Feature], [Fix], [Minor], [Test], [Conf], etc.
   - Write clear, concise description
   - Remind to use `git commit -S` for GPG signing
6. Ask if the user wants to proceed with the commit

Do NOT automatically commit - just prepare, verify, and suggest.